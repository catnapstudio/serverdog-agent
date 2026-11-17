package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/listenowner"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// activate makes release live.
func (j *job) activate(ctx context.Context, release string) error {
	if info, err := os.Lstat(filepath.Join(j.releasesDir(), release)); err != nil || !info.IsDir() {
		return fmt.Errorf("Release %s doesn't exist.", release)
	}

	if j.s.RunsOwnServer() {
		return j.activateNode(ctx, release)
	}

	// A cancel or timeout after the rename but before the process exits must not look like a failed switch:
	// current would point at the release while finish deletes it. Leaving the placeholder page is part of the switch.
	background := context.WithoutCancel(ctx)
	if err := j.switchCurrent(background, release); err != nil {
		return err
	}

	return j.leavePlaceholder(background, func(applier apply.Applier) error {
		if err := j.serveReleases(background, applier); err != nil {
			return err
		}
		j.wentLive()

		return j.removePlaceholder(background)
	})
}

// switchCurrentScript runs as the site user. Arguments: site directory, link target. It stages the symlink next to
// current and renames it over current in one step.
const switchCurrentScript = `my ($dir, $target) = @ARGV; my $tmp = "$dir/.current.serverdog-new"; unlink $tmp; symlink($target, $tmp) or die "symlink: $!\n"; rename($tmp, "$dir/current") or die "rename: $!\n";`

// switchCurrent points current at release in one rename. Root never creates or renames anything inside the site
// user's directory: the symlink is made and renamed as the site user.
func (j *job) switchCurrent(ctx context.Context, release string) error {
	if info, err := os.Lstat(j.dir); err != nil || !info.IsDir() {
		return fmt.Errorf("The site directory %s is missing.", j.dir)
	}

	if err := j.run(ctx, j.dir, "perl", "-e", switchCurrentScript, "--", j.dir, filepath.Join("releases", release)); err != nil {
		j.run(ctx, j.dir, "rm", "-f", "--", filepath.Join(j.dir, ".current.serverdog-new"))

		return fmt.Errorf("switch current: %w", err)
	}

	j.logf("current now points at releases/%s.\n", release)

	return nil
}

// remove deletes path as the site user, so a symlink the user planted can't make root delete anything else.
func (j *job) remove(ctx context.Context, path string) error {
	return j.run(ctx, j.dir, "rm", "-rf", "--", path)
}

func (j *job) wentLive() {
	j.release = ""
	j.update(func(d *state.Deployment) { d.WentLive = true })
}

// activateNode starts release's own server (a Node site's, or a PHP site's Octane) on the idle port, waits until it
// answers, moves Nginx to it, and stops the old instance.
func (j *job) activateNode(ctx context.Context, release string) error {
	ports, err := j.r.Store.NodePorts(j.s.ID)
	if err != nil {
		return err
	}
	live, err := j.livePort(ports)
	if err != nil {
		return err
	}

	idle := ports[0]
	if live == ports[0] {
		idle = ports[1]
	}

	if err := j.checkPortGuard(ctx); err != nil {
		return err
	}

	instance := nodeservice.Instance(j.s.ID, idle)
	portEnv := j.r.Paths.File(nodeservice.PortEnv(j.s.ID, idle))
	releaseDir := filepath.Join(j.releasesDir(), release)

	// Said here rather than as a server that never answers. The start script checks again as the site's user.
	if j.s.Octane {
		if _, err := os.Stat(filepath.Join(releaseDir, j.s.AppDirectory, "vendor", "laravel", "octane")); err != nil {
			return errors.New("This release has no laravel/octane, so Octane can't serve it. Add it with composer require laravel/octane, or turn Octane off in the site's settings.")
		}
	}
	background := context.WithoutCancel(ctx)

	// retreat undoes the idle instance before Nginx moved to it. Without its port file nothing names the release,
	// so finish can delete it (see releaseInUse).
	retreat := func() {
		j.systemctl(background, "disable", instance)
		j.systemctl(background, "stop", instance)
		if _, err := j.r.Applier.Apply(background, apply.Plan{Files: []apply.File{{Path: portEnv, Remove: true}}}); err != nil {
			j.logf("Couldn't remove %s: %v\n", portEnv, err)
		}
	}

	if _, err := j.r.Applier.Apply(ctx, apply.Plan{Files: []apply.File{{Path: portEnv, Content: nodeservice.RenderPortEnv(idle, releaseDir)}}}); err != nil {
		return err
	}

	j.logf("Starting the release on port %d.\n", idle)
	if err := j.systemctl(ctx, "restart", instance); err != nil {
		retreat()
		return fmt.Errorf("The release didn't start: %w", err)
	}

	if err := j.waitForNode(ctx, idle); err != nil {
		retreat()
		return err
	}

	// The probe accepts any HTTP answer, so it only means something if the answer came from this release.
	if err := j.checkListener(ctx, idle, instance); err != nil {
		retreat()
		return err
	}

	// Enabled before Nginx moves to it: a reboot right after the switch must start the instance Nginx points at.
	if err := j.systemctl(ctx, "enable", instance); err != nil {
		retreat()
		return fmt.Errorf("The release couldn't be enabled: %w", err)
	}

	// A site's first release also takes it off its placeholder page, in the same validated change. The folder the page
	// is moved to is deleted last, once the switch is complete.
	var removed error
	err = j.holdToLeavePlaceholder(ctx, func(applier apply.Applier) error {
		firstConfig, err := j.releaseConfig(ctx)
		if err != nil {
			return err
		}
		// An Octane site was on PHP-FPM until its first Octane deploy: this is the change that moves it over.
		if j.s.Octane && len(firstConfig) == 0 {
			if firstConfig, err = j.octaneConfig(ctx); err != nil {
				return err
			}
		}

		if _, err := applier.Apply(ctx, apply.Plan{
			Files:   append([]apply.File{{Path: j.r.Paths.File(paths.NginxUpstream(j.s.ID)), Content: nodeservice.RenderUpstream(j.s.ID, idle)}}, firstConfig...),
			Checks:  []system.Command{nginx.Check},
			Reloads: []system.Command{nginx.Reload},
		}); err != nil {
			return err
		}

		// Nginx now sends traffic to the new release, so it is live even if a later step fails.
		j.wentLive()
		removed = j.removePlaceholder(background)

		return nil
	})
	if err != nil {
		retreat()
		return err
	}

	// Nothing below may be skipped because the deploy was cancelled right after the reload.
	var failures []error

	if removed != nil {
		failures = append(failures, removed)
	}
	if err := j.r.Store.SetLivePort(j.s.ID, idle); err != nil {
		failures = append(failures, fmt.Errorf("The release is live, but recording its port failed: %w", err))
	}
	// The site's record says Octane serves it, so a later save renders Nginx the same way.
	if j.s.Octane {
		if _, err := j.r.Store.UpdateSite(j.s.ID, func(s *site.Site) { s.OctanePort = idle }, time.Now()); err != nil {
			failures = append(failures, fmt.Errorf("The release is live, but recording that Octane serves it failed: %w", err))
		}
	}
	if err := j.switchCurrent(background, release); err != nil {
		failures = append(failures, fmt.Errorf("The release is live, but %w", err))
	}

	if live != 0 {
		old := nodeservice.Instance(j.s.ID, live)
		j.systemctl(background, "disable", old)

		if j.r.DrainFor > 0 {
			j.logf("Stopping the previous release in %s, once its requests finish.\n", j.r.DrainFor)
			select {
			case <-ctx.Done():
			case <-time.After(j.r.DrainFor):
			}
		}
		j.systemctl(background, "stop", old)
	}

	j.deleteRetiredPlaceholder(background)

	return errors.Join(failures...)
}

// octaneConfig is the Nginx config that sends the site's requests to its Octane server.
func (j *job) octaneConfig(ctx context.Context) ([]apply.File, error) {
	if j.r.ReleaseConfig == nil {
		return nil, errors.New("This deploy can't move the site to Octane.")
	}

	files, err := j.r.ReleaseConfig(ctx, j.s.ID, j.caps)
	if err != nil {
		return nil, fmt.Errorf("Couldn't render the Nginx config that sends requests to Octane: %w", err)
	}

	return files, nil
}

// errNoPortGuard fails a Node deploy before its release starts: without the guard, another user could take the idle
// port first.
var errNoPortGuard = errors.New("The port guard isn't active, so the release wasn't started.")

func (j *job) checkPortGuard(ctx context.Context) error {
	if j.r.PortGuard == nil {
		j.logf("Port guard: not configured.\n")
		return errNoPortGuard
	}

	if err := j.r.PortGuard(ctx); err != nil {
		j.logf("Port guard: %v\n", err)
		return errNoPortGuard
	}

	return nil
}

// livePort is the port Nginx serves: the one the upstream file names. The store can lag behind it after a crash
// between the reload and SetLivePort, so it is only used when the file is missing or doesn't name one of ports,
// and corrected when the two disagree.
func (j *job) livePort(ports [2]int) (int, error) {
	stored, err := j.r.Store.LivePort(j.s.ID)
	if err != nil {
		return 0, err
	}

	content, err := os.ReadFile(j.r.Paths.File(paths.NginxUpstream(j.s.ID)))
	if err != nil {
		return stored, nil
	}

	served, ok := nodeservice.UpstreamPort(content)
	if !ok || (served != ports[0] && served != ports[1]) || served == stored {
		return stored, nil
	}

	j.logf("Nginx serves port %d, not the recorded %d; recording %d.\n", served, stored, served)
	if err := j.r.Store.SetLivePort(j.s.ID, served); err != nil {
		return 0, fmt.Errorf("record live port: %w", err)
	}

	return served, nil
}

func (j *job) waitForNode(ctx context.Context, port int) error {
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	deadline := time.Now().Add(j.r.ProbeFor)

	for {
		if err := j.r.Probe(ctx, url); err == nil {
			j.logf("The release answers on port %d.\n", port)
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("The new release didn't answer on port %d within %s, so the site keeps serving the previous one.", port, j.r.ProbeFor)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(j.r.ProbeEvery):
		}
	}
}

func (j *job) systemctl(ctx context.Context, args ...string) error {
	result, err := j.r.System.Run(ctx, system.Command{Name: "systemctl", Args: args})
	if err != nil {
		j.logf("systemctl %v: %s\n", args, system.Tail(result.Output, 3))
	}

	return err
}

// probeClient doesn't follow redirects: an app that redirects / to https://its-domain/ is answering.
var probeClient = &http.Client{
	Timeout: 2 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// HTTPProbe answers nil when anything serves HTTP at url, whatever the status.
func HTTPProbe(ctx context.Context, url string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	response, err := probeClient.Do(request)
	if err != nil {
		return err
	}

	return response.Body.Close()
}

// prune deletes releases beyond the newest ReleasesToKeep, never the live one.
func (j *job) prune(ctx context.Context) error {
	entries, err := os.ReadDir(j.releasesDir())
	if err != nil {
		return err
	}

	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	live := j.liveRelease()
	for i, name := range names {
		if i < j.s.ReleasesToKeep || name == live {
			continue
		}

		if err := j.remove(ctx, filepath.Join(j.releasesDir(), name)); err != nil {
			j.logf("Couldn't remove release %s: %v\n", name, err)
			continue
		}
		j.logf("Removed release %s.\n", name)
	}

	return nil
}

// releaseInUse says why release must not be deleted, or "" when nothing uses it: current points at it, or a Node
// instance's port file names it. Nginx may already serve a Node release whose deploy crashed before recording that it
// went live, so leaking a release that never went live is preferred over deleting a live one. Root only reads here:
// current with Readlink, and the port files are root's own.
func releaseInUse(p paths.Paths, siteDir, siteID, release string) string {
	if target, err := os.Readlink(filepath.Join(siteDir, "current")); err == nil && filepath.Base(target) == release {
		return "current points at it"
	}

	want := filepath.Join(siteDir, "releases", release)
	portFiles, _ := filepath.Glob(filepath.Join(p.File(paths.SiteEtcDir(siteID)), "*.env"))

	for _, file := range portFiles {
		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Sprintf("%s couldn't be read", file)
		}

		for line := range strings.SplitSeq(string(content), "\n") {
			if value, ok := strings.CutPrefix(line, "SERVERDOG_RELEASE_DIRECTORY="); ok && filepath.Clean(value) == want {
				return fmt.Sprintf("the Node instance in %s is set to run it", filepath.Base(file))
			}
		}
	}

	return ""
}

func (j *job) liveRelease() string {
	target, err := os.Readlink(filepath.Join(j.dir, "current"))
	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

func (j *job) checkListener(ctx context.Context, port int, instance string) error {
	if j.r.Listener == nil {
		j.logf("Listener check: not configured.\n")
		return &listenowner.ForeignError{Port: port}
	}

	err := j.r.Listener.OwnedBy(ctx, port, instance)
	var foreign *listenowner.ForeignError
	if errors.As(err, &foreign) {
		j.logf("%s\n", foreign.Detail())

		return err
	}
	if err != nil {
		j.logf("Listener check: %v\n", err)

		return fmt.Errorf("Port %d couldn't be checked, so the release wasn't started.\n\n%w", port, err)
	}

	return nil
}
