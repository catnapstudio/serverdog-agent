// Package deploy runs a site's deploys: fetch, check out a release, link shared paths, run the script,
// activate, and clean up. Each deploy runs as "serverdog-agent run-deploy <id>" in its own systemd unit.
package deploy

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// DefaultPath is the PATH deploy commands start from. PHP sites get their version's helpers in front.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Runner performs deployments.
type Runner struct {
	Store *state.Store
	Paths paths.Paths
	// Exec runs git and the deploy script as the site user; System runs systemctl and nginx as root.
	Exec    system.Runner
	System  system.Runner
	Applier apply.Applier
	// Notify posts the outcome to the site's webhook or the server's (notify.Manager.Deploy). Nil sends nothing.
	Notify func(ctx context.Context, s site.Site, d state.Deployment) error
	// HealthCheck answers nil when the site serves rawURL with a status under 400 (SiteHealthCheck). The site's health
	// check path is tried every ProbeEvery for HealthCheckFor after the deploy. Nil skips it.
	HealthCheck    func(ctx context.Context, rawURL string) error
	HealthCheckFor time.Duration
	// OPcacheFrozen reports whether OPcache stopped checking files (phpsettings.Manager.OPcacheFrozen); PHP-FPM then
	// reloads once a PHP release is live, or it would keep running the old code. Nil never reloads.
	OPcacheFrozen func() bool
	// Out is the deploy log (stdout of the deploy's unit).
	Out        io.Writer
	Now        func() time.Time
	LookupUser func(name string) (system.User, error)
	// AsUser runs Exec commands with the site user's ids. Tests leave it false and run as themselves.
	AsUser   bool
	BasePath string
	// Probe answers nil when something serves HTTP at url (Node health check).
	Probe      func(ctx context.Context, url string) error
	ProbeEvery time.Duration
	ProbeFor   time.Duration
	// DrainFor is how long the previous Node instance keeps running after the switch.
	DrainFor time.Duration
	// PortGuard brings the Node port guard in step with the store and fails when it isn't attached
	// (portguard.Syncer.Sync). A Node release doesn't start without it, and nil counts as a missing guard.
	PortGuard func(ctx context.Context) error
	// Listener checks that only the new instance listens on its port before Nginx moves to it
	// (listenowner.Checker). Nil counts as a foreign listener.
	Listener Listener
	// ReleaseConfig renders the Nginx files that serve a site's releases instead of its placeholder page (the sites
	// manager in production), for a server with caps. It returns none for a customised config, which is left alone.
	ReleaseConfig func(ctx context.Context, siteID string, caps capabilities.Capabilities) ([]apply.File, error)
	// Capabilities detects what the server runs, for ReleaseConfig. It waits on version commands, so it runs before
	// the apply lock. Nil detects nothing (tests).
	Capabilities func(context.Context) capabilities.Capabilities
	// Timeout overrides the site's deploy timeout when non-zero (tests).
	Timeout time.Duration
}

// Listener checks who listens on a Node instance's port.
type Listener interface {
	// OwnedBy returns nil when something listens on port and every listener runs in unit's control group.
	OwnedBy(ctx context.Context, port int, unit string) error
}

// job is one deployment in progress.
type job struct {
	r    *Runner
	d    state.Deployment
	s    site.Site
	user system.User
	dir  string

	// release is the directory this deploy created while it isn't live; it is deleted if the deploy fails.
	release     string
	releaseName string
	redeploy    bool

	// placeholder is true while the site serves its placeholder page; the deploy that makes a release live ends it.
	placeholder bool
	// retired is true once this deploy moved the placeholder page aside and until it deleted the folder it moved it to.
	retired bool
	// caps is what the server runs, detected before the switch from the placeholder page takes the apply lock.
	caps capabilities.Capabilities
}

func (r *Runner) load(d state.Deployment) (*job, error) {
	s, err := r.Store.GetSite(d.SiteID)
	if err != nil {
		return nil, fmt.Errorf("The site no longer exists.")
	}

	user, err := r.LookupUser(s.User)
	if err != nil {
		return nil, fmt.Errorf("The site's user %s doesn't exist.", s.User)
	}

	// A deploy runs the script its phases were planned from; an edit made since waits for the next deploy.
	if d.Kind == state.KindDeploy && d.Script != "" {
		s.DeployScript = d.Script
	}

	return &job{r: r, d: d, s: s, user: user, dir: r.Paths.File(s.Directory), placeholder: hasPlaceholder(r.Paths, s)}, nil
}

func (j *job) logf(format string, args ...any) {
	fmt.Fprintf(j.r.Out, format, args...)
}

func (j *job) asUser() *system.User {
	if !j.r.AsUser {
		return nil
	}

	user := j.user

	return &user
}

func (j *job) path() string {
	if j.s.Runtime == site.PHP {
		return j.r.Paths.File(paths.PHPHelperBin(j.s.PHPVersion)) + ":" + j.r.BasePath
	}

	return j.r.BasePath
}

func (j *job) credentials() gitsource.Credentials {
	return gitsource.Credentials{
		KeyPath:              j.r.Paths.File(paths.DeployKey(j.s.User, j.s.ID)),
		KnownHostsPath:       j.r.Paths.File(paths.SiteKnownHosts(j.s.User, j.s.ID)),
		GlobalKnownHostsPath: j.r.Paths.File(paths.KnownHosts),
		Home:                 j.user.Home,
		Path:                 j.path(),
		User:                 j.asUser(),
	}
}

func (j *job) baseEnv() []string {
	return append(gitsource.GitEnv(j.credentials()), "USER="+j.user.Name, "LOGNAME="+j.user.Name, "COMPOSER_NO_INTERACTION=1")
}

// run runs a command as the site user and streams its output into the log.
func (j *job) run(ctx context.Context, dir, name string, args ...string) error {
	_, err := j.r.Exec.Run(ctx, system.Command{Name: name, Args: args, Dir: dir, Env: j.baseEnv(), User: j.asUser(), Stdout: j.r.Out})

	return err
}

// output runs a command as the site user and returns its trimmed output.
func (j *job) output(ctx context.Context, dir, name string, args ...string) (string, error) {
	result, err := j.r.Exec.Run(ctx, system.Command{Name: name, Args: args, Dir: dir, Env: j.baseEnv(), User: j.asUser()})

	return strings.TrimSpace(string(result.Output)), err
}

// update changes the deployment row and keeps j.d in step. Progress is best effort: a failed write is logged, not fatal.
func (j *job) update(change func(*state.Deployment)) {
	updated, err := j.r.Store.UpdateDeployment(j.d.ID, change)
	if err != nil {
		j.logf("Couldn't record progress: %v\n", err)
		change(&j.d)
		return
	}

	j.d = updated
}

// phase marks name running, runs fn, and marks it done or failed.
func (j *job) phase(ctx context.Context, name string, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	j.update(func(d *state.Deployment) { setPhase(d, name, state.PhaseRunning, j.r.Now()) })
	j.logf("\n==> %s\n", titles[name])

	if err := fn(); err != nil {
		j.update(func(d *state.Deployment) { setPhase(d, name, state.PhaseFailed, j.r.Now()) })
		return err
	}

	j.update(func(d *state.Deployment) { setPhase(d, name, state.PhaseDone, j.r.Now()) })

	return nil
}

func (j *job) releasesDir() string { return filepath.Join(j.dir, "releases") }

func short(commit string) string {
	if len(commit) > 7 {
		return commit[:7]
	}

	return commit
}
