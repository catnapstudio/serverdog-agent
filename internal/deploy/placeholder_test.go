package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// withPlaceholder gives the fixture's site its placeholder page, and a ReleaseConfig that writes a marker config.
// It returns where that config goes.
func (f *fixture) withPlaceholder() string {
	f.t.Helper()

	dir := filepath.Join(f.dir(), "placeholder")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("placeholder"), 0o644); err != nil {
		f.t.Fatal(err)
	}

	config := filepath.Join(f.root, "etc/nginx/sites-available/serverdog-abcdefghijkl.conf")
	f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) {
		return []apply.File{{Path: config, Content: []byte("# serves releases\n")}}, nil
	}

	return config
}

func (f *fixture) placeholderExists() bool {
	_, err := os.Lstat(filepath.Join(f.dir(), "placeholder"))

	return err == nil
}

func TestTheFirstLiveDeployLeavesThePlaceholder(t *testing.T) {
	f := newFixture(t, nil)
	config := f.withPlaceholder()

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.live() != d.Release {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if f.read(config) != "# serves releases\n" {
		t.Error("Nginx still serves the placeholder")
	}
	if f.placeholderExists() {
		t.Error("the placeholder page is still there")
	}
	if commands := f.system.Commands(); !slices.Equal(commands, []string{"nginx -t", "/usr/local/bin/serverdog-agent reload-nginx"}) {
		t.Errorf("commands = %v", commands)
	}

	f.system.Reset()
	f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) {
		t.Error("a later deploy asked for the release config again")
		return nil, nil
	}
	if second := f.run(state.KindDeploy, ""); second.State != state.Succeeded {
		t.Fatalf("second = %+v\n%s", second, f.out)
	}
	if commands := f.system.Commands(); len(commands) != 0 {
		t.Errorf("a later static deploy ran %v", commands)
	}
}

func TestAFailedFirstDeployKeepsThePlaceholder(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.DeployScript = "$CREATE_RELEASE()\nexit 3\n$ACTIVATE_RELEASE()\n"
	})
	config := f.withPlaceholder()

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive {
		t.Fatalf("deployment = %+v", d)
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Error("a failed deploy wrote the release config")
	}
	if !f.placeholderExists() {
		t.Error("a failed deploy removed the placeholder")
	}
}

func TestAFirstDeployThatFailsAfterGoingLiveStillDropsThePlaceholder(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.DeployScript = "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\nexit 4\n"
	})
	config := f.withPlaceholder()

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || !d.WentLive {
		t.Fatalf("deployment = %+v", d)
	}
	if f.read(config) != "# serves releases\n" || f.placeholderExists() {
		t.Error("a release that went live is hidden behind the placeholder")
	}
}

func TestNginxRejectingTheSwitchKeepsThePlaceholder(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()
	f.system.Fail("nginx", 1, "nginx: [emerg] unexpected end of file")

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || !strings.Contains(d.Error, "Nginx couldn't switch from the placeholder page to the release") {
		t.Fatalf("deployment = %+v", d)
	}
	if !f.placeholderExists() {
		t.Error("the placeholder was removed although Nginx still serves it")
	}
	// current already points at the release, so it is kept for the next deploy rather than deleted.
	if f.live() != d.Release || !slices.Contains(f.releases(), d.Release) {
		t.Errorf("current -> %q, releases %v", f.live(), f.releases())
	}
}

const customisedNote = "The Nginx config is customised, so ServerDog left it unchanged. If it still serves the placeholder folder, point it at the release or reset it to the generated config.\n"

func TestACustomisedConfigIsLeftAloneButThePlaceholderGoes(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()
	f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) { return nil, nil }

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive {
		t.Fatalf("deployment = %+v", d)
	}
	if commands := f.system.Commands(); len(commands) != 0 {
		t.Errorf("ran %v for a customised config", commands)
	}
	if f.placeholderExists() {
		t.Error("the placeholder page is still there")
	}
}

// A config customised while the site showed its placeholder may still point at the folder the deploy removes.
func TestEveryKindOfSiteSaysWhyACustomisedConfigWasLeftAlone(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T) *fixture{
		"zero downtime": func(t *testing.T) *fixture { return newFixture(t, nil) },
		"in place": func(t *testing.T) *fixture {
			return newFixture(t, func(s *site.Site) { s.ZeroDowntime, s.DeployScript = false, "echo built\n" })
		},
		"node": nodeFixture,
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			f.withPlaceholder()
			f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) { return nil, nil }

			d := f.run(state.KindDeploy, "")
			if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() {
				t.Fatalf("deployment = %+v, placeholder kept = %v\n%s", d, f.placeholderExists(), f.out)
			}
			if log := f.out.String(); strings.Count(log, customisedNote) != 1 {
				t.Errorf("log doesn't explain the customised config once:\n%s", log)
			}

			f.out.Reset()
			if second := f.run(state.KindDeploy, ""); second.State != state.Succeeded || strings.Contains(f.out.String(), customisedNote) {
				t.Errorf("a later deploy = %+v, log:\n%s", second, f.out)
			}
		})
	}
}

func TestAGeneratedReleaseConfigSaysNothingAboutCustomisation(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()

	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded || strings.Contains(f.out.String(), "customised") {
		t.Errorf("deployment = %+v, log:\n%s", d, f.out)
	}
}

func TestAReleaseConfigThatCantBeRenderedFailsTheSwitch(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()
	f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) {
		return nil, errors.New("read the site's certificates: database is locked")
	}

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || !f.placeholderExists() {
		t.Fatalf("deployment = %+v", d)
	}
	if d.Error != "Couldn't render the Nginx config that serves the release: read the site's certificates: database is locked" {
		t.Errorf("error = %q", d.Error)
	}
}

func TestAnInPlaceSiteLeavesThePlaceholderOnlyAfterItsScript(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.ZeroDowntime = false
		s.DeployScript = "exit 5\n"
	})
	config := f.withPlaceholder()

	failed := f.run(state.KindDeploy, "")
	if failed.State != state.Failed || failed.WentLive || !f.placeholderExists() {
		t.Fatalf("failed first deploy = %+v, placeholder kept = %v", failed, f.placeholderExists())
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Error("the failed deploy switched Nginx")
	}

	f.updateSite(func(s *site.Site) { s.DeployScript = "echo built\n" })
	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() || f.read(config) != "# serves releases\n" {
		t.Fatalf("second = %+v\n%s", d, f.out)
	}
}

func TestANodeSiteLeavesThePlaceholderWithItsFirstSwitch(t *testing.T) {
	f := nodeFixture(t)
	config := f.withPlaceholder()

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if f.read(config) != "# serves releases\n" || f.placeholderExists() {
		t.Error("the Node site still shows the placeholder")
	}

	checks := slices.DeleteFunc(f.system.Commands(), func(c string) bool { return c != "nginx -t" })
	if len(checks) != 1 {
		t.Errorf("Nginx was checked %d times; the upstream and the config change together", len(checks))
	}
}

func TestAPlaceholderSiteNeedsTheReleaseConfig(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()
	f.runner.ReleaseConfig = nil

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || !f.placeholderExists() {
		t.Errorf("deployment = %+v", d)
	}
}

// applyLockHeld reports whether the apply lock is taken, as a config the agent writes meanwhile would find it.
func (f *fixture) applyLockHeld() bool {
	done, cancel := context.WithCancel(ctx)
	cancel()

	release, err := lock.Acquire(done, f.runner.Applier.LockPath)
	if err != nil {
		return true
	}
	release()

	return false
}

// placeholderRemovals runs commands like Exec and records, for each step that takes the placeholder page away, whether
// the apply lock was held: moving the folder aside, and deleting the folder it was moved to. failMove and failDelete
// make that step fail instead.
type placeholderRemovals struct {
	system.Runner
	f                    *fixture
	moved, deleted       []bool
	failMove, failDelete bool
}

func (r *placeholderRemovals) Run(ctx context.Context, cmd system.Command) (system.Result, error) {
	last := cmd.Args[len(cmd.Args)-1]

	if cmd.Name == "perl" && slices.ContainsFunc(cmd.Args, func(arg string) bool { return strings.HasSuffix(arg, "/placeholder") }) {
		r.moved = append(r.moved, r.f.applyLockHeld())
		if r.failMove {
			return system.Result{}, errors.New("rename: Permission denied")
		}
	}
	if cmd.Name == "rm" && strings.Contains(filepath.Base(last), "placeholder") {
		r.deleted = append(r.deleted, r.f.applyLockHeld())
		if r.failDelete {
			return system.Result{}, errors.New("rm: Permission denied")
		}
	}

	return r.Runner.Run(ctx, cmd)
}

// retiredPlaceholders lists the folders the page was moved to and that are still there.
func (f *fixture) retiredPlaceholders() []string {
	found, err := filepath.Glob(filepath.Join(f.dir(), ".placeholder-removed-*"))
	if err != nil {
		f.t.Fatal(err)
	}

	return found
}

// The agent renders a site's config, applies it and saves what it rendered from under the apply lock. The switch
// renders the release config, applies it and removes the placeholder page under the same lock, so a certificate the
// agent activates meanwhile is either in what the switch renders, or rendered by the agent after the page is gone.
func TestTheSwitchFromThePlaceholderHoldsTheApplyLock(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T) *fixture{
		"zero downtime": func(t *testing.T) *fixture { return newFixture(t, nil) },
		"in place": func(t *testing.T) *fixture {
			return newFixture(t, func(s *site.Site) { s.ZeroDowntime, s.DeployScript = false, "echo built\n" })
		},
		"node": nodeFixture,
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			config := f.withPlaceholder()

			var rendered []bool
			f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) {
				rendered = append(rendered, f.applyLockHeld())

				return []apply.File{{Path: config, Content: []byte("# serves releases\n")}}, nil
			}
			removals := &placeholderRemovals{Runner: f.runner.Exec, f: f}
			f.runner.Exec = removals
			var detected []bool
			f.runner.Capabilities = func(context.Context) capabilities.Capabilities {
				detected = append(detected, f.applyLockHeld())

				return capabilities.Capabilities{NginxVersion: "1.28.0"}
			}
			release := f.runner.ReleaseConfig
			f.runner.ReleaseConfig = func(ctx context.Context, siteID string, caps capabilities.Capabilities) ([]apply.File, error) {
				if caps.NginxVersion != "1.28.0" {
					t.Errorf("release config rendered for %+v, not the detected capabilities", caps)
				}

				return release(ctx, siteID, caps)
			}

			d := f.run(state.KindDeploy, "")
			if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() || f.read(config) != "# serves releases\n" {
				t.Fatalf("deployment = %+v, placeholder kept = %v\n%s", d, f.placeholderExists(), f.out)
			}
			if !slices.Equal(rendered, []bool{true}) {
				t.Errorf("release config rendered with the apply lock held: %v", rendered)
			}
			if !slices.Equal(detected, []bool{false}) {
				t.Errorf("capabilities detected with the apply lock held: %v", detected)
			}
			if !slices.Equal(removals.moved, []bool{true}) {
				t.Errorf("placeholder moved aside with the apply lock held: %v", removals.moved)
			}
			if !slices.Equal(removals.deleted, []bool{false}) {
				t.Errorf("moved placeholder deleted with the apply lock held: %v", removals.deleted)
			}
			if left := f.retiredPlaceholders(); len(left) != 0 {
				t.Errorf("the moved placeholder is still there: %v", left)
			}
			if f.applyLockHeld() {
				t.Error("the deploy kept the apply lock")
			}
		})
	}
}

// A placeholder folder the site user filled with many files is moved aside under the apply lock in one rename, and
// deleted after it, so other sites' changes never wait for its rm.
func TestABigPlaceholderIsDeletedOnceTheApplyLockIsFree(t *testing.T) {
	f := newFixture(t, nil)
	f.withPlaceholder()
	for i := range 200 {
		if err := os.WriteFile(filepath.Join(f.dir(), "placeholder", fmt.Sprintf("file-%d", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	removals := &placeholderRemovals{Runner: f.runner.Exec, f: f}
	f.runner.Exec = removals

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() {
		t.Fatalf("deployment = %+v, placeholder kept = %v\n%s", d, f.placeholderExists(), f.out)
	}
	if !slices.Equal(removals.moved, []bool{true}) || !slices.Equal(removals.deleted, []bool{false}) {
		t.Errorf("moved under the lock %v, deleted under the lock %v", removals.moved, removals.deleted)
	}
	if left := f.retiredPlaceholders(); len(left) != 0 {
		t.Errorf("the moved placeholder is still there: %v", left)
	}
}

func TestEveryKindOfSiteFailsWhenThePlaceholderCantBeMovedAside(t *testing.T) {
	for name, fixture := range map[string]func(*testing.T) *fixture{
		"zero downtime": func(t *testing.T) *fixture { return newFixture(t, nil) },
		"in place": func(t *testing.T) *fixture {
			return newFixture(t, func(s *site.Site) { s.ZeroDowntime, s.DeployScript = false, "echo built\n" })
		},
		"node": nodeFixture,
	} {
		t.Run(name, func(t *testing.T) {
			f := fixture(t)
			f.withPlaceholder()
			removals := &placeholderRemovals{Runner: f.runner.Exec, f: f, failMove: true}
			f.runner.Exec = removals

			d := f.run(state.KindDeploy, "")
			if d.State != state.Failed || !d.WentLive {
				t.Fatalf("deployment = %+v\n%s", d, f.out)
			}
			if !strings.HasPrefix(d.Error, "The release is live, but the placeholder page couldn't be removed") {
				t.Errorf("error = %q", d.Error)
			}
			if !f.placeholderExists() || len(removals.deleted) != 0 {
				t.Errorf("placeholder kept = %v, deletes = %v", f.placeholderExists(), removals.deleted)
			}
			if f.applyLockHeld() {
				t.Error("the deploy kept the apply lock")
			}
		})
	}
}

// The page is gone once it is moved aside, so a moved folder that couldn't be deleted is only logged, and later deploys
// don't trip over it.
func TestAMovedPlaceholderThatCantBeDeletedIsLeftBehind(t *testing.T) {
	f := newFixture(t, nil)
	config := f.withPlaceholder()
	removals := &placeholderRemovals{Runner: f.runner.Exec, f: f, failDelete: true}
	f.runner.Exec = removals

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() || f.read(config) != "# serves releases\n" {
		t.Fatalf("deployment = %+v, placeholder kept = %v\n%s", d, f.placeholderExists(), f.out)
	}
	if !strings.Contains(f.out.String(), "Couldn't delete the old placeholder folder") {
		t.Errorf("log doesn't mention the folder left behind:\n%s", f.out)
	}
	if left := f.retiredPlaceholders(); len(left) != 1 {
		t.Fatalf("moved placeholders = %v", left)
	}

	f.runner.ReleaseConfig = func(context.Context, string, capabilities.Capabilities) ([]apply.File, error) {
		t.Error("a later deploy asked for the release config again")
		return nil, nil
	}
	if second := f.run(state.KindDeploy, ""); second.State != state.Succeeded {
		t.Fatalf("second = %+v\n%s", second, f.out)
	}
}

// placeholderDeletion runs commands like Exec and calls seen when it deletes the folder the placeholder page was moved
// to.
type placeholderDeletion struct {
	system.Runner
	seen func()
}

func (r *placeholderDeletion) Run(ctx context.Context, cmd system.Command) (system.Result, error) {
	if cmd.Name == "rm" && strings.HasPrefix(filepath.Base(cmd.Args[len(cmd.Args)-1]), ".placeholder-removed-") {
		r.seen()
	}

	return r.Runner.Run(ctx, cmd)
}

// The site user decides how big the placeholder folder is. A Node site's first switch must finish (live port, current,
// the instance Put's upstream named stopped) before the folder is deleted, so a slow or killed delete can't leave the
// site half switched.
func TestANodeSiteDeletesThePlaceholderOnlyOnceTheSwitchIsDone(t *testing.T) {
	f := nodeFixtureServing(t, 0, string(nodeservice.RenderUpstream("abcdefghijkl", 20000)))
	f.withPlaceholder()

	deletions := 0
	f.runner.Exec = &placeholderDeletion{Runner: f.runner.Exec, seen: func() {
		deletions++

		if live, _ := f.store.LivePort("abcdefghijkl"); live != 20001 {
			t.Errorf("live port when the placeholder was deleted = %d, want 20001", live)
		}
		if f.live() == "" {
			t.Error("current didn't point at the release when the placeholder was deleted")
		}
		if !slices.Contains(f.system.Commands(), "systemctl stop serverdog-site-abcdefghijkl@20000.service") {
			t.Errorf("the placeholder was deleted before the old instance stopped: %v", f.system.Commands())
		}
	}}

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() {
		t.Fatalf("deployment = %+v, placeholder kept = %v\n%s", d, f.placeholderExists(), f.out)
	}
	if deletions != 1 {
		t.Errorf("the moved placeholder was deleted %d times, want once", deletions)
	}
	if left := f.retiredPlaceholders(); len(left) != 0 {
		t.Errorf("the moved placeholder is still there: %v", left)
	}
}

func TestASiteWithoutARepositoryRunsItsScriptOnCurrentAndLeavesThePlaceholder(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.ZeroDowntime = false
		s.RepositoryURL, s.Branch = "", ""
		s.DeployScript = "cd $SERVERDOG_SITE_PATH\n\n[ -f index.php ] || echo '<?php echo 1;' > index.php\n"
	})
	config := f.withPlaceholder()

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || f.placeholderExists() || f.read(config) != "# serves releases\n" {
		t.Fatalf("deploy = %+v\n%s", d, f.out)
	}
	if len(d.Phases) != 1 || d.Phases[0].Name != state.PhaseBuild {
		t.Errorf("phases = %+v, want only the build", d.Phases)
	}
	if f.read(filepath.Join(f.dir(), "current", "index.php")) != "<?php echo 1;\n" {
		t.Errorf("the script didn't write into current/")
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "current", ".git")); !os.IsNotExist(err) {
		t.Errorf("a site without a repository got a git checkout")
	}
}
