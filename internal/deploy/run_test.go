package deploy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/listenowner"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

func (f *fixture) run(kind, release string) state.Deployment {
	f.t.Helper()

	id := f.start(kind, release)
	if err := f.runner.Run(ctx, id); err != nil {
		f.t.Fatal(err)
	}

	d, _ := f.store.GetDeployment(id)
	return d
}

func (f *fixture) live() string {
	target, err := os.Readlink(filepath.Join(f.dir(), "current"))
	if err != nil {
		return ""
	}

	return filepath.Base(target)
}

func (f *fixture) releases() []string {
	entries, _ := os.ReadDir(filepath.Join(f.dir(), "releases"))

	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}

	return names
}

func phaseStates(d state.Deployment) map[string]string {
	states := map[string]string{}
	for _, phase := range d.Phases {
		states[phase.Name] = phase.State
	}

	return states
}

func TestDeploySucceedsAndSwitchesCurrent(t *testing.T) {
	f := newFixture(t, nil)

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || !d.WentLive || d.FinishedAt.IsZero() {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if f.live() != d.Release {
		t.Errorf("current -> %q, want %q", f.live(), d.Release)
	}
	if f.read(filepath.Join(f.dir(), "current/public/index.html")) != "v1" {
		t.Error("current doesn't serve the release")
	}
	for name, phaseState := range phaseStates(d) {
		if phaseState != state.PhaseDone {
			t.Errorf("phase %s = %s", name, phaseState)
		}
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 5)
	if len(activity) == 0 || activity[0].Kind != "deploy.succeeded" || activity[0].Actor != "Test Mac" {
		t.Errorf("activity = %+v", activity)
	}
}

func TestFailedBuildLeavesTheSiteUntouched(t *testing.T) {
	f := newFixture(t, nil)
	first := f.run(state.KindDeploy, "")

	f.updateSite(func(s *site.Site) {
		s.DeployScript = "$CREATE_RELEASE()\necho building\nexit 3\n$ACTIVATE_RELEASE()\n"
	})
	d := f.run(state.KindDeploy, "")

	if d.State != state.Failed || d.WentLive || d.Error != "The deploy script failed with exit code 3." {
		t.Fatalf("deployment = %+v", d)
	}
	if f.live() != first.Release {
		t.Errorf("current -> %q, want the first release %q", f.live(), first.Release)
	}
	if !slices.Equal(f.releases(), []string{first.Release}) {
		t.Errorf("releases = %v; the failed one should be gone", f.releases())
	}

	states := phaseStates(d)
	if states[state.PhaseBuild] != state.PhaseFailed || states[state.PhaseActivate] != state.PhaseSkipped || states[state.PhaseCleanUp] != state.PhaseSkipped {
		t.Errorf("phases = %v", states)
	}
}

func TestFailureAfterActivationIsLive(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.DeployScript = "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\nexit 4\n"
	})

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || !d.WentLive || f.live() != d.Release {
		t.Errorf("deployment = %+v, live = %s", d, f.live())
	}
}

func TestCancelDuringBuildKeepsOldRelease(t *testing.T) {
	f := newFixture(t, nil)
	first := f.run(state.KindDeploy, "")

	f.updateSite(func(s *site.Site) { s.DeployScript = "$CREATE_RELEASE()\nsleep 30\n$ACTIVATE_RELEASE()\n" })
	id := f.start(state.KindDeploy, "")

	cancelled, cancel := context.WithCancel(ctx)
	time.AfterFunc(500*time.Millisecond, cancel)

	start := time.Now()
	if err := f.runner.Run(cancelled, id); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("cancel didn't stop the script")
	}

	d, _ := f.store.GetDeployment(id)
	if d.State != state.Cancelled || d.WentLive {
		t.Errorf("deployment = %+v", d)
	}
	if f.live() != first.Release || !slices.Equal(f.releases(), []string{first.Release}) {
		t.Errorf("live = %s, releases = %v", f.live(), f.releases())
	}
}

func TestTimeoutDuringBuild(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.DeployScript = "$CREATE_RELEASE()\nsleep 30\n$ACTIVATE_RELEASE()\n" })
	f.runner.Timeout = 500 * time.Millisecond

	d := f.run(state.KindDeploy, "")
	if d.State != state.TimedOut || d.WentLive || !strings.Contains(d.Error, "didn't finish within") {
		t.Errorf("deployment = %+v", d)
	}
	if len(f.releases()) != 0 {
		t.Errorf("releases = %v", f.releases())
	}
}

func TestCleanUpKeepsTheNewestReleases(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.ReleasesToKeep = 2 })

	var last state.Deployment
	for range 4 {
		last = f.run(state.KindDeploy, "")
	}

	if got := f.releases(); len(got) != 2 || !slices.Contains(got, last.Release) {
		t.Errorf("releases = %v", got)
	}
}

func TestRollbackSwitchesWithoutRunningTheScript(t *testing.T) {
	f := newFixture(t, nil)
	first := f.run(state.KindDeploy, "")
	f.commit(map[string]string{"public/index.html": "v2"}, "Second")
	f.run(state.KindDeploy, "")
	f.out.Reset()

	d := f.run(state.KindRollback, first.Release)
	if d.State != state.Succeeded || !d.WentLive || f.live() != first.Release {
		t.Fatalf("rollback = %+v, live = %s", d, f.live())
	}
	if strings.Contains(f.out.String(), "built") {
		t.Error("rollback ran the deploy script")
	}
	if f.read(filepath.Join(f.dir(), "current/public/index.html")) != "v1" {
		t.Error("current doesn't serve the first release")
	}
}

func TestRollbackToTheLiveReleaseFails(t *testing.T) {
	f := newFixture(t, nil)
	first := f.run(state.KindDeploy, "")

	if d := f.run(state.KindRollback, first.Release); d.State != state.Failed || !strings.Contains(d.Error, "already live") {
		t.Errorf("rollback = %+v", d)
	}
}

func TestInPlaceDeployUpdatesTheCheckout(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.ZeroDowntime = false
		s.DeployScript = "echo in place at $SERVERDOG_DEPLOY_COMMIT\n"
	})

	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded || !d.WentLive {
		t.Fatalf("first = %+v\n%s", d, f.out)
	}

	second := f.commit(map[string]string{"public/index.html": "v2"}, "Second")
	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded || d.Commit != second {
		t.Fatalf("second = %+v", d)
	}

	current := filepath.Join(f.dir(), "current")
	if f.read(filepath.Join(current, "public/index.html")) != "v2" {
		t.Error("checkout not updated")
	}
	if _, err := os.Stat(filepath.Join(current, ".git")); err != nil {
		t.Error("in-place checkout lost .git")
	}
	if !strings.Contains(f.out.String(), "in place at "+second) {
		t.Errorf("output = %s", f.out)
	}
}

func nodeFixture(t *testing.T) *fixture {
	return newFixture(t, func(s *site.Site) {
		s.Runtime = site.Node
		s.WebDirectory = ""
		s.NodeStartCommand = "node server.js"
	})
}

func TestNodeDeploysSwitchBetweenTwoPorts(t *testing.T) {
	f := nodeFixture(t)

	f.run(state.KindDeploy, "")
	upstream := filepath.Join(f.root, "etc/nginx/serverdog/upstreams/abcdefghijkl.conf")
	if !strings.Contains(f.read(upstream), "127.0.0.1:20000;") {
		t.Errorf("upstream = %s", f.read(upstream))
	}
	if !strings.Contains(f.read(filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")), "SERVERDOG_RELEASE_DIRECTORY="+filepath.Join(f.dir(), "releases")) {
		t.Error("port env doesn't name the release")
	}

	f.system.Reset()
	second := f.run(state.KindDeploy, "")
	if second.State != state.Succeeded {
		t.Fatalf("second = %+v\n%s", second, f.out)
	}
	if !strings.Contains(f.read(upstream), "127.0.0.1:20001;") {
		t.Errorf("upstream after second deploy = %s", f.read(upstream))
	}
	if live, _ := f.store.LivePort("abcdefghijkl"); live != 20001 {
		t.Errorf("live port = %d", live)
	}

	want := []string{
		"systemctl restart serverdog-site-abcdefghijkl@20001.service",
		"systemctl enable serverdog-site-abcdefghijkl@20001.service",
		"nginx -t",
		"/usr/local/bin/serverdog-agent reload-nginx",
		"systemctl disable serverdog-site-abcdefghijkl@20000.service",
		"systemctl stop serverdog-site-abcdefghijkl@20000.service",
	}
	if got := f.system.Commands(); !slices.Equal(got, want) {
		t.Errorf("commands =\n%v\nwant\n%v", got, want)
	}
}

// nodeFixtureServing is a Node site whose store records stored as live while the upstream file holds upstream.
func nodeFixtureServing(t *testing.T, stored int, upstream string) *fixture {
	f := nodeFixture(t)
	if _, err := f.store.NodePorts("abcdefghijkl"); err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetLivePort("abcdefghijkl", stored); err != nil {
		t.Fatal(err)
	}

	file := filepath.Join(f.root, "etc/nginx/serverdog/upstreams/abcdefghijkl.conf")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(upstream), 0o644); err != nil {
		t.Fatal(err)
	}

	return f
}

// A crash between the upstream reload and recording the live port leaves the store behind Nginx. The deploy must
// start on the port Nginx doesn't serve, not restart the serving one.
func TestNodeDeployTrustsTheUpstreamFileOverTheStoredLivePort(t *testing.T) {
	f := nodeFixtureServing(t, 20000, string(nodeservice.RenderUpstream("abcdefghijkl", 20001)))

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}

	want := []string{
		"systemctl restart serverdog-site-abcdefghijkl@20000.service",
		"systemctl enable serverdog-site-abcdefghijkl@20000.service",
		"nginx -t",
		"/usr/local/bin/serverdog-agent reload-nginx",
		"systemctl disable serverdog-site-abcdefghijkl@20001.service",
		"systemctl stop serverdog-site-abcdefghijkl@20001.service",
	}
	if got := f.system.Commands(); !slices.Equal(got, want) {
		t.Errorf("commands =\n%v\nwant\n%v", got, want)
	}
	if live, _ := f.store.LivePort("abcdefghijkl"); live != 20000 {
		t.Errorf("live port = %d", live)
	}
}

func TestNodeDeployFallsBackToTheStoredLivePortWithoutAReadableUpstream(t *testing.T) {
	f := nodeFixtureServing(t, 20000, "# hand-edited\nupstream serverdog_abcdefghijkl {\n}\n")

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if got := f.system.Commands(); len(got) == 0 || got[0] != "systemctl restart serverdog-site-abcdefghijkl@20001.service" {
		t.Errorf("commands = %v, want the release started on 20001", got)
	}
}

func TestNodeReleaseThatNeverAnswersDoesNotGoLive(t *testing.T) {
	f := nodeFixture(t)
	f.runner.Probe = func(context.Context, string) error { return errors.New("connection refused") }
	f.runner.ProbeFor = 50 * time.Millisecond

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || !strings.Contains(d.Error, "didn't answer") {
		t.Fatalf("deployment = %+v", d)
	}
	if !slices.Contains(f.system.Commands(), "systemctl stop serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("idle instance not stopped: %v", f.system.Commands())
	}
	if live, _ := f.store.LivePort("abcdefghijkl"); live != 0 {
		t.Errorf("live port = %d", live)
	}
	if f.live() != "" {
		t.Error("current was switched")
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")); !os.IsNotExist(err) {
		t.Errorf("the idle instance's port file is left: %v", err)
	}
	if len(f.releases()) != 0 {
		t.Errorf("releases = %v; the release that never answered was kept", f.releases())
	}
}

// recordingRunner runs commands for real and remembers them.
type recordingRunner struct {
	mu       sync.Mutex
	commands [][]string
}

func (r *recordingRunner) Run(ctx context.Context, c system.Command) (system.Result, error) {
	r.mu.Lock()
	r.commands = append(r.commands, append([]string{c.Name}, c.Args...))
	r.mu.Unlock()

	return system.Exec{}.Run(ctx, c)
}

func (r *recordingRunner) ran(want ...string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.ContainsFunc(r.commands, func(command []string) bool { return slices.Equal(command, want) })
}

// The site user can swap releases for a symlink to anywhere before cleanup runs. Deleting must go through the
// site user's own rm, so root never follows that link. Everything here runs as the test user, so the victim is made
// read-only (the deletes fail) and the real proof is that every removal went through Exec as `rm -rf --`.
func TestPruneNeverDeletesAsRootThroughASwappedReleasesLink(t *testing.T) {
	victim := t.TempDir()
	for _, name := range []string{"0001", "0002", "0003", "0004"} {
		if err := os.MkdirAll(filepath.Join(victim, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(victim, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(victim, 0o755) })

	f := newFixture(t, func(s *site.Site) {
		s.ReleasesToKeep = 2
		s.DeployScript = "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n" +
			`rm -rf "$SERVERDOG_SITE_ROOT/releases.bak"; mv "$SERVERDOG_SITE_ROOT/releases" "$SERVERDOG_SITE_ROOT/releases.bak"; ln -s ` + victim + ` "$SERVERDOG_SITE_ROOT/releases"` + "\n"
	})
	recorder := &recordingRunner{}
	f.runner.Exec = recorder

	d := f.run(state.KindDeploy, "")
	if d.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}

	for _, name := range []string{"0001", "0002"} {
		if !recorder.ran("rm", "-rf", "--", filepath.Join(f.dir(), "releases", name)) {
			t.Errorf("release %s wasn't removed with the site user's rm: %v", name, recorder.commands)
		}
	}

	if os.Geteuid() == 0 {
		return
	}
	entries, _ := os.ReadDir(victim)
	if len(entries) != 4 {
		t.Errorf("victim entries = %d, want 4", len(entries))
	}
}

func TestNodeFailureAfterTheSwitchEndsFailedButLive(t *testing.T) {
	f := nodeFixture(t)

	blocker := filepath.Join(f.dir(), "current", "occupied")
	if err := os.MkdirAll(filepath.Dir(blocker), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || !d.WentLive || !strings.Contains(d.Error, "switch current") {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if live, _ := f.store.LivePort("abcdefghijkl"); live != 20000 {
		t.Errorf("live port = %d", live)
	}
	if !slices.Contains(f.system.Commands(), "systemctl enable serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("commands = %v", f.system.Commands())
	}
	if len(f.releases()) != 1 {
		t.Errorf("a live release was removed: %v", f.releases())
	}
	if _, err := os.Lstat(filepath.Join(f.dir(), ".current.serverdog-new")); err == nil {
		t.Error("the staged symlink was left behind")
	}
}

func TestHTTPProbeDoesNotFollowRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/unreachable", http.StatusFound)
	}))
	defer server.Close()

	if err := HTTPProbe(ctx, server.URL); err != nil {
		t.Errorf("a redirect means the app answers, got %v", err)
	}
}

// finishCancelled runs finish for a deploy cancelled after it created release, before it recorded going live.
func (f *fixture) finishCancelled(release string) *job {
	f.t.Helper()

	dir := filepath.Join(f.dir(), "releases", release)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		f.t.Fatal(err)
	}

	j := f.job(f.start(state.KindDeploy, release))
	j.release, j.releaseName = dir, release
	j.finish(state.Cancelled, "The deploy was cancelled.")

	return j
}

func TestFinishKeepsTheReleaseCurrentPointsAt(t *testing.T) {
	f := newFixture(t, nil)
	if err := os.Symlink("releases/20261016-180000", filepath.Join(f.dir(), "current")); err != nil {
		t.Fatal(err)
	}

	f.finishCancelled("20261016-180000")

	if !slices.Equal(f.releases(), []string{"20261016-180000"}) {
		t.Errorf("releases = %v; the release current points at was deleted", f.releases())
	}
	if !strings.Contains(f.out.String(), "Kept release 20261016-180000") {
		t.Errorf("output = %q", f.out)
	}
}

func TestFinishKeepsAReleaseANodePortFileNames(t *testing.T) {
	f := nodeFixture(t)
	release := filepath.Join(f.dir(), "releases", "20261016-180000")
	portEnv := filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20001.env")
	if err := os.MkdirAll(filepath.Dir(portEnv), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(portEnv, nodeservice.RenderPortEnv(20001, release), 0o644); err != nil {
		t.Fatal(err)
	}

	f.finishCancelled("20261016-180000")

	if !slices.Equal(f.releases(), []string{"20261016-180000"}) {
		t.Errorf("releases = %v; a release Nginx may serve was deleted", f.releases())
	}
}

func TestFinishRemovesAnUnusedRelease(t *testing.T) {
	f := nodeFixture(t)
	portEnv := filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")
	os.MkdirAll(filepath.Dir(portEnv), 0o755)
	os.WriteFile(portEnv, nodeservice.RenderPortEnv(20000, filepath.Join(f.dir(), "releases", "20261016-170000")), 0o644)

	f.finishCancelled("20261016-180000")

	if len(f.releases()) != 0 {
		t.Errorf("releases = %v", f.releases())
	}
}

func TestNodeSwitchRejectedByNginxDisablesTheNewInstance(t *testing.T) {
	f := nodeFixture(t)
	f.system.Fail("nginx", 1, "nginx: [emerg] rejected")

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive {
		t.Fatalf("deployment = %+v", d)
	}

	commands := f.system.Commands()
	for _, want := range []string{"systemctl disable serverdog-site-abcdefghijkl@20000.service", "systemctl stop serverdog-site-abcdefghijkl@20000.service"} {
		if !slices.Contains(commands, want) {
			t.Errorf("missing %q in %v", want, commands)
		}
	}
	if len(f.releases()) != 0 {
		t.Errorf("releases = %v", f.releases())
	}
}

func TestNodeReleaseThatDoesNotStartIsStopped(t *testing.T) {
	f := nodeFixture(t)
	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		if c.Args[0] == "restart" {
			return system.Result{ExitCode: 1}, &system.ExitError{Command: "systemctl", ExitCode: 1, Output: []byte("Job failed")}
		}
		return system.Result{}, nil
	})

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || !strings.Contains(d.Error, "didn't start") {
		t.Fatalf("deployment = %+v", d)
	}
	if !slices.Contains(f.system.Commands(), "systemctl stop serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("commands = %v; systemd keeps restarting an instance that isn't stopped", f.system.Commands())
	}
	if len(f.releases()) != 0 {
		t.Errorf("releases = %v", f.releases())
	}
}

func TestRunLeavesAFinishedDeploymentAlone(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	f.store.UpdateDeployment(id, func(d *state.Deployment) { d.State, d.Error = state.Cancelled, "The deploy was cancelled." })

	if err := f.runner.Run(ctx, id); err != nil {
		t.Fatal(err)
	}

	d, _ := f.store.GetDeployment(id)
	if d.State != state.Cancelled || d.Commit != "" || len(f.releases()) != 0 {
		t.Errorf("deployment = %+v, releases = %v", d, f.releases())
	}
	if _, err := os.Stat(filepath.Join(f.dir(), "repo")); err == nil {
		t.Error("the repository was fetched")
	}
	if !strings.Contains(f.out.String(), "isn't running") {
		t.Errorf("output = %q", f.out)
	}
}

func TestCancelAfterActivationKeepsTheNewRelease(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.DeployScript = "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\nsleep 30\n" })
	id := f.start(state.KindDeploy, "")

	cancelled, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for cancelled.Err() == nil {
			if d, _ := f.store.GetDeployment(id); d.WentLive {
				time.Sleep(200 * time.Millisecond)
				cancel()
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	start := time.Now()
	if err := f.runner.Run(cancelled, id); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 10*time.Second {
		t.Error("cancel didn't stop the script")
	}

	d, _ := f.store.GetDeployment(id)
	if d.State != state.Cancelled || !d.WentLive {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if f.live() != d.Release || !slices.Equal(f.releases(), []string{d.Release}) {
		t.Errorf("live = %s, releases = %v, want %s kept and live", f.live(), f.releases(), d.Release)
	}
	if states := phaseStates(d); states[state.PhaseActivate] != state.PhaseDone || states[state.PhaseAfterActivation] != state.PhaseFailed {
		t.Errorf("phases = %v", states)
	}
}

func TestPruneKeepsTheLiveReleaseEvenWhenItIsOld(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.ReleasesToKeep = 2 })
	for _, name := range []string{"20261016-170000", "20261016-170001", "20261016-170002", "20261016-170003"} {
		if err := os.MkdirAll(filepath.Join(f.dir(), "releases", name), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("releases/20261016-170000", filepath.Join(f.dir(), "current")); err != nil {
		t.Fatal(err)
	}

	if err := f.job(f.start(state.KindDeploy, "")).prune(ctx); err != nil {
		t.Fatal(err)
	}

	if want := []string{"20261016-170000", "20261016-170002", "20261016-170003"}; !slices.Equal(f.releases(), want) {
		t.Errorf("releases = %v, want %v", f.releases(), want)
	}
}

// Fifty failed deploys after the last good one push its row out of the history, but its release is still kept on the
// server, so it must stay on the rollback list.
func TestPruningTheHistoryKeepsReleasesThatCanBeRolledBackTo(t *testing.T) {
	f := newFixture(t, nil)
	good := f.run(state.KindDeploy, "")

	for range historyKept {
		failed := state.Deployment{
			ID: ids.New(), SiteID: "abcdefghijkl", Kind: state.KindDeploy, State: state.Failed, Actor: "Test Mac",
			Phases: PlannedPhases(site.Site{ZeroDowntime: true}, state.KindDeploy), Marker: "m", StartedAt: f.tick(), FinishedAt: f.tick(),
		}
		if err := f.store.CreateDeployment(failed); err != nil {
			t.Fatal(err)
		}
	}

	if latest := f.run(state.KindDeploy, ""); latest.State != state.Succeeded {
		t.Fatalf("latest = %+v\n%s", latest, f.out)
	}

	wentLive, err := f.store.ReleasesThatWentLive("abcdefghijkl")
	if err != nil || !wentLive[good.Release] {
		t.Errorf("ReleasesThatWentLive = %v %v, want %s kept", wentLive, err, good.Release)
	}
	if commit, _, _ := f.store.ReleaseCommit("abcdefghijkl", good.Release); commit != good.Commit {
		t.Errorf("ReleaseCommit(%s) = %q, want %q", good.Release, commit, good.Commit)
	}
	if list, _ := f.store.ListDeployments("abcdefghijkl", 100); len(list) != historyKept+1 {
		t.Errorf("history has %d deployments, want %d", len(list), historyKept+1)
	}
}

// The phases are planned when Deploy is called. A script edited before the deploy's unit starts must not run, or a
// segment the plan doesn't know about would be skipped without a word.
func TestAScriptEditedAfterDeployWaitsForTheNextDeploy(t *testing.T) {
	f := newFixture(t, nil)
	d, _, err := f.manager().Deploy(ctx, "abcdefghijkl", "Mac")
	if err != nil {
		t.Fatal(err)
	}

	f.updateSite(func(s *site.Site) {
		s.DeployScript = "echo edited before\n$CREATE_RELEASE()\n\ncd $SERVERDOG_RELEASE_DIRECTORY\necho edited build\n\n$ACTIVATE_RELEASE()\necho edited after\n"
	})

	if err := f.runner.Run(ctx, d.ID); err != nil {
		t.Fatal(err)
	}

	done, _ := f.store.GetDeployment(d.ID)
	if done.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", done, f.out)
	}
	if !strings.Contains(f.out.String(), "built") || strings.Contains(f.out.String(), "edited") {
		t.Errorf("the deploy didn't run the script it was started with:\n%s", f.out)
	}
	for name, phaseState := range phaseStates(done) {
		if phaseState != state.PhaseDone {
			t.Errorf("phase %s = %s", name, phaseState)
		}
	}
}

func TestNodeDeployFailsBeforeStartingWithoutThePortGuard(t *testing.T) {
	for name, guard := range map[string]func(context.Context) error{
		"detached": func(context.Context) error { return errors.New("the port guard isn't attached") },
		"missing":  nil,
	} {
		t.Run(name, func(t *testing.T) {
			f := nodeFixture(t)
			f.runner.PortGuard = guard

			d := f.run(state.KindDeploy, "")
			if d.State != state.Failed || d.WentLive || d.Error != "The port guard isn't active, so the release wasn't started." {
				t.Fatalf("deployment = %+v", d)
			}
			if len(f.system.Commands()) != 0 {
				t.Errorf("commands = %v; nothing may start without the guard", f.system.Commands())
			}
			if _, err := os.Stat(filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")); !os.IsNotExist(err) {
				t.Errorf("the idle instance's port file was written: %v", err)
			}
			if len(f.releases()) != 0 {
				t.Errorf("releases = %v", f.releases())
			}
		})
	}
}

func TestNodeDeploySyncsThePortGuardBeforeStartingTheRelease(t *testing.T) {
	f := nodeFixture(t)
	synced := false
	f.runner.PortGuard = func(context.Context) error {
		if commands := f.system.Commands(); len(commands) != 0 {
			t.Errorf("the guard synced after %v, want before the release started", commands)
		}
		synced = true

		return nil
	}

	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if !synced {
		t.Error("the guard wasn't synced")
	}
}

func TestNodeDeployLogsWhyThePortGuardFailed(t *testing.T) {
	f := nodeFixture(t)
	f.runner.PortGuard = func(context.Context) error { return errors.New("open the port map: permission denied") }

	f.run(state.KindDeploy, "")
	if !strings.Contains(f.out.String(), "Port guard: open the port map: permission denied") {
		t.Errorf("output = %s", f.out)
	}
}

func TestNodeReleaseWhosePortSomeoneElseHoldsDoesNotGoLive(t *testing.T) {
	f := nodeFixture(t)
	f.runner.Listener = fakeListener{err: &listenowner.ForeignError{Port: 20000, Foreign: []listenowner.Socket{{Port: 20000, UID: 1001, Inode: 7}}}}

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || d.Error != "Port 20000 is held by a process outside the release." {
		t.Fatalf("deployment = %+v", d)
	}
	if !strings.Contains(f.out.String(), "owned by uid 1001") {
		t.Errorf("output = %s", f.out)
	}

	commands := f.system.Commands()
	for _, want := range []string{"systemctl disable serverdog-site-abcdefghijkl@20000.service", "systemctl stop serverdog-site-abcdefghijkl@20000.service"} {
		if !slices.Contains(commands, want) {
			t.Errorf("missing %q in %v", want, commands)
		}
	}
	if slices.Contains(commands, "nginx -t") || slices.Contains(commands, "systemctl enable serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("commands = %v; the switch went ahead", commands)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/nginx/serverdog/upstreams/abcdefghijkl.conf")); !os.IsNotExist(err) {
		t.Errorf("the upstream was written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")); !os.IsNotExist(err) {
		t.Errorf("the idle instance's port file is left: %v", err)
	}
	if live, _ := f.store.LivePort("abcdefghijkl"); live != 0 {
		t.Errorf("live port = %d", live)
	}
}

func TestNodeDeployChecksTheListenerOfTheIdleInstance(t *testing.T) {
	f := nodeFixtureServing(t, 20000, string(nodeservice.RenderUpstream("abcdefghijkl", 20000)))
	listener := &recordingListener{}
	f.runner.Listener = listener

	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded {
		t.Fatalf("deployment = %+v\n%s", d, f.out)
	}
	if want := []string{"20001 serverdog-site-abcdefghijkl@20001.service"}; !slices.Equal(listener.checked, want) {
		t.Errorf("checked = %v, want %v", listener.checked, want)
	}
}

type recordingListener struct{ checked []string }

func (l *recordingListener) OwnedBy(_ context.Context, port int, unit string) error {
	l.checked = append(l.checked, fmt.Sprintf("%d %s", port, unit))

	return nil
}

func TestNodeReleaseWhosePortCouldNotBeCheckedDoesNotGoLive(t *testing.T) {
	f := nodeFixture(t)
	f.runner.Listener = fakeListener{err: errors.New("find the control group of serverdog-site-abcdefghijkl@20000.service: exit status 1")}

	d := f.run(state.KindDeploy, "")
	if d.State != state.Failed || d.WentLive || d.Error != "Port 20000 couldn't be checked, so the release wasn't started." {
		t.Fatalf("deployment = %+v", d)
	}
	if !strings.Contains(f.out.String(), "Listener check: find the control group of serverdog-site-abcdefghijkl@20000.service: exit status 1") {
		t.Errorf("output = %s", f.out)
	}

	commands := f.system.Commands()
	if !slices.Contains(commands, "systemctl stop serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("the idle instance wasn't stopped: %v", commands)
	}
	if slices.Contains(commands, "nginx -t") || slices.Contains(commands, "systemctl enable serverdog-site-abcdefghijkl@20000.service") {
		t.Errorf("commands = %v; the switch went ahead", commands)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/nginx/serverdog/upstreams/abcdefghijkl.conf")); !os.IsNotExist(err) {
		t.Errorf("the upstream was written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20000.env")); !os.IsNotExist(err) {
		t.Errorf("the idle instance's port file is left: %v", err)
	}
}

func TestProcessesRestartOnlyWhenTheLiveCodeChanged(t *testing.T) {
	f := newFixture(t, func(s *site.Site) {
		s.Processes = []site.Process{{ID: "workerid2345", Name: "Queue worker", Command: "php artisan queue:work", Count: 2}}
	})
	restart := "systemctl restart --no-block serverdog-process-abcdefghijkl-workerid2345@1.service serverdog-process-abcdefghijkl-workerid2345@2.service"

	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded || !slices.Contains(f.system.Commands(), restart) {
		t.Fatalf("deployment = %+v, commands = %v", d, f.system.Commands())
	}

	f.system.Reset()
	f.updateSite(func(s *site.Site) { s.DeployScript = "$CREATE_RELEASE()\nexit 3\n$ACTIVATE_RELEASE()\n" })
	if d := f.run(state.KindDeploy, ""); d.State != state.Failed || slices.Contains(f.system.Commands(), restart) {
		t.Errorf("a deploy that never went live restarted the processes: %v", f.system.Commands())
	}
}

func TestFrozenOPcacheReloadsPHPOnceLive(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.Runtime, s.PHPVersion = site.PHP, "8.4" })
	frozen := false
	f.runner.OPcacheFrozen = func() bool { return frozen }
	reload := "systemctl reload php8.4-fpm"

	if f.run(state.KindDeploy, ""); slices.Contains(f.system.Commands(), reload) {
		t.Errorf("PHP-FPM reloaded while OPcache checks files: %v", f.system.Commands())
	}

	frozen = true
	f.system.Reset()
	if d := f.run(state.KindDeploy, ""); d.State != state.Succeeded || !slices.Contains(f.system.Commands(), reload) {
		t.Errorf("deployment = %+v, commands = %v", d, f.system.Commands())
	}
}

func TestAFinishedDeployIsPostedToTheWebhook(t *testing.T) {
	f := newFixture(t, nil)

	var posted []state.Deployment
	f.runner.Notify = func(_ context.Context, _ site.Site, d state.Deployment) error {
		posted = append(posted, d)
		return nil
	}

	f.updateSite(func(s *site.Site) {
		s.DeployScript = "$CREATE_RELEASE()\nexit 3\n$ACTIVATE_RELEASE()\n"
	})
	f.run(state.KindDeploy, "")

	if len(posted) != 1 || posted[0].State != state.Failed || posted[0].Error == "" {
		t.Fatalf("posted %+v, want the failed deploy with its error", posted)
	}
}
