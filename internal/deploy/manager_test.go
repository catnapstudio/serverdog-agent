package deploy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func (f *fixture) manager() *Manager {
	return &Manager{
		Store:      f.store,
		Paths:      paths.Paths{Root: f.root},
		System:     f.system,
		Executable: "/usr/local/bin/serverdog-agent",
		StateDir:   "/var/lib/serverdog",
		Now:        func() time.Time { return f.clock },
		NewID:      ids.New,
		Locks:      &lock.Keyed{},
		Exec:       system.Exec{},
		LookupUser: func(string) (system.User, error) { return system.CurrentUser() },
	}
}

func TestDeployStartsAUnitWithTheLog(t *testing.T) {
	f := newFixture(t, nil)

	d, running, err := f.manager().Deploy(ctx, "abcdefghijkl", "Morgan's Mac")
	if err != nil || running {
		t.Fatalf("Deploy = %v, %v", running, err)
	}

	log := paths.DeployLog("abcdefghijkl", d.ID)
	want := fmt.Sprintf("systemd-run --unit serverdog-deploy-%s --collect --quiet --property=RuntimeMaxSec=1860 --property=KillMode=mixed --property=StandardOutput=append:%[2]s --property=StandardError=append:%[2]s /usr/local/bin/serverdog-agent run-deploy --state-dir /var/lib/serverdog %[1]s", d.ID, log)
	if got := f.system.Commands(); len(got) != 1 || got[0] != want {
		t.Errorf("commands =\n%v\nwant\n%s", got, want)
	}

	info, err := os.Stat(filepath.Join(f.root, log))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("log file = %v %v", info, err)
	}

	stored, _ := f.store.GetDeployment(d.ID)
	if stored.State != state.Running || stored.Actor != "Morgan's Mac" || len(stored.Phases) == 0 || stored.Marker == "" {
		t.Errorf("stored = %+v", stored)
	}
}

func TestDeployReturnsTheRunningDeploy(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()

	first, _, _ := manager.Deploy(ctx, "abcdefghijkl", "Mac")
	second, running, err := manager.Deploy(ctx, "abcdefghijkl", "Mac")
	if err != nil || !running || second.ID != first.ID {
		t.Errorf("second = %s %v %v", second.ID, running, err)
	}
	if len(f.system.Calls()) != 1 {
		t.Errorf("started %d units", len(f.system.Calls()))
	}
}

func TestAUnitThatDoesNotStartFailsTheDeployment(t *testing.T) {
	f := newFixture(t, nil)
	f.system.Fail("systemd-run", 1, "Failed to start transient service unit")

	d, _, err := f.manager().Deploy(ctx, "abcdefghijkl", "Mac")
	if err == nil {
		t.Fatal("expected an error")
	}

	stored, _ := f.store.GetDeployment(d.ID)
	if stored.State != state.Failed || !strings.Contains(stored.Error, "couldn't start") {
		t.Errorf("stored = %+v", stored)
	}
}

func TestRecoverOnlyInterruptsUnitsSystemdSaysAreGone(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()

	type answer struct {
		code   int
		output string
		want   string
	}
	table := []answer{
		{0, "active\n", state.Running},
		{3, "deactivating\n", state.Running},
		{3, "failed\n", state.Interrupted},
		{4, "inactive\n", state.Interrupted},
		{3, "", state.Interrupted},
		{1, "", state.Running},
	}

	answers := map[string]answer{}
	var deployments []state.Deployment
	for i, a := range table {
		s, _ := f.store.GetSite("abcdefghijkl")
		s.ID = ids.New()
		s.Domains = []site.Domain{{Name: fmt.Sprintf("s%d.example.com", i), Redirect: site.NoRedirect, Primary: true}}
		if _, err := f.store.PutSite(s, 0, f.clock); err != nil {
			t.Fatal(err)
		}

		d := state.Deployment{ID: ids.New(), SiteID: s.ID, Kind: state.KindDeploy, State: state.Running, Actor: "Mac", Release: fmt.Sprintf("20261016-17000%d", i), Phases: PlannedPhases(s, state.KindDeploy), StartedAt: f.clock.Add(-time.Minute)}
		if err := f.store.CreateDeployment(d); err != nil {
			t.Fatal(err)
		}
		os.MkdirAll(filepath.Join(f.root, s.Directory, "releases", d.Release), 0o755)

		answers[Unit(d.ID)] = a
		deployments = append(deployments, d)
	}

	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		a := answers[c.Args[len(c.Args)-1]]
		if a.code == 0 {
			return system.Result{Output: []byte(a.output)}, nil
		}
		return system.Result{Output: []byte(a.output), ExitCode: a.code}, &system.ExitError{Command: "systemctl", ExitCode: a.code, Output: []byte(a.output)}
	})

	manager.Recover(ctx)

	for i, a := range table {
		got, _ := f.store.GetDeployment(deployments[i].ID)
		if got.State != a.want {
			t.Errorf("is-active exit %d printing %q: state %s, want %s", a.code, a.output, got.State, a.want)
		}
	}

	interrupted, _ := f.store.GetDeployment(deployments[2].ID)
	s, _ := f.store.GetSite(interrupted.SiteID)
	if _, err := os.Stat(filepath.Join(f.root, s.Directory, "releases", interrupted.Release)); !os.IsNotExist(err) {
		t.Error("an interrupted deploy's release that never went live was kept")
	}

	running, _ := f.store.GetDeployment(deployments[1].ID)
	s, _ = f.store.GetSite(running.SiteID)
	if _, err := os.Stat(filepath.Join(f.root, s.Directory, "releases", running.Release)); err != nil {
		t.Errorf("a deploy that is still shutting down lost its release: %v", err)
	}
}

func TestRecoverKeepsTheReleaseCurrentPointsAt(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()

	id := f.start(state.KindDeploy, "20261016-170000")
	f.clock = f.clock.Add(time.Minute)
	release := filepath.Join(f.dir(), "releases/20261016-170000")
	os.MkdirAll(release, 0o755)
	if err := os.Symlink("releases/20261016-170000", filepath.Join(f.dir(), "current")); err != nil {
		t.Fatal(err)
	}
	f.system.Fail("systemctl", 3, "inactive\n")

	manager.Recover(ctx)

	if got, _ := f.store.GetDeployment(id); got.State != state.Interrupted {
		t.Errorf("state = %s", got.State)
	}
	if _, err := os.Stat(release); err != nil {
		t.Errorf("the live release was deleted: %v", err)
	}
}

func TestAbandonedReleasesAreRemovedAsTheSiteUser(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	exec := &systemtest.Fake{}
	user := system.User{Name: "siteuser", UID: 4242, GID: 4343}
	manager.Exec = exec
	manager.AsUser = true
	manager.LookupUser = func(name string) (system.User, error) {
		if name != "siteuser" {
			t.Errorf("looked up %q", name)
		}
		return user, nil
	}
	f.updateSite(func(s *site.Site) { s.User = "siteuser" })

	f.start(state.KindDeploy, "20261016-170000")
	f.clock = f.clock.Add(time.Minute)
	f.system.Fail("systemctl", 3, "inactive\n")

	manager.Recover(ctx)

	calls := exec.Calls()
	if len(calls) != 1 {
		t.Fatalf("calls = %v", exec.Commands())
	}

	want := "rm -rf -- " + filepath.Join(f.dir(), "releases/20261016-170000")
	if got := exec.Commands()[0]; got != want {
		t.Errorf("command = %q, want %q", got, want)
	}
	if calls[0].User == nil || !reflect.DeepEqual(*calls[0].User, user) {
		t.Errorf("user = %+v, want %+v", calls[0].User, user)
	}
}

func TestRecoverLeavesDeploysThatJustStarted(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	d, _, _ := manager.Deploy(ctx, "abcdefghijkl", "Mac")
	f.system.Fail("systemctl", 4, "")

	manager.Recover(ctx)

	if got, _ := f.store.GetDeployment(d.ID); got.State != state.Running {
		t.Errorf("state = %s; a unit that is still being created was interrupted", got.State)
	}
}

func TestCancelStopsTheUnitAndRecordsWho(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	d, _, _ := manager.Deploy(ctx, "abcdefghijkl", "Mac")

	// The runner records the cancellation when systemd stops it.
	f.system.Handle("systemctl", func(system.Command) (system.Result, error) {
		f.store.UpdateDeployment(d.ID, func(d *state.Deployment) { d.State = state.Cancelled })
		return system.Result{}, nil
	})

	cancelled, err := manager.Cancel(ctx, d.ID, "Other Mac")
	if err != nil || cancelled.State != state.Cancelled {
		t.Fatalf("Cancel = %+v %v", cancelled, err)
	}
	if !slices.Contains(f.system.Commands(), "systemctl stop "+Unit(d.ID)) {
		t.Errorf("commands = %v", f.system.Commands())
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	if len(activity) != 1 || activity[0].Kind != "deploy.cancelled" || activity[0].Actor != "Other Mac" {
		t.Errorf("activity = %+v", activity)
	}
}

func TestCancelRecordsItWhenTheRunnerCouldNot(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	d, _, _ := manager.Deploy(ctx, "abcdefghijkl", "Mac")

	cancelled, err := manager.Cancel(ctx, d.ID, "Mac")
	if err != nil || cancelled.State != state.Cancelled || cancelled.FinishedAt.IsZero() {
		t.Errorf("Cancel = %+v %v", cancelled, err)
	}
}

func TestCancelTreatsAnUnloadedUnitAsStopped(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	d, _, _ := manager.Deploy(ctx, "abcdefghijkl", "Mac")
	f.system.Fail("systemctl", 5, "Unit not loaded.")

	cancelled, err := manager.Cancel(ctx, d.ID, "Mac")
	if err != nil || cancelled.State != state.Cancelled {
		t.Errorf("Cancel = %+v %v", cancelled, err)
	}
}

func TestRollbackNeedsAKeptRelease(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()

	_, err := manager.Rollback(ctx, "abcdefghijkl", "20261016-170000", "Mac")
	var invalid *site.InvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v", err)
	}

	if _, err := manager.Rollback(ctx, "abcdefghijkl", "../../etc", "Mac"); !errors.As(err, &invalid) {
		t.Errorf("path in release name: %v", err)
	}

	os.MkdirAll(filepath.Join(f.dir(), "releases/20261016-170000"), 0o755)
	if _, err := manager.Rollback(ctx, "abcdefghijkl", "20261016-170000", "Mac"); !errors.As(err, &invalid) || !strings.Contains(invalid.Reason, "never went live") {
		t.Fatalf("rollback to a release that never went live: %v", err)
	}

	id := f.start(state.KindDeploy, "20261016-170000")
	f.store.UpdateDeployment(id, func(d *state.Deployment) { d.State, d.WentLive = state.Succeeded, true })

	d, err := manager.Rollback(ctx, "abcdefghijkl", "20261016-170000", "Mac")
	if err != nil || d.Kind != state.KindRollback || d.Release != "20261016-170000" {
		t.Errorf("rollback = %+v %v", d, err)
	}
}

func TestRecoverKeepsAReleaseANodePortFileNames(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()

	id := f.start(state.KindDeploy, "20261016-170000")
	f.clock = f.clock.Add(time.Minute)
	release := filepath.Join(f.dir(), "releases/20261016-170000")
	os.MkdirAll(release, 0o755)
	portEnv := filepath.Join(f.root, "etc/serverdog/sites/abcdefghijkl/20001.env")
	os.MkdirAll(filepath.Dir(portEnv), 0o755)
	if err := os.WriteFile(portEnv, nodeservice.RenderPortEnv(20001, release), 0o644); err != nil {
		t.Fatal(err)
	}
	f.system.Fail("systemctl", 3, "inactive\n")

	manager.Recover(ctx)

	if got, _ := f.store.GetDeployment(id); got.State != state.Interrupted {
		t.Errorf("state = %s", got.State)
	}
	if _, err := os.Stat(release); err != nil {
		t.Errorf("a release Nginx may serve was deleted: %v", err)
	}
}

// contextRunner records whether each command's context was already done and whether it had a deadline.
type contextRunner struct {
	cancelled   []bool
	hasDeadline []bool
}

func (r *contextRunner) Run(ctx context.Context, _ system.Command) (system.Result, error) {
	_, deadline := ctx.Deadline()
	r.cancelled = append(r.cancelled, ctx.Err() != nil)
	r.hasDeadline = append(r.hasDeadline, deadline)

	return system.Result{}, nil
}

func TestDeployStartsTheUnitEvenWhenTheClientLeaves(t *testing.T) {
	f := newFixture(t, nil)
	manager := f.manager()
	recorder := &contextRunner{}
	manager.System = recorder

	gone, cancel := context.WithCancel(ctx)
	cancel()

	d, _, err := manager.Deploy(gone, "abcdefghijkl", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.cancelled) != 1 || recorder.cancelled[0] || !recorder.hasDeadline[0] {
		t.Errorf("systemd-run context: cancelled %v, deadline %v; want a live context with a deadline", recorder.cancelled, recorder.hasDeadline)
	}
	if stored, _ := f.store.GetDeployment(d.ID); stored.State != state.Running {
		t.Errorf("state = %s", stored.State)
	}
}

func TestAnInPlaceSiteWithoutARepositoryDeploysItsScriptAlone(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.RepositoryURL, s.Branch, s.ZeroDowntime = "", "", false })

	d, _, err := f.manager().Deploy(ctx, "abcdefghijkl", "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Phases) != 1 || d.Phases[0].Name != state.PhaseBuild {
		t.Errorf("phases = %+v, want only the build", d.Phases)
	}
}

func TestAZeroDowntimeDeployWithoutARepositoryIsRefusedAndRecordsNothing(t *testing.T) {
	f := newFixture(t, func(s *site.Site) { s.RepositoryURL, s.Branch = "", "" })

	_, _, err := f.manager().Deploy(ctx, "abcdefghijkl", "Mac")
	if !errors.Is(err, ErrNoRepository) {
		t.Fatalf("err = %v, want ErrNoRepository", err)
	}

	if list, _ := f.store.ListDeployments("abcdefghijkl", 10); len(list) != 0 {
		t.Errorf("deployments = %+v", list)
	}
	if len(f.system.Calls()) != 0 {
		t.Errorf("ran %v", f.system.Commands())
	}
	if _, err := os.Stat(filepath.Join(f.root, paths.DeployLogDir("abcdefghijkl"))); !os.IsNotExist(err) {
		t.Errorf("deploy log dir: %v", err)
	}
}

func TestDeployRecordsTheScriptItPlannedFrom(t *testing.T) {
	f := newFixture(t, nil)
	s, _ := f.store.GetSite("abcdefghijkl")

	d, _, err := f.manager().Deploy(ctx, "abcdefghijkl", "Mac")
	if err != nil {
		t.Fatal(err)
	}

	stored, err := f.store.GetDeployment(d.ID)
	if err != nil || stored.Script != s.DeployScript {
		t.Errorf("script = %q %v, want %q", stored.Script, err, s.DeployScript)
	}
}
