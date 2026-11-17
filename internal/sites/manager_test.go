package sites

import (
	"context"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var ctx = context.Background()

type fixture struct {
	t       *testing.T
	root    string
	store   *state.Store
	system  *systemtest.Fake
	manager *Manager
	users   map[string]bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	current, _ := system.CurrentUser()
	f := &fixture{t: t, root: root, store: store, system: &systemtest.Fake{}, users: map[string]bool{"serverdog": true}}

	f.system.Handle("useradd", func(c system.Command) (system.Result, error) {
		f.users[c.Args[len(c.Args)-1]] = true
		return system.Result{}, nil
	})

	f.manager = &Manager{
		Store:   store,
		Paths:   paths.Paths{Root: root},
		System:  f.system,
		Exec:    system.Exec{},
		Applier: apply.Applier{Runner: f.system, LockPath: filepath.Join(root, "apply.lock")},
		Keys:    gitsource.Keys{Paths: paths.Paths{Root: root}},
		Capabilities: func(context.Context) capabilities.Capabilities {
			return capabilities.Capabilities{PHPVersions: []string{"8.4", "8.3"}, NginxVersion: "1.24.0", NodeVersion: "v24.22.0"}
		},
		LookupUser: func(name string) (system.User, error) {
			if !f.users[name] {
				return system.User{}, errors.New("unknown user " + name)
			}
			user := current
			user.Name = name
			return user, nil
		},
		Now:   func() time.Time { return time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC) },
		Locks: &lock.Keyed{},
	}

	f.installPHP("8.4")
	f.installPHP("8.3")

	return f
}

// installPHP puts a PHP version's FPM binary and systemd unit where the package installs them.
func (f *fixture) installPHP(version string) {
	f.t.Helper()

	for _, logical := range []string{"/usr/sbin/php-fpm" + version, "/usr/lib/systemd/system/php" + version + "-fpm.service"} {
		if err := os.MkdirAll(filepath.Dir(f.file(logical)), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(f.file(logical), nil, 0o755); err != nil {
			f.t.Fatal(err)
		}
	}
}

// uninstallPHP removes what installPHP put in place, and makes the version's check and reload fail as they do once
// the package is gone.
func (f *fixture) uninstallPHP(version string) {
	f.t.Helper()

	for _, logical := range []string{"/usr/sbin/php-fpm" + version, "/usr/lib/systemd/system/php" + version + "-fpm.service"} {
		if err := os.Remove(f.file(logical)); err != nil {
			f.t.Fatal(err)
		}
	}

	f.system.Fail("/usr/sbin/php-fpm"+version, 127, "exec: \"/usr/sbin/php-fpm"+version+"\": stat /usr/sbin/php-fpm"+version+": no such file or directory")
	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		if strings.Join(c.Args, " ") != "reload php"+version+"-fpm" {
			return system.Result{}, nil
		}

		output := []byte("Failed to reload php" + version + "-fpm.service: Unit php" + version + "-fpm.service not found.")
		return system.Result{Output: output, ExitCode: 5}, &system.ExitError{Command: "systemctl", ExitCode: 5, Output: output}
	})
}

func laravel() site.Site {
	return site.Site{
		ID:              "abcdefghijkl",
		Preset:          "laravel",
		Runtime:         site.PHP,
		Domains:         []site.Domain{{Name: "orchard.com", Redirect: site.FromWWW, Primary: true}},
		RepositoryURL:   "git@github.com:morgan/orchard.git",
		Branch:          "main",
		PHPVersion:      "8.4",
		WebDirectory:    "public",
		EnvironmentFile: ".env",
		SharedPaths:     []string{"storage"},
		DeployScript:    "$CREATE_RELEASE()\n$ACTIVATE_RELEASE()\n",
		ZeroDowntime:    true,
		User:            "serverdog",
	}
}

func (f *fixture) file(logical string) string { return filepath.Join(f.root, logical) }

func (f *fixture) exists(logical string) bool {
	_, err := os.Lstat(f.file(logical))
	return err == nil
}

func TestPutCreatesAPHPSite(t *testing.T) {
	f := newFixture(t)

	saved, created, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil || !created {
		t.Fatalf("Put = %v, %v", created, err)
	}
	if saved.Revision != 1 || saved.Directory != "/home/serverdog/orchard.com" || saved.ReleasesToKeep != 5 {
		t.Errorf("saved = %+v", saved)
	}

	for _, logical := range []string{
		"/etc/nginx/sites-available/serverdog-abcdefghijkl.conf",
		"/etc/nginx/sites-enabled/serverdog-abcdefghijkl.conf",
		"/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf",
		"/home/serverdog/orchard.com/releases",
		"/home/serverdog/orchard.com/shared/.env",
		"/home/serverdog/.ssh/serverdog-abcdefghijkl",
		"/home/serverdog/.ssh/serverdog-abcdefghijkl.known_hosts",
	} {
		if !f.exists(logical) {
			t.Errorf("missing %s", logical)
		}
	}

	if info, _ := os.Stat(f.file("/home/serverdog/orchard.com/shared/.env")); info.Mode().Perm() != 0o600 {
		t.Errorf(".env mode = %v", info.Mode())
	}

	want := []string{"usermod -aG serverdog www-data", "/usr/sbin/php-fpm8.4 -t", "nginx -t", "systemctl reload php8.4-fpm", "/usr/local/bin/serverdog-agent reload-nginx"}
	if got := f.system.Commands(); !slices.Equal(got, want) {
		t.Errorf("commands =\n%v\nwant\n%v", got, want)
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	if len(activity) != 1 || activity[0].Kind != "site.created" {
		t.Errorf("activity = %+v", activity)
	}
}

func TestPutTwiceReloadsNothing(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, laravel(), 0, "Mac")
	f.system.Reset()

	if _, created, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil || created {
		t.Fatalf("second Put = %v, %v", created, err)
	}

	for _, command := range f.system.Commands() {
		if strings.Contains(command, "reload") || strings.HasSuffix(command, " -t") {
			t.Errorf("unchanged site ran %q", command)
		}
	}
}

func TestPutRetriesAfterFailedApply(t *testing.T) {
	f := newFixture(t)
	isolated := laravel()
	isolated.Isolated, isolated.User = true, "orchard"
	f.system.Fail("nginx", 1, "nginx: [emerg] host not found in upstream")

	_, _, err := f.manager.Put(ctx, isolated, 0, "Mac")
	var applyErr *apply.Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Error("a site whose config was rejected was stored")
	}
	if f.exists("/etc/nginx/sites-available/serverdog-abcdefghijkl.conf") {
		t.Error("rejected config left in place")
	}

	f.system = &systemtest.Fake{}
	f.system.Handle("useradd", func(system.Command) (system.Result, error) {
		t.Error("useradd ran again on retry")
		return system.Result{}, nil
	})
	f.manager.System = f.system
	f.manager.Applier.Runner = f.system

	saved, created, err := f.manager.Put(ctx, isolated, 0, "Mac")
	if err != nil || !created || saved.Directory != "/home/orchard/orchard.com" {
		t.Fatalf("retry = %+v %v %v", saved, created, err)
	}

	f.system.Reset()
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}
	for _, command := range f.system.Commands() {
		if strings.Contains(command, "reload") {
			t.Errorf("identical Put ran %q", command)
		}
	}
}

func TestIsolatedUserMustBeNew(t *testing.T) {
	f := newFixture(t)
	f.users["orchard"] = true

	isolated := laravel()
	isolated.Isolated, isolated.User = true, "orchard"

	var invalid *site.InvalidError
	if _, _, err := f.manager.Put(ctx, isolated, 0, "Mac"); !errors.As(err, &invalid) {
		t.Errorf("err = %v", err)
	}
}

func TestPutRejectsConflictsBeforeTouchingAnything(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.system.Reset()

	other := laravel()
	other.ID = "bbbbbbbbbbbb"
	_, _, err := f.manager.Put(ctx, other, 0, "Mac")

	var taken *state.DomainTakenError
	if !errors.As(err, &taken) {
		t.Fatalf("err = %v", err)
	}
	if len(f.system.Calls()) != 0 {
		t.Errorf("ran %v", f.system.Commands())
	}

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); !errors.Is(err, state.ErrStaleRevision) {
		t.Errorf("stale create err = %v", err)
	}
}

func TestChangingThePHPVersionMovesThePool(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, laravel(), 0, "Mac")
	f.system.Reset()

	saved.PHPVersion = "8.3"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	if f.exists("/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf") || !f.exists("/etc/php/8.3/fpm/pool.d/serverdog-abcdefghijkl.conf") {
		t.Error("pool not moved")
	}
	for _, want := range []string{"systemctl reload php8.3-fpm", "systemctl reload php8.4-fpm"} {
		if !slices.Contains(f.system.Commands(), want) {
			t.Errorf("missing %q in %v", want, f.system.Commands())
		}
	}
}

func TestPutCreatesANodeSite(t *testing.T) {
	f := newFixture(t)
	node := laravel()
	node.Runtime, node.PHPVersion, node.WebDirectory, node.NodeStartCommand = site.Node, "", "", "npm run start -- -H 127.0.0.1"

	if _, _, err := f.manager.Put(ctx, node, 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	unit, _ := os.ReadFile(f.file("/etc/systemd/system/serverdog-site-abcdefghijkl@.service"))
	if strings.Contains(string(unit), "shared/.env") {
		t.Errorf("unit reads the site's environment file as root: %s", unit)
	}
	start, _ := os.ReadFile(f.file("/etc/serverdog/sites/abcdefghijkl/start.sh"))
	if !strings.Contains(string(start), "env-exports '/home/serverdog/orchard.com/shared/.env'") {
		t.Errorf("start.sh = %s", start)
	}
	if info, err := os.Stat(f.file("/etc/serverdog/sites/abcdefghijkl/start.sh")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("start.sh = %v %v", info, err)
	}
	upstream, _ := os.ReadFile(f.file("/etc/nginx/serverdog/upstreams/abcdefghijkl.conf"))
	if !strings.Contains(string(upstream), "127.0.0.1:20000;") {
		t.Errorf("upstream = %s", upstream)
	}
	if !slices.Contains(f.system.Commands(), "systemctl daemon-reload") {
		t.Errorf("commands = %v", f.system.Commands())
	}
}

func TestEnvRoundTripChecksForOtherEdits(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")

	content, sum, err := f.manager.Env(ctx, "abcdefghijkl")
	if err != nil || len(content) != 0 || sum != Sum(nil) {
		t.Fatalf("Env = %q %s %v", content, sum, err)
	}

	if _, err := f.manager.PutEnv(ctx, "abcdefghijkl", []byte("APP_KEY=x\n"), Sum([]byte("other")), "Mac"); !errors.Is(err, ErrStaleContent) {
		t.Errorf("stale PutEnv err = %v", err)
	}

	newSum, err := f.manager.PutEnv(ctx, "abcdefghijkl", []byte("APP_KEY=x\n"), sum, "Mac")
	if err != nil || newSum != Sum([]byte("APP_KEY=x\n")) {
		t.Fatalf("PutEnv = %s %v", newSum, err)
	}

	content, _, _ = f.manager.Env(ctx, "abcdefghijkl")
	if string(content) != "APP_KEY=x\n" {
		t.Errorf("content = %q", content)
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	if activity[0].Kind != "env.changed" || strings.Contains(activity[0].Summary, "APP_KEY") {
		t.Errorf("activity = %+v", activity[0])
	}
}

func TestCustomisedNginxConfigSurvivesPutUntilReset(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, laravel(), 0, "Mac")

	generated, sum, customised, err := f.manager.NginxConfig(ctx, "abcdefghijkl")
	if err != nil || customised || !strings.Contains(string(generated), "server_name orchard.com;") {
		t.Fatalf("NginxConfig = %v %v", customised, err)
	}

	custom := append([]byte("# my change\n"), generated...)
	if _, err := f.manager.PutNginxConfig(ctx, "abcdefghijkl", custom, sum, "Mac"); err != nil {
		t.Fatal(err)
	}

	current, _ := f.store.GetSite("abcdefghijkl")
	current.Branch = "develop"
	if _, _, err := f.manager.Put(ctx, current, current.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	content, _, customised, _ := f.manager.NginxConfig(ctx, "abcdefghijkl")
	if !customised || !strings.HasPrefix(string(content), "# my change") {
		t.Errorf("customised config overwritten (customised=%v)", customised)
	}

	reset, _, err := f.manager.ResetNginxConfig(ctx, "abcdefghijkl", "Mac")
	if err != nil || strings.Contains(string(reset), "# my change") {
		t.Fatalf("reset = %v", err)
	}
	if after, _ := f.store.GetSite("abcdefghijkl"); after.NginxCustomised || after.Revision <= saved.Revision {
		t.Errorf("site after reset = %+v", after)
	}
}

func TestInvalidCustomConfigIsNotApplied(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	before, sum, _, _ := f.manager.NginxConfig(ctx, "abcdefghijkl")
	f.system.Fail("nginx", 1, `nginx: [emerg] unknown directive "bogus"`)

	_, err := f.manager.PutNginxConfig(ctx, "abcdefghijkl", []byte("bogus;\n"), sum, "Mac")
	var applyErr *apply.Error
	if !errors.As(err, &applyErr) || !strings.Contains(applyErr.Output, "bogus") {
		t.Fatalf("err = %v", err)
	}

	after, _, customised, _ := f.manager.NginxConfig(ctx, "abcdefghijkl")
	if string(after) != string(before) || customised {
		t.Error("rejected config was kept")
	}
}

func TestDeleteRemovesConfigAndOptionallyFiles(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")

	if err := f.manager.Delete(ctx, "abcdefghijkl", true, "Mac"); err != nil {
		t.Fatal(err)
	}

	for _, logical := range []string{
		"/etc/nginx/sites-available/serverdog-abcdefghijkl.conf",
		"/etc/nginx/sites-enabled/serverdog-abcdefghijkl.conf",
		"/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf",
		"/home/serverdog/orchard.com",
		"/home/serverdog/.ssh/serverdog-abcdefghijkl",
	} {
		if f.exists(logical) {
			t.Errorf("%s still exists", logical)
		}
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("site still stored: %v", err)
	}
	if owner, ok, _ := f.store.DomainOwner("orchard.com"); ok {
		t.Errorf("domain still owned by %s", owner)
	}
}

func TestDeleteRefusesWhileDeploying(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.store.CreateDeployment(state.Deployment{ID: "dddddddddddd", SiteID: "abcdefghijkl", Kind: state.KindDeploy, State: state.Running, Actor: "Mac", StartedAt: time.Now()})

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); !errors.Is(err, state.ErrDeployRunning) {
		t.Errorf("err = %v", err)
	}
}

func TestDeployKeyBeforeAndAfterCreation(t *testing.T) {
	f := newFixture(t)

	pending, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	installed, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil || installed != pending {
		t.Errorf("installed = %+v %v, want the key shown before creation", installed, err)
	}
}

func TestFailedCreateKeepsTheKeyTheUserWasShown(t *testing.T) {
	f := newFixture(t)
	pendingDir := paths.PendingKeyDir("abcdefghijkl")

	shown, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}

	f.system.Fail("nginx", 1, "nginx: [emerg] rejected")
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err == nil {
		t.Fatal("Put succeeded although nginx rejected the config")
	}

	afterFailure, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil || afterFailure != shown {
		t.Fatalf("key after failed create = %+v %v, want %+v", afterFailure, err, shown)
	}

	installed, _ := os.ReadFile(f.file("/home/serverdog/.ssh/serverdog-abcdefghijkl.pub"))
	if !strings.HasPrefix(string(installed), strings.TrimSpace(shown.PublicKey)) {
		t.Errorf("installed key %q is not the one shown %q", installed, shown.PublicKey)
	}

	f.system = &systemtest.Fake{}
	f.manager.System = f.system
	f.manager.Applier.Runner = f.system

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	final, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil || final != shown {
		t.Errorf("key after retry = %+v %v, want %+v", final, err, shown)
	}
	if f.exists(pendingDir) {
		t.Error("pending key directory left behind after the site was saved")
	}
}

func TestFailedCreateWithoutAPriorKeyViewStillMatches(t *testing.T) {
	f := newFixture(t)
	f.system.Fail("nginx", 1, "nginx: [emerg] rejected")
	f.manager.Put(ctx, laravel(), 0, "Mac")

	shown, err := f.manager.DeployKey(ctx, "abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}

	f.system = &systemtest.Fake{}
	f.manager.System = f.system
	f.manager.Applier.Runner = f.system
	f.manager.Put(ctx, laravel(), 0, "Mac")

	if final, err := f.manager.DeployKey(ctx, "abcdefghijkl"); err != nil || final != shown {
		t.Errorf("installed key = %+v %v, want the one shown after the failure %+v", final, err, shown)
	}
}

func nodeSite() site.Site {
	node := laravel()
	node.Runtime, node.PHPVersion, node.WebDirectory, node.NodeStartCommand = site.Node, "", "", "npm run start -- -H 127.0.0.1"

	return node
}

func TestDeletingANodeSiteStopsNginxBeforeTheService(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, nodeSite(), 0, "Mac")
	f.system.Reset()

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"nginx -t",
		"/usr/local/bin/serverdog-agent reload-nginx",
		"systemctl disable --now serverdog-site-abcdefghijkl@20000.service",
		"systemctl disable --now serverdog-site-abcdefghijkl@20001.service",
		"systemctl daemon-reload",
	}
	if got := f.system.Commands(); !slices.Equal(got, want) {
		t.Errorf("commands =\n%v\nwant\n%v", got, want)
	}

	for _, logical := range []string{
		"/etc/systemd/system/serverdog-site-abcdefghijkl@.service",
		"/etc/nginx/serverdog/upstreams/abcdefghijkl.conf",
		"/etc/serverdog/sites/abcdefghijkl/start.sh",
		"/etc/nginx/sites-enabled/serverdog-abcdefghijkl.conf",
	} {
		if f.exists(logical) {
			t.Errorf("%s still exists", logical)
		}
	}
}

func TestDeletingANodeSiteKeepsItRunningWhenNginxRejectsTheChange(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, nodeSite(), 0, "Mac")
	f.system.Reset()
	f.system.Fail("nginx", 1, "nginx: [emerg] rejected")

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err == nil {
		t.Fatal("Delete succeeded")
	}

	for _, command := range f.system.Commands() {
		if strings.Contains(command, "disable") {
			t.Errorf("stopped the service although nginx rejected the change: %q", command)
		}
	}
	if _, err := f.store.GetSite("abcdefghijkl"); err != nil {
		t.Errorf("site record lost: %v", err)
	}
	if !f.exists("/etc/systemd/system/serverdog-site-abcdefghijkl@.service") {
		t.Error("unit removed")
	}
}

func TestDeleteReturnsAFailureToStopTheService(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, nodeSite(), 0, "Mac")
	f.system.Handle("systemctl", func(c system.Command) (system.Result, error) {
		if c.Args[0] == "disable" {
			return system.Result{ExitCode: 1}, &system.ExitError{Command: "systemctl", ExitCode: 1, Output: []byte("Failed to disable unit")}
		}

		return system.Result{}, nil
	})

	err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac")
	if err == nil || !strings.Contains(err.Error(), "serverdog-site-abcdefghijkl@20000.service") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.store.GetSite("abcdefghijkl"); err != nil {
		t.Errorf("site record lost although the service is still running: %v", err)
	}
}

func TestDeletingAnIsolatedSiteRemovesItsUser(t *testing.T) {
	f := newFixture(t)
	isolated := laravel()
	isolated.Isolated, isolated.User = true, "orchard"
	f.manager.Put(ctx, isolated, 0, "Mac")
	f.system.Reset()

	if err := f.manager.Delete(ctx, "abcdefghijkl", true, "Mac"); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.system.Commands(), "userdel --remove orchard") {
		t.Errorf("commands = %v", f.system.Commands())
	}
	if f.exists("/home/orchard/orchard.com") {
		t.Error("site directory left behind")
	}
}

func TestDeleteReturnsAUserdelFailureAndAllowsARetry(t *testing.T) {
	f := newFixture(t)
	isolated := laravel()
	isolated.Isolated, isolated.User = true, "orchard"
	f.manager.Put(ctx, isolated, 0, "Mac")
	f.system.Handle("userdel", func(system.Command) (system.Result, error) {
		return system.Result{ExitCode: 8}, &system.ExitError{Command: "userdel", ExitCode: 8, Output: []byte("user is currently used by process 1")}
	})

	err := f.manager.Delete(ctx, "abcdefghijkl", true, "Mac")
	if err == nil || !strings.Contains(err.Error(), "orchard") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.store.GetSite("abcdefghijkl"); err != nil {
		t.Fatalf("record removed although the user could not be: %v", err)
	}

	f.system.Handle("userdel", func(system.Command) (system.Result, error) { return system.Result{}, nil })
	if err := f.manager.Delete(ctx, "abcdefghijkl", true, "Mac"); err != nil {
		t.Errorf("retry = %v", err)
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("site still stored: %v", err)
	}
}

func TestDeletingANodeSiteCanBeRetriedAfterACleanupFailure(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, nodeSite(), 0, "Mac")

	failing := &systemtest.Fake{}
	failing.Fail("rm", 1, "rm: cannot remove: Permission denied")
	f.manager.Exec = failing

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err == nil {
		t.Fatal("Delete succeeded although the cleanup failed")
	}
	if _, err := f.store.GetSite("abcdefghijkl"); err != nil {
		t.Fatalf("record removed after a failed cleanup: %v", err)
	}

	f.manager.Exec = system.Exec{}
	f.system.Reset()

	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatalf("retry = %v", err)
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("site still stored: %v", err)
	}
	for _, command := range f.system.Commands() {
		if strings.Contains(command, "disable") {
			t.Errorf("retry ran %q for a unit that is already gone", command)
		}
	}
}

func TestPutLeavesAnExistingUpstreamToTheDeploy(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, nodeSite(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.SetLivePort("abcdefghijkl", 20000); err != nil {
		t.Fatal(err)
	}

	// A deploy is switching to port 20001: it wrote the upstream but hasn't recorded the live port yet.
	upstream := f.file("/etc/nginx/serverdog/upstreams/abcdefghijkl.conf")
	switched := nodeservice.RenderUpstream("abcdefghijkl", 20001)
	if err := os.WriteFile(upstream, switched, 0o644); err != nil {
		t.Fatal(err)
	}

	saved.Branch = "develop"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatal(err)
	}

	if got, _ := os.ReadFile(upstream); string(got) != string(switched) {
		t.Errorf("upstream = %s, want the deploy's %s", got, switched)
	}
}

func TestAnIdenticalPutChangesNothing(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	f.system.Reset()

	// What the app sends back: the site as it got it, agent-owned fields included or not.
	again := saved
	again.Revision, again.Directory, again.CreatedAt = 0, "", time.Time{}
	again.SharedPaths = append([]string{}, saved.SharedPaths...)

	got, created, err := f.manager.Put(ctx, again, saved.Revision, "Mac")
	if err != nil || created {
		t.Fatalf("Put = %v, %v", created, err)
	}
	if got.Revision != saved.Revision || got.Directory != saved.Directory || !got.CreatedAt.Equal(saved.CreatedAt) {
		t.Errorf("site = %+v, want the stored %+v", got, saved)
	}
	if stored, _ := f.store.GetSite("abcdefghijkl"); stored.Revision != saved.Revision {
		t.Errorf("stored revision = %d, want %d", stored.Revision, saved.Revision)
	}
	if activity, _ := f.store.ListActivity("abcdefghijkl", 10); len(activity) != 1 {
		t.Errorf("activity = %+v, want only the creation", activity)
	}
	if commands := f.system.Commands(); len(commands) != 0 {
		t.Errorf("ran %v", commands)
	}

	// A real change still goes through.
	again.Branch = "develop"
	if changed, _, err := f.manager.Put(ctx, again, saved.Revision, "Mac"); err != nil || changed.Revision != saved.Revision+1 {
		t.Errorf("changed Put = %+v %v", changed, err)
	}
}

func TestConcurrentDeployKeyCallsShowOneKey(t *testing.T) {
	f := newFixture(t)

	keys := make([]gitsource.DeployKey, 16)
	errs := make([]error, len(keys))
	var wg sync.WaitGroup
	for i := range keys {
		wg.Go(func() {
			if i%2 == 0 {
				keys[i], errs[i] = f.manager.DeployKey(ctx, "abcdefghijkl")
				return
			}

			var credentials gitsource.Credentials
			credentials, errs[i] = f.manager.RepositoryCredentials(ctx, "abcdefghijkl")
			if errs[i] == nil {
				line, err := os.ReadFile(credentials.KeyPath + ".pub")
				keys[i], errs[i] = gitsource.DeployKey{PublicKey: strings.TrimSpace(string(line))}, err
			}
		})
	}
	wg.Wait()

	for i := range keys {
		if errs[i] != nil {
			t.Fatalf("call %d: %v", i, errs[i])
		}
		if keys[i].PublicKey != keys[0].PublicKey {
			t.Fatalf("call %d showed %s, call 0 showed %s", i, keys[i].PublicKey, keys[0].PublicKey)
		}
	}

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	if installed, err := f.manager.DeployKey(ctx, "abcdefghijkl"); err != nil || installed != keys[0] {
		t.Errorf("installed = %+v %v, want %+v", installed, err, keys[0])
	}
}

// PHP may be installed after the agent started, when server setup wrote the helpers for the versions it found.
func TestPutEnsuresThePHPHelpers(t *testing.T) {
	f := newFixture(t)

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	if target, err := os.Readlink(f.file("/usr/local/lib/serverdog/php/8.4/bin/php")); err != nil || target != "/usr/bin/php8.4" {
		t.Errorf("php helper -> %q (%v)", target, err)
	}
	composer, err := os.ReadFile(f.file("/usr/local/lib/serverdog/php/8.4/bin/composer"))
	if err != nil || string(composer) != string(phpfpm.RenderComposer("8.4")) {
		t.Errorf("composer helper = %q (%v)", composer, err)
	}
	if info, err := os.Stat(f.file("/usr/local/lib/serverdog/php/8.4/bin/composer")); err != nil || info.Mode().Perm() != 0o755 {
		t.Errorf("composer helper = %v %v", info, err)
	}
}

// Another site can take a domain between Put's first owner check and the apply lock. The check under the lock must
// refuse before Nginx sees a second server block for the domain.
func TestADomainTakenDuringAPutLeavesNoConfig(t *testing.T) {
	f := newFixture(t)
	rival := laravel()
	rival.ID = "zyxwvutsrqpo"

	raced := false
	f.system.Handle("usermod", func(system.Command) (system.Result, error) {
		if raced {
			return system.Result{}, nil
		}
		raced = true

		if _, _, err := f.manager.Put(ctx, rival, 0, "Mac"); err != nil {
			t.Errorf("rival Put: %v", err)
		}

		return system.Result{}, nil
	})

	_, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	var taken *state.DomainTakenError
	if !errors.As(err, &taken) || taken.Name != "orchard.com" || taken.SiteID != rival.ID {
		t.Fatalf("err = %v, want orchard.com taken by %s", err, rival.ID)
	}

	for _, logical := range []string{
		"/etc/nginx/sites-available/serverdog-abcdefghijkl.conf",
		"/etc/nginx/sites-enabled/serverdog-abcdefghijkl.conf",
		"/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf",
	} {
		if f.exists(logical) {
			t.Errorf("the refused Put left %s", logical)
		}
	}
	if !f.exists("/etc/nginx/sites-enabled/serverdog-zyxwvutsrqpo.conf") {
		t.Error("the rival's config is missing")
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("the refused site was stored: %v", err)
	}
}

func TestDeletingASiteWhosePHPVersionWasUninstalled(t *testing.T) {
	f := newFixture(t)
	f.manager.Put(ctx, laravel(), 0, "Mac")
	f.uninstallPHP("8.4")
	f.system.Reset()

	if err := f.manager.Delete(ctx, "abcdefghijkl", true, "Mac"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if f.exists("/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf") || f.exists("/etc/nginx/sites-enabled/serverdog-abcdefghijkl.conf") {
		t.Error("the pool or the Nginx config is still there")
	}
	for _, command := range f.system.Commands() {
		if strings.Contains(command, "php-fpm8.4") || strings.Contains(command, "php8.4-fpm") {
			t.Errorf("ran %q for the uninstalled version", command)
		}
	}
	if _, err := f.store.GetSite("abcdefghijkl"); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("site still stored: %v", err)
	}
}

func TestMovingASiteOffAnUninstalledPHPVersion(t *testing.T) {
	f := newFixture(t)
	saved, _, _ := f.manager.Put(ctx, laravel(), 0, "Mac")
	f.uninstallPHP("8.4")
	f.system.Reset()

	saved.PHPVersion = "8.3"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if f.exists("/etc/php/8.4/fpm/pool.d/serverdog-abcdefghijkl.conf") || !f.exists("/etc/php/8.3/fpm/pool.d/serverdog-abcdefghijkl.conf") {
		t.Error("pool not moved")
	}
	commands := f.system.Commands()
	for _, want := range []string{"/usr/sbin/php-fpm8.3 -t", "systemctl reload php8.3-fpm"} {
		if !slices.Contains(commands, want) {
			t.Errorf("missing %q in %v", want, commands)
		}
	}
	for _, command := range commands {
		if strings.Contains(command, "php-fpm8.4") || strings.Contains(command, "php8.4-fpm") {
			t.Errorf("ran %q for the uninstalled version", command)
		}
	}
}

// recordPortSyncs makes the manager record, at each port guard sync, which Node ports the store gives to which user.
func (f *fixture) recordPortSyncs() *[]map[int]string {
	var syncs []map[int]string
	f.manager.SyncPorts = func(context.Context) error {
		users, err := f.store.NodePortUsers()
		if err != nil {
			f.t.Fatal(err)
		}
		syncs = append(syncs, users)

		return nil
	}

	return &syncs
}

func TestNodeSitesSyncThePortGuardAfterSavingAndDeleting(t *testing.T) {
	f := newFixture(t)
	syncs := f.recordPortSyncs()

	if _, _, err := f.manager.Put(ctx, nodeSite(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	want := []map[int]string{{20000: "serverdog", 20001: "serverdog"}, {}}
	if !slices.EqualFunc(*syncs, want, maps.Equal) {
		t.Errorf("syncs saw %v, want %v (after the site is saved, then after its ports are released)", *syncs, want)
	}
}

func TestOtherSitesDoNotSyncThePortGuard(t *testing.T) {
	f := newFixture(t)
	syncs := f.recordPortSyncs()

	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	if len(*syncs) != 0 {
		t.Errorf("a PHP site synced the port guard %d times", len(*syncs))
	}
}

func TestDeletingASiteThatHeldAReverbPortSyncsThePortGuard(t *testing.T) {
	f := newFixture(t)

	spec := laravel()
	spec.Domains = append(spec.Domains, site.Domain{Name: "ws.example.com", Redirect: site.NoRedirect, Reverb: true})
	if _, _, err := f.manager.Put(ctx, spec, 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	syncs := f.recordPortSyncs()
	if err := f.manager.Delete(ctx, "abcdefghijkl", false, "Mac"); err != nil {
		t.Fatal(err)
	}

	if len(*syncs) != 1 {
		t.Errorf("deleting the site synced the port guard %d times, want once", len(*syncs))
	}
}

func TestAFailedPortSyncDoesNotFailThePut(t *testing.T) {
	f := newFixture(t)
	f.manager.SyncPorts = func(context.Context) error { return errors.New("the port guard isn't attached") }

	if _, created, err := f.manager.Put(ctx, nodeSite(), 0, "Mac"); err != nil || !created {
		t.Errorf("Put = %v, %v", created, err)
	}
}

func withoutWebsite() site.Site {
	s := laravel()
	s.ID, s.Domains, s.Name, s.WebDirectory = "workerworker", nil, "worker", ""
	s.Scheduler = true
	s.Processes = []site.Process{{ID: "queuequeueqq", Name: "Queue", Command: "php artisan queue:work", Count: 1}}

	return s
}

func TestASiteWithoutAWebsiteNeedsNoNginx(t *testing.T) {
	f := newFixture(t)
	f.manager.Capabilities = func(context.Context) capabilities.Capabilities {
		return capabilities.Capabilities{PHPVersions: []string{"8.4"}}
	}

	saved, _, err := f.manager.Put(ctx, withoutWebsite(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if saved.Directory != "/home/serverdog/worker" {
		t.Errorf("directory = %s", saved.Directory)
	}

	for _, logical := range []string{"/etc/nginx/sites-available/serverdog-workerworker.conf", "/etc/php/8.4/fpm/pool.d/serverdog-workerworker.conf", "/home/serverdog/worker/placeholder"} {
		if f.exists(logical) {
			t.Errorf("%s exists", logical)
		}
	}
	if !f.exists(paths.SchedulerCron("workerworker")) || !f.exists("/home/serverdog/worker/releases") {
		t.Error("the scheduler or the releases are missing")
	}
	for _, command := range f.system.Commands() {
		if strings.Contains(command, "nginx") || strings.Contains(command, "fpm") {
			t.Errorf("ran %q", command)
		}
	}

	if _, _, _, err := f.manager.NginxConfig(ctx, "workerworker"); err == nil {
		t.Error("a site without a website has an Nginx config")
	}

	twin := withoutWebsite()
	twin.ID = "twintwintwin"
	if _, _, err := f.manager.Put(ctx, twin, 0, "Mac"); err == nil || !strings.Contains(err.Error(), "named worker already") {
		t.Errorf("second site named worker: %v", err)
	}

	f.system.Reset()
	if err := f.manager.Delete(ctx, "workerworker", true, "Mac"); err != nil {
		t.Fatal(err)
	}
	if f.exists("/home/serverdog/worker") || f.exists(paths.SchedulerCron("workerworker")) {
		t.Error("the site's files are left")
	}
	for _, command := range f.system.Commands() {
		if strings.Contains(command, "nginx") {
			t.Errorf("delete ran %q", command)
		}
	}
}

func TestPasswordsAreHashedAndKept(t *testing.T) {
	spec := site.Site{BasicAuth: &site.BasicAuth{Username: "client", Password: "secret"}}
	if err := hashPassword(&spec); err != nil {
		t.Fatal(err)
	}
	if spec.BasicAuth.Password != "" || bcrypt.CompareHashAndPassword([]byte(spec.BasicAuth.Hash), []byte("secret")) != nil {
		t.Fatalf("basic auth = %+v; want only a hash of the password", spec.BasicAuth)
	}

	change := site.Site{BasicAuth: &site.BasicAuth{Username: "client"}}
	keepPassword(&change, spec)
	if err := hashPassword(&change); err != nil || change.BasicAuth.Hash != spec.BasicAuth.Hash {
		t.Errorf("a change without a password: hash kept = %v, %v", change.BasicAuth.Hash == spec.BasicAuth.Hash, err)
	}

	unprotected := site.Site{BasicAuth: &site.BasicAuth{Username: "client"}}
	keepPassword(&unprotected, site.Site{})
	var invalid *site.InvalidError
	if err := hashPassword(&unprotected); !errors.As(err, &invalid) {
		t.Errorf("protecting without a password: err = %v; want an invalid site", err)
	}
}

// Octane takes over at a deploy, never at a save: a site with Octane just turned on keeps answering from PHP-FPM, and
// one whose app has no laravel/octane simply fails that deploy.
func TestOctaneIsPreparedOnSaveAndServedAfterItsDeploy(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	config := f.file("/etc/nginx/sites-available/serverdog-abcdefghijkl.conf")
	// A site with a live release, past its placeholder page.
	if err := os.RemoveAll(f.file("/home/serverdog/orchard.com/placeholder")); err != nil {
		t.Fatal(err)
	}

	saved.Octane = true
	saved, _, err = f.manager.Put(ctx, saved, saved.Revision, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if saved.OctanePort != 0 {
		t.Errorf("Octane is live before any deploy: port %d", saved.OctanePort)
	}

	start, _ := os.ReadFile(f.file("/etc/serverdog/sites/abcdefghijkl/start.sh"))
	for _, want := range []string{`cd "${SERVERDOG_RELEASE_DIRECTORY:?}"/''`, "bind 127.0.0.1", "admin off", `--port="${PORT:?}"`, "--caddyfile=bootstrap/cache/octane.Caddyfile", "exec /usr/bin/php8.4 artisan octane:start --server=frankenphp"} {
		if !strings.Contains(string(start), want) {
			t.Errorf("start.sh lacks %q:\n%s", want, start)
		}
	}
	if !f.exists("/etc/systemd/system/serverdog-site-abcdefghijkl@.service") || !f.exists("/etc/nginx/serverdog/upstreams/abcdefghijkl.conf") {
		t.Error("the Octane server's unit or upstream wasn't written")
	}
	if nginx, _ := os.ReadFile(config); !strings.Contains(string(nginx), "fastcgi_pass") || strings.Contains(string(nginx), "@octane") {
		t.Errorf("Nginx left PHP-FPM before an Octane server was up:\n%s", nginx)
	}

	// What the deploy records once the release's Octane answers on a port.
	if err := f.store.SetLivePort("abcdefghijkl", 20001); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateSite("abcdefghijkl", func(s *site.Site) { s.OctanePort = 20001 }, time.Now()); err != nil {
		t.Fatal(err)
	}
	live, _ := f.store.GetSite("abcdefghijkl")

	// A later save keeps sending requests to Octane, and keeps the port the deploy recorded.
	live.ForceHTTPS = true
	live, _, err = f.manager.Put(ctx, live, live.Revision, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if nginx, _ := os.ReadFile(config); live.OctanePort != 20001 || !strings.Contains(string(nginx), "proxy_pass http://serverdog_abcdefghijkl;") || strings.Contains(string(nginx), "fastcgi_pass") {
		t.Errorf("port %d, Nginx:\n%s", live.OctanePort, nginx)
	}
	if start, _ := os.ReadFile(f.file("/etc/serverdog/sites/abcdefghijkl/start.sh")); !strings.Contains(string(start), "export OCTANE_HTTPS=true") {
		t.Errorf("a site that forces HTTPS doesn't tell Octane:\n%s", start)
	}

	// Off: PHP-FPM serves again in the same change, then the Octane servers and their unit go.
	live.Octane = false
	off, _, err := f.manager.Put(ctx, live, live.Revision, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if nginx, _ := os.ReadFile(config); off.OctanePort != 0 || !strings.Contains(string(nginx), "fastcgi_pass") || strings.Contains(string(nginx), "upstreams") {
		t.Errorf("port %d, Nginx:\n%s", off.OctanePort, nginx)
	}
	if f.exists("/etc/systemd/system/serverdog-site-abcdefghijkl@.service") || f.exists("/etc/nginx/serverdog/upstreams/abcdefghijkl.conf") {
		t.Error("the Octane server's unit or upstream is still there")
	}
	if port, _ := f.store.LivePort("abcdefghijkl"); port != 0 {
		t.Errorf("live port is still %d", port)
	}
	for _, want := range []string{"systemctl disable --now serverdog-site-abcdefghijkl@20000.service", "systemctl disable --now serverdog-site-abcdefghijkl@20001.service"} {
		if !slices.Contains(f.system.Commands(), want) {
			t.Errorf("didn't run %q: %v", want, f.system.Commands())
		}
	}
}

func TestACustomisedNginxConfigRefusesWhatItCantFollow(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.UpdateSite(saved.ID, func(s *site.Site) { s.NginxCustomised = true }, time.Now()); err != nil {
		t.Fatal(err)
	}
	saved, _ = f.store.GetSite(saved.ID)

	var invalid *site.InvalidError

	octane := saved
	octane.Octane = true
	if _, _, err := f.manager.Put(ctx, octane, saved.Revision, "Mac"); !errors.As(err, &invalid) || invalid.Field != "nginx" {
		t.Errorf("turning Octane on: %v", err)
	}

	reverb := saved
	reverb.Domains = append(slices.Clone(saved.Domains), site.Domain{Name: "ws.example.com", Redirect: site.NoRedirect, Reverb: true})
	if _, _, err := f.manager.Put(ctx, reverb, saved.Revision, "Mac"); !errors.As(err, &invalid) || invalid.Field != "nginx" {
		t.Errorf("adding a Reverb domain: %v", err)
	}

	// Anything else still saves.
	saved.Branch = "develop"
	if _, _, err := f.manager.Put(ctx, saved, saved.Revision, "Mac"); err != nil {
		t.Errorf("changing the branch: %v", err)
	}
}

// A Node deploy checks the guard itself before it starts anything; Reverb is started by the save, so the save is
// where a missing guard must stop it: without the guard any local user could take the port and receive the domain's
// traffic.
func TestReverbIsRefusedWithoutThePortGuard(t *testing.T) {
	f := newFixture(t)
	saved, _, err := f.manager.Put(ctx, laravel(), 0, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	f.manager.SyncPorts = func(context.Context) error { return errors.New("the port guard isn't attached") }

	reverb := saved
	reverb.Domains = append(slices.Clone(saved.Domains), site.Domain{Name: "ws.example.com", Redirect: site.NoRedirect, Reverb: true})

	var invalid *site.InvalidError
	if _, _, err := f.manager.Put(ctx, reverb, saved.Revision, "Mac"); !errors.As(err, &invalid) || !strings.Contains(invalid.Reason, "port guard isn't active") {
		t.Fatalf("Put = %v", err)
	}

	// Nothing was reserved or written for it.
	stored, _ := f.store.GetSite(saved.ID)
	if _, serves := stored.ReverbDomain(); serves || stored.ReverbPort != 0 {
		t.Errorf("the site was saved with Reverb: %+v", stored.Domains)
	}
	if users, _ := f.store.NodePortUsers(); len(users) != 0 {
		t.Errorf("a port was reserved: %v", users)
	}
	if nginx, _ := os.ReadFile(f.file("/etc/nginx/sites-available/serverdog-abcdefghijkl.conf")); strings.Contains(string(nginx), "ws.example.com") {
		t.Errorf("Nginx got the Reverb domain:\n%s", nginx)
	}

	// With the guard back, the same save goes through.
	f.manager.SyncPorts = func(context.Context) error { return nil }
	if with, _, err := f.manager.Put(ctx, reverb, saved.Revision, "Mac"); err != nil || with.ReverbPort == 0 {
		t.Fatalf("Put with the guard = port %d, %v", with.ReverbPort, err)
	}
}
