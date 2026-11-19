package updates

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T) (*Manager, *systemtest.Fake) {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	for _, dir := range []string{"/etc/apt/apt.conf.d", "/var/run", "/var/lib/apt/periodic"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	fake := &systemtest.Fake{}
	p := paths.Paths{Root: root}

	return &Manager{Store: store, Paths: p, Runner: fake, Applier: apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")}}, fake
}

func TestRenderAddsTheVendorArchivesAndTheRestart(t *testing.T) {
	conf := string(Render(Settings{Databases: false, AutomaticReboot: true, RebootTime: "03:30"}))

	for _, want := range []string{`"site=packages.sury.org";`, `"site=deb.nodesource.com";`, `Automatic-Reboot "true";`, `Automatic-Reboot-Time "03:30";`} {
		if !strings.Contains(conf, want) {
			t.Errorf("missing %s in\n%s", want, conf)
		}
	}
	if strings.Contains(conf, "mariadb") {
		t.Errorf("databases are off, but\n%s", conf)
	}
	if !strings.Contains(string(Render(Defaults)), `"site=dlm.mariadb.com";`) {
		t.Error("the defaults leave out the database archives")
	}
}

func TestPutWritesTheFileAndApplyKeepsIt(t *testing.T) {
	m, fake := newManager(t)
	ctx := context.Background()

	if err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(m.Paths.File(ConfFile))
	if string(written) != string(Render(Defaults)) {
		t.Fatalf("Apply wrote\n%s", written)
	}

	if _, err := m.Put(ctx, Settings{RebootTime: "4am"}, 0); err == nil {
		t.Fatal("a bad time was accepted")
	}

	revision, err := m.Put(ctx, Settings{AutomaticReboot: true, RebootTime: "05:00"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Put(ctx, Settings{RebootTime: "05:00"}, 0); err == nil {
		t.Fatal("a stale revision was accepted")
	}

	settings, got, _ := m.Get()
	if got != revision || !settings.AutomaticReboot || settings.Databases {
		t.Fatalf("got %+v at %d", settings, got)
	}
	written, _ = os.ReadFile(m.Paths.File(ConfFile))
	if !strings.Contains(string(written), `Automatic-Reboot-Time "05:00";`) {
		t.Fatalf("Put wrote\n%s", written)
	}

	checks := 0
	for _, call := range fake.Calls() {
		if call.Name == "apt-config" {
			checks++
		}
	}
	if checks != 2 {
		t.Fatalf("apt-config checked %d times, want once per change", checks)
	}
}

func TestStatusCountsPendingUpdatesAndTheRestart(t *testing.T) {
	m, fake := newManager(t)
	fake.Handle("apt-get", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte("Reading package lists...\n" +
			"Inst libc6 [2.39-0ubuntu8.3] (2.39-0ubuntu8.4 Ubuntu:24.04/noble-security [arm64])\n" +
			"Inst php8.4-fpm [8.4.1-1] (8.4.2-1 deb.sury.org:noble [arm64])\n" +
			"Conf libc6 (2.39-0ubuntu8.4 Ubuntu:24.04/noble-security [arm64])\n")}, nil
	})
	os.WriteFile(m.Paths.File(rebootFile), []byte("*** System restart required ***\n"), 0o644)
	os.WriteFile(m.Paths.File(rebootPkgsFile), []byte("linux-base\nlibc6\nlinux-base\n"), 0o644)

	s, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if s.Pending != 2 || s.SecurityPending != 1 || s.RebootRequiredSince.IsZero() || strings.Join(s.RebootPackages, ",") != "linux-base,libc6" || !s.LastRun.IsZero() {
		t.Fatalf("got %+v", s)
	}
}

func TestRebootWatcherPostsOncePerPendingRestart(t *testing.T) {
	m, _ := newManager(t)
	flag := m.Paths.File(rebootFile)
	os.WriteFile(flag, nil, 0o644)
	since := time.Date(2026, 11, 10, 6, 0, 0, 0, time.UTC)
	os.Chtimes(flag, since, since)

	now := since.Add(2 * 24 * time.Hour)
	var posts []string
	check := func() {
		w := &RebootWatcher{Updates: m, Host: func() string { return "web-1" }, Now: func() time.Time { return now }, Logger: slog.New(slog.DiscardHandler),
			Post: func(_ context.Context, text string) error { posts = append(posts, text); return nil }}
		w.Check(context.Background())
	}

	check()
	if len(posts) != 0 {
		t.Fatalf("posted before the wait: %q", posts)
	}

	now = since.Add(4 * 24 * time.Hour)
	check()
	check()
	if len(posts) != 1 || !strings.Contains(posts[0], "web-1 have waited for a restart since 10 Nov") {
		t.Fatalf("posted %q", posts)
	}

	// A later update asks for a restart again.
	later := since.Add(10 * 24 * time.Hour)
	os.Chtimes(flag, later, later)
	now = later.Add(4 * 24 * time.Hour)
	check()
	if len(posts) != 2 {
		t.Fatalf("posted %q", posts)
	}
}

func TestApplyAddsUbuntusSecurityArchiveNextToAMirror(t *testing.T) {
	m, fake := newManager(t)
	ctx := context.Background()
	write := func(path, content string) {
		t.Helper()
		full := m.Paths.File(path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("/etc/os-release", "ID=ubuntu\nVERSION_CODENAME=resolute\n")
	write("/etc/apt/sources.list.d/ubuntu.sources", "URIs: https://mirror.hetzner.com/ubuntu/security\nSuites: resolute-security\n")

	if err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	written, _ := os.ReadFile(m.Paths.File(SecuritySourcesFile))
	if !strings.Contains(string(written), "Suites: resolute-security") || !strings.Contains(string(written), "ubuntu.com") {
		t.Fatalf("wrote\n%s", written)
	}
	if !slices.ContainsFunc(fake.Calls(), func(c system.Command) bool { return c.Name == "apt-cache" }) {
		t.Error("the new source wasn't checked")
	}

	// Once the image itself uses Ubuntu's archive, ours would only duplicate it.
	write("/etc/apt/sources.list.d/ubuntu.sources", "URIs: http://security.ubuntu.com/ubuntu http://ports.ubuntu.com/ubuntu-ports\n")
	if err := m.Apply(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.Paths.File(SecuritySourcesFile)); !os.IsNotExist(err) {
		t.Errorf("the duplicate source stayed: %v", err)
	}
}

func TestSecuritySourcesPicksTheArchiveForTheArchitecture(t *testing.T) {
	if got := string(SecuritySources("noble", "amd64")); !strings.Contains(got, "URIs: http://security.ubuntu.com/ubuntu\n") {
		t.Errorf("amd64:\n%s", got)
	}
	if got := string(SecuritySources("noble", "arm64")); !strings.Contains(got, "URIs: http://ports.ubuntu.com/ubuntu-ports\n") {
		t.Errorf("arm64:\n%s", got)
	}
}
