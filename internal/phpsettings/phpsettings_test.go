package phpsettings

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

// newManager makes a server with PHP 8.4 and Nginx installed.
func newManager(t *testing.T) (*Manager, *systemtest.Fake, string) {
	t.Helper()

	root := t.TempDir()
	for _, file := range []string{"usr/sbin/php-fpm8.4", "lib/systemd/system/php8.4-fpm.service"} {
		os.MkdirAll(filepath.Join(root, filepath.Dir(file)), 0o755)
		os.WriteFile(filepath.Join(root, file), nil, 0o755)
	}
	os.MkdirAll(filepath.Join(root, "etc/nginx/conf.d"), 0o755)

	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	fake := &systemtest.Fake{}

	return &Manager{Store: store, Paths: paths.Paths{Root: root}, Applier: apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")}}, fake, root
}

func TestSettingsReachEveryVersionAndNginx(t *testing.T) {
	m, fake, root := newManager(t)

	settings := Settings{UploadMB: 200, MaxExecutionSeconds: 120, MemoryMB: 512, OPcacheFrozen: true}
	revision, err := m.Put(context.Background(), settings, 0)
	if err != nil || revision != 1 {
		t.Fatalf("Put = %d, %v", revision, err)
	}

	fpm, _ := os.ReadFile(filepath.Join(root, FPMIni("8.4")))
	for _, want := range []string{"upload_max_filesize = 200M\n", "post_max_size = 200M\n", "max_execution_time = 120\n", "memory_limit = 512M\n", "opcache.validate_timestamps = 0\n"} {
		if !strings.Contains(string(fpm), want) {
			t.Errorf("FPM ini lacks %q:\n%s", want, fpm)
		}
	}

	cli, _ := os.ReadFile(filepath.Join(root, CLIIni("8.4")))
	if !strings.Contains(string(cli), "memory_limit = 512M\n") || strings.Contains(string(cli), "max_execution_time") {
		t.Errorf("CLI ini =\n%s", cli)
	}

	conf, _ := os.ReadFile(filepath.Join(root, NginxConf))
	if !strings.Contains(string(conf), "client_max_body_size 200m;\n") || !strings.Contains(string(conf), "fastcgi_read_timeout 125s;\n") {
		t.Errorf("Nginx conf =\n%s", conf)
	}

	if commands := fake.Commands(); !slices.Contains(commands, "systemctl reload php8.4-fpm") || !slices.Contains(commands, "nginx -t") {
		t.Errorf("commands = %q", commands)
	}

	got, listed, err := m.Get()
	if err != nil || listed != 1 || got != settings || !m.OPcacheFrozen() {
		t.Errorf("Get = %v, %d, %v", got, listed, err)
	}
}

func TestDefaultsBeforeTheFirstSave(t *testing.T) {
	m, _, root := newManager(t)

	got, revision, err := m.Get()
	if err != nil || revision != 0 || got != Defaults || m.OPcacheFrozen() {
		t.Errorf("Get = %v, %d, %v", got, revision, err)
	}

	// A version installed before anything was saved keeps PHP's own settings.
	if err := m.ApplyVersion(context.Background(), "8.4"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, FPMIni("8.4"))); !os.IsNotExist(err) {
		t.Errorf("an ini was written before any save: %v", err)
	}
}

func TestNewVersionGetsTheSavedSettings(t *testing.T) {
	m, _, root := newManager(t)
	ctx := context.Background()

	if _, err := m.Put(ctx, Settings{UploadMB: 10, MaxExecutionSeconds: 30, MemoryMB: 256}, 0); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(root, FPMIni("8.4")))

	if err := m.ApplyVersion(ctx, "8.4"); err != nil {
		t.Fatal(err)
	}
	if fpm, _ := os.ReadFile(filepath.Join(root, FPMIni("8.4"))); !strings.Contains(string(fpm), "memory_limit = 256M") {
		t.Errorf("FPM ini =\n%s", fpm)
	}
}

func TestOutOfRangeAndStaleAreRefused(t *testing.T) {
	m, _, _ := newManager(t)
	ctx := context.Background()

	for _, s := range []Settings{{UploadMB: 0, MaxExecutionSeconds: 30, MemoryMB: 128}, {UploadMB: 64, MaxExecutionSeconds: 0, MemoryMB: 128}, {UploadMB: 64, MaxExecutionSeconds: 30, MemoryMB: 16}} {
		if _, err := m.Put(ctx, s, 0); err == nil {
			t.Errorf("%v was accepted", s)
		}
	}

	if _, err := m.Put(ctx, Defaults, 3); !errors.Is(err, state.ErrStaleDocument) {
		t.Errorf("Put = %v, want a stale document", err)
	}
}
