package serversetup

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func setup(t *testing.T, caps capabilities.Capabilities) (string, *systemtest.Fake, Setup) {
	root := t.TempDir()
	fake := &systemtest.Fake{}

	return root, fake, Setup{
		Paths:        paths.Paths{Root: root},
		Applier:      apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")},
		Capabilities: caps,
	}
}

func TestEnsureCreatesDirectoriesSnippetsAndHelpers(t *testing.T) {
	root, fake, s := setup(t, capabilities.Capabilities{PHPVersions: []string{"8.4"}, NginxVersion: "1.24.0"})

	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	modes := map[string]os.FileMode{
		"/var/lib/serverdog/deploys":                         0o700,
		"/var/lib/serverdog/keys":                            0o700,
		"/var/lib/serverdog-acme/.well-known/acme-challenge": 0o755,
		"/etc/serverdog/sites":                               0o755,
		"/etc/serverdog/certs":                               0o700,
		"/var/lib/serverdog/acme-account":                    0o700,
	}
	for logical, mode := range modes {
		info, err := os.Stat(filepath.Join(root, logical))
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", logical, info, err)
		}
	}

	for logical, want := range map[string]string{
		"/etc/serverdog/known_hosts":                    "github.com ssh-ed25519",
		"/etc/nginx/serverdog/acme.conf":                "root /var/lib/serverdog-acme;",
		"/etc/nginx/serverdog/tls.conf":                 "ssl_protocols TLSv1.2 TLSv1.3;",
		"/etc/nginx/conf.d/serverdog-http.conf":         "map $http_upgrade $serverdog_connection_upgrade",
		"/etc/nginx/sites-available/000-catch-all":      "ssl_reject_handshake on;",
		"/usr/local/lib/serverdog/php/8.4/bin/composer": "exec /usr/bin/php8.4 /usr/local/bin/composer",
	} {
		content, err := os.ReadFile(filepath.Join(root, logical))
		if err != nil || !strings.Contains(string(content), want) {
			t.Errorf("%s lacks %q (%v)", logical, want, err)
		}
	}

	if target, _ := os.Readlink(filepath.Join(root, "/usr/local/lib/serverdog/php/8.4/bin/php")); target != "/usr/bin/php8.4" {
		t.Errorf("php helper -> %q", target)
	}

	want := []string{"nginx -t", "/usr/local/bin/serverdog-agent reload-nginx", "systemctl daemon-reload", "systemctl enable serverdog-port-guard.service"}
	if !slices.Equal(fake.Commands(), want) {
		t.Errorf("commands = %v", fake.Commands())
	}

	fake.Reset()
	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.Calls()) != 0 {
		t.Errorf("second Ensure ran %v", fake.Commands())
	}
}

func TestEnsureWithoutNginxSkipsNginxFiles(t *testing.T) {
	root, fake, s := setup(t, capabilities.Capabilities{})

	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nginx")); !os.IsNotExist(err) {
		t.Error("wrote Nginx files on a server without Nginx")
	}
	if !slices.Equal(fake.Commands(), []string{"systemctl daemon-reload", "systemctl enable serverdog-port-guard.service"}) {
		t.Errorf("commands = %v, want only the port guard unit's", fake.Commands())
	}
}

func TestCatchAllMatchesTheSitesHTTP2Listen(t *testing.T) {
	for version, want := range map[string]string{
		"1.24.0": "listen 443 ssl http2 default_server;",
		"1.28.3": "listen 443 ssl default_server;",
	} {
		root, _, s := setup(t, capabilities.Capabilities{NginxVersion: version})
		if err := s.Ensure(context.Background()); err != nil {
			t.Fatal(err)
		}

		content, _ := os.ReadFile(filepath.Join(root, "/etc/nginx/sites-available/000-catch-all"))
		if !strings.Contains(string(content), want) || !strings.Contains(string(content), "ssl_reject_handshake on;") {
			t.Errorf("%s:\n%s", version, content)
		}
	}
}

func TestEnsureInstallsThePortGuardBootUnit(t *testing.T) {
	root, _, s := setup(t, capabilities.Capabilities{})

	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	unit, err := os.ReadFile(filepath.Join(root, "/etc/systemd/system/serverdog-port-guard.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DefaultDependencies=no", "Before=sysinit.target", "ExecStart=/usr/local/bin/serverdog-agent port-guard", "WantedBy=sysinit.target"} {
		if !strings.Contains(string(unit), want) {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}

	reference, err := os.ReadFile("../../deploy/serverdog-port-guard.service")
	if err != nil || string(reference) != PortGuardUnit {
		t.Errorf("deploy/serverdog-port-guard.service differs from PortGuardUnit (%v)", err)
	}
}

func TestEnsureInstallsThePortGuardBootUnitWhenTheNginxSetupFails(t *testing.T) {
	root, fake, s := setup(t, capabilities.Capabilities{NginxVersion: "1.24.0"})
	fake.Fail("nginx", 1, "nginx: [emerg] unknown directive \"proxy_pas\"")

	err := s.Ensure(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown directive") {
		t.Errorf("Ensure = %v, want the nginx -t failure", err)
	}

	if _, err := os.Stat(filepath.Join(root, "/etc/systemd/system/serverdog-port-guard.service")); err != nil {
		t.Errorf("the boot unit wasn't installed: %v", err)
	}
	if want := []string{"nginx -t", "systemctl daemon-reload", "systemctl enable serverdog-port-guard.service"}; !slices.Equal(fake.Commands(), want) {
		t.Errorf("commands = %v, want %v", fake.Commands(), want)
	}
}

func TestEnsureLocksEachPackagedPHPPoolAndDropsTheLockOnceThePoolIsGone(t *testing.T) {
	root, fake, s := setup(t, capabilities.Capabilities{PHPVersions: []string{"8.4", "8.5"}})

	stock := filepath.Join(root, "/etc/php/8.4/fpm/pool.d/www.conf")
	if err := os.MkdirAll(filepath.Dir(stock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stock, []byte("[www]\n;listen = 127.0.0.1:9000\nlisten = /run/php/php8.4-fpm.sock\nlisten.owner = www-data\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}

	lock := filepath.Join(root, "/etc/php/8.4/fpm/pool.d/zz-serverdog-www.conf")
	if content, err := os.ReadFile(lock); err != nil || !strings.Contains(string(content), "[www]\nlisten.mode = 0600") {
		t.Errorf("lock = %q, %v", content, err)
	}

	// 8.5 has no packaged pool, so it gets no lock: a lock alone is a pool PHP-FPM can't load.
	if _, err := os.Stat(filepath.Join(root, "/etc/php/8.5/fpm/pool.d/zz-serverdog-www.conf")); !os.IsNotExist(err) {
		t.Errorf("8.5 was locked without a packaged pool: %v", err)
	}

	if commands := fake.Commands(); !slices.Contains(commands, "/usr/sbin/php-fpm8.4 -t") || !slices.Contains(commands, "systemctl reload php8.4-fpm") || !slices.Contains(commands, "chmod 0600 /run/php/php8.4-fpm.sock") || slices.Contains(commands, "systemctl reload php8.5-fpm") {
		t.Errorf("commands = %v", commands)
	}

	if err := os.Remove(stock); err != nil {
		t.Fatal(err)
	}
	if err := s.Ensure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("the lock outlived the packaged pool: %v", err)
	}
}
