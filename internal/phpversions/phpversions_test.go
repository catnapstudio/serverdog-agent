package phpversions

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T, versions ...string) (*Manager, *systemtest.Fake, string) {
	t.Helper()
	root := t.TempDir()

	for _, version := range versions {
		file := root + "/etc/php/" + version + "/fpm/php-fpm.conf"
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(root+"/usr/bin", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(root+"/usr/bin/php"+version, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(root+"/etc/alternatives", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root+"/usr/bin/php"+versions[0], root+"/etc/alternatives/php"); err != nil {
		t.Fatal(err)
	}

	fake := &systemtest.Fake{}
	sites := []site.Site{{Domains: []site.Domain{{Name: "shop.test", Primary: true}}, PHPVersion: "8.3"}}

	return &Manager{Paths: paths.Paths{Root: root}, System: fake, Sites: func() ([]site.Site, error) { return sites, nil }}, fake, root
}

func TestStatus(t *testing.T) {
	m, fake, _ := newManager(t, "8.4", "8.3")
	fake.Handle("apt-cache", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte("Package: php8.4-fpm\nVersion: 1\n\nPackage: php8.5-fpm\n\nPackage: php8.2-fpm\n")}, &system.ExitError{ExitCode: 100}
	})

	status, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(status.Installed, ",") != "8.4,8.3" || strings.Join(status.Available, ",") != "8.5,8.2" || status.CLI != "8.4" || strings.Join(status.UsedBy["8.3"], ",") != "shop.test" {
		t.Errorf("status = %+v", status)
	}
}

func TestInstallUsesTheArchivesRedisPackageWhenThereIsOne(t *testing.T) {
	m, fake, root := newManager(t, "8.4")
	if err := os.MkdirAll(root+"/etc/apt/sources.list.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(root+suryList, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.Install(context.Background(), "8.2"); err != nil {
		t.Fatal(err)
	}

	commands := strings.Join(fake.Commands(), "\n")
	if !strings.Contains(commands, "install php8.2-fpm php8.2-cli") || !strings.Contains(commands, "php8.2-redis") || !strings.HasSuffix(commands, "systemctl enable --now php8.2-fpm") {
		t.Errorf("ran:\n%s", commands)
	}

	if err := m.Install(context.Background(), "9.9; reboot"); err == nil {
		t.Error("an unknown version was installed")
	}
}

func TestRemoveRefusesAVersionInUse(t *testing.T) {
	m, fake, _ := newManager(t, "8.4", "8.3", "8.2")
	fake.Handle("dpkg-query", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte("php8.2-cli\nphp8.2-fpm\n")}, nil
	})
	ctx := context.Background()

	for _, version := range []string{"8.3", "8.4"} {
		if err := m.Remove(ctx, version); err == nil {
			t.Errorf("PHP %s was removed", version)
		}
	}

	if err := m.Remove(ctx, "8.2"); err != nil {
		t.Fatal(err)
	}
	if last := fake.Commands()[len(fake.Commands())-1]; !strings.HasSuffix(last, "purge php8.2-cli php8.2-fpm") {
		t.Errorf("last = %s", last)
	}
}
