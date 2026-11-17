package serversettings

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func setup(t *testing.T) (*Manager, *systemtest.Fake, string) {
	root := t.TempDir()
	for _, dir := range []string{"usr/share/zoneinfo/Europe", "etc/redis"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"usr/share/zoneinfo/Europe/Paris": "TZif",
		"usr/share/zoneinfo/UTC":          "TZif",
		"etc/redis/redis.conf":            "bind 127.0.0.1\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/usr/share/zoneinfo/Europe/Paris", filepath.Join(root, "etc/localtime")); err != nil {
		t.Fatal(err)
	}

	fake := &systemtest.Fake{}
	return &Manager{Paths: paths.Paths{Root: root}, Runner: fake}, fake, root
}

func TestTimezone(t *testing.T) {
	m, fake, _ := setup(t)

	if zone := m.Timezone(); zone != "Europe/Paris" {
		t.Errorf("zone = %q", zone)
	}

	var invalid *site.InvalidError
	if err := m.SetTimezone(context.Background(), "Mars/Olympus"); !errors.As(err, &invalid) {
		t.Errorf("unknown zone: err = %v", err)
	}
	if err := m.SetTimezone(context.Background(), "../etc/passwd"); !errors.As(err, &invalid) {
		t.Errorf("path: err = %v", err)
	}
	if err := m.SetTimezone(context.Background(), "UTC"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(fake.Commands(), "\n"); !strings.Contains(got, "timedatectl set-timezone UTC") || !strings.Contains(got, "systemctl try-restart cron") {
		t.Errorf("commands:\n%s", got)
	}
}

func TestRedisPasswordIsIncludedAndRemoved(t *testing.T) {
	m, fake, root := setup(t)
	ctx := context.Background()

	if err := m.SetRedisPassword(ctx, "short"); err == nil {
		t.Error("a short password was accepted")
	}
	if err := m.SetRedisPassword(ctx, "abcdefghijklmnop1234"); err != nil {
		t.Fatal(err)
	}
	if err := m.SetRedisPassword(ctx, "abcdefghijklmnop5678"); err != nil {
		t.Fatal(err)
	}

	config, _ := os.ReadFile(filepath.Join(root, "etc/redis/redis.conf"))
	if strings.Count(string(config), "include "+RedisAuth) != 1 {
		t.Errorf("redis.conf:\n%s", config)
	}
	if password, _ := m.RedisPassword(); password != "abcdefghijklmnop5678" {
		t.Errorf("password = %q", password)
	}

	if err := m.SetRedisPassword(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if password, _ := m.RedisPassword(); password != "" {
		t.Errorf("password after removing = %q", password)
	}
	if !strings.Contains(strings.Join(fake.Commands(), "\n"), "systemctl restart redis-server") {
		t.Error("Redis wasn't restarted")
	}
}

func TestAFailedRestartRestoresThePassword(t *testing.T) {
	m, fake, _ := setup(t)
	ctx := context.Background()
	if err := m.SetRedisPassword(ctx, "abcdefghijklmnop1234"); err != nil {
		t.Fatal(err)
	}

	fake.Fail("systemctl", 1, "failed")
	if err := m.SetRedisPassword(ctx, "zzzzzzzzzzzzzzzz9999"); err == nil {
		t.Fatal("a failed restart was reported as success")
	}
	if password, _ := m.RedisPassword(); password != "abcdefghijklmnop1234" {
		t.Errorf("password = %q; want the previous one", password)
	}
}
