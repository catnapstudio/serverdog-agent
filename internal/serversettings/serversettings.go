// Package serversettings reads and changes server-wide settings: the timezone and Redis's password.
package serversettings

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const (
	zoneinfo    = "/usr/share/zoneinfo/"
	localtime   = "/etc/localtime"
	redisConfig = "/etc/redis/redis.conf"
	// RedisAuth holds requirepass, included from redis.conf like private networking's file.
	RedisAuth = "/etc/redis/serverdog-auth.conf"
)

var (
	zoneName      = regexp.MustCompile(`^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+){0,2}$`)
	redisPassword = regexp.MustCompile(`^[A-Za-z0-9]{16,128}$`)
)

type Manager struct {
	Paths  paths.Paths
	Runner system.Runner

	mu sync.Mutex
}

// Timezone is the server's IANA zone, read from /etc/localtime's link; UTC when it isn't one.
func (m *Manager) Timezone() string {
	target, err := os.Readlink(m.Paths.File(localtime))
	if err != nil {
		return "UTC"
	}

	_, zone, found := strings.Cut(target, zoneinfo)
	if !found || !zoneName.MatchString(zone) {
		return "UTC"
	}

	return zone
}

// SetTimezone changes the system zone and restarts cron, which reads it once at start: scheduled jobs follow it.
func (m *Manager) SetTimezone(ctx context.Context, zone string) error {
	if !zoneName.MatchString(zone) {
		return &site.InvalidError{Field: "timezone", Reason: "Pick a timezone like Europe/Paris."}
	}
	if info, err := os.Stat(m.Paths.File(zoneinfo + zone)); err != nil || info.IsDir() {
		return &site.InvalidError{Field: "timezone", Reason: fmt.Sprintf("This server doesn't know the timezone %s.", zone)}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.Runner.Run(ctx, system.Command{Name: "timedatectl", Args: []string{"set-timezone", zone}}); err != nil {
		return err
	}

	_, err := m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"try-restart", "cron"}})

	return err
}

// RedisInstalled tells whether the server has Redis's config to change.
func (m *Manager) RedisInstalled() bool {
	_, err := os.Stat(m.Paths.File(redisConfig))
	return err == nil
}

// RedisPassword is the password clients must send, or "" when Redis takes any local client.
func (m *Manager) RedisPassword() (string, error) {
	content, err := os.ReadFile(m.Paths.File(RedisAuth))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(content), "\n") {
		if value, found := strings.CutPrefix(strings.TrimSpace(line), "requirepass "); found {
			return strings.Trim(value, `"`), nil
		}
	}

	return "", nil
}

// SetRedisPassword makes Redis require password, or no password when it is "", and restarts it. If Redis doesn't come
// back, the previous files are restored and it restarts with them.
func (m *Manager) SetRedisPassword(ctx context.Context, password string) error {
	if password != "" && !redisPassword.MatchString(password) {
		return &site.InvalidError{Field: "password", Reason: "The password must be 16 to 128 letters and digits."}
	}
	if !m.RedisInstalled() {
		return &site.InvalidError{Field: "redis", Reason: "This server has no Redis."}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	configPath, authPath := m.Paths.File(redisConfig), m.Paths.File(RedisAuth)
	config, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	previousAuth, authErr := os.ReadFile(authPath)
	hadAuth := authErr == nil

	include := "include " + RedisAuth
	if !strings.Contains("\n"+string(config), "\n"+include+"\n") {
		// Written in place, so redis.conf keeps its owner and mode.
		if err := os.WriteFile(configPath, []byte(strings.TrimRight(string(config), "\n")+"\n"+include+"\n"), 0o640); err != nil {
			return err
		}
	}

	content := "# Managed by ServerDog: the password Redis clients send.\n"
	if password != "" {
		content += "requirepass " + password + "\n"
	}
	if err := m.writeAuth(ctx, authPath, []byte(content)); err != nil {
		return err
	}

	if _, err := m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"restart", "redis-server"}}); err != nil {
		restore := context.WithoutCancel(ctx)
		if hadAuth {
			_ = m.writeAuth(restore, authPath, previousAuth)
		} else {
			_ = os.Remove(authPath)
		}
		_ = os.WriteFile(configPath, config, 0o640)
		_, _ = m.Runner.Run(restore, system.Command{Name: "systemctl", Args: []string{"restart", "redis-server"}})

		return fmt.Errorf("Redis didn't restart with the new password, so the previous one is back: %w", err)
	}

	return nil
}

// writeAuth leaves the file readable by Redis only: it holds the password.
func (m *Manager) writeAuth(ctx context.Context, path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, content, 0o640); err != nil {
		return err
	}

	_, err := m.Runner.Run(ctx, system.Command{Name: "chown", Args: []string{"redis:redis", path}})

	return err
}
