// Package phpversions installs and removes PHP versions and picks the one the php command runs, with the packages the
// app's provisioning installs.
package phpversions

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Candidates are the versions the app offers, newest first.
var Candidates = []string{"8.5", "8.4", "8.3", "8.2", "8.1", "8.0", "7.4"}

var extensions = []string{"fpm", "cli", "common", "mysql", "pgsql", "sqlite3", "mbstring", "xml", "curl", "zip", "bcmath", "intl", "gd", "readline"}

// suryList is where provisioning adds packages.sury.org, which has every candidate.
const suryList = "/etc/apt/sources.list.d/serverdog-sury-php.list"

var packageLine = regexp.MustCompile(`(?m)^Package: php([0-9.]+)-fpm$`)

type Status struct {
	// Installed are the versions with PHP-FPM, newest first.
	Installed []string
	// Available are the candidates apt can install that aren't installed.
	Available []string
	// CLI is the version the php command runs; "" when it isn't one of ours.
	CLI string
	// UsedBy maps a version to the sites that run on it.
	UsedBy map[string][]string
}

// Error is a failed command: a summary, then the end of its output.
type Error struct {
	Summary string
	Output  string
}

func (e *Error) Error() string {
	return e.Summary + "\n\n" + e.Output
}

type Manager struct {
	Paths  paths.Paths
	System system.Runner
	Sites  func() ([]site.Site, error)
	// AfterInstall gives a new version the server's PHP settings (phpsettings.Manager.ApplyVersion). Nil does nothing.
	AfterInstall func(ctx context.Context, version string) error

	mu sync.Mutex
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	usedBy, err := m.usedBy()
	if err != nil {
		return Status{}, err
	}

	status := Status{Installed: m.installed(), CLI: m.cli(), UsedBy: usedBy}

	// apt-cache exits non-zero when any package is unknown, but still prints the ones it knows.
	args := []string{"show", "--no-all-versions"}
	for _, version := range Candidates {
		args = append(args, "php"+version+"-fpm")
	}
	result, _ := m.System.Run(ctx, system.Command{Name: "apt-cache", Args: args})

	for _, match := range packageLine.FindAllStringSubmatch(string(result.Output), -1) {
		if !slices.Contains(status.Installed, match[1]) && !slices.Contains(status.Available, match[1]) {
			status.Available = append(status.Available, match[1])
		}
	}
	slices.SortFunc(status.Available, func(a, b string) int { return slices.Index(Candidates, a) - slices.Index(Candidates, b) })

	return status, nil
}

// Install adds a version with its PHP-FPM service running.
func (m *Manager) Install(ctx context.Context, version string) error {
	if !slices.Contains(Candidates, version) {
		return invalid("ServerDog installs PHP %s.", strings.Join(Candidates, ", "))
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if slices.Contains(m.installed(), version) {
		return nil
	}

	packages := make([]string, 0, len(extensions)+1)
	for _, extension := range extensions {
		packages = append(packages, "php"+version+"-"+extension)
	}

	redis := "php-redis"
	if _, err := os.Stat(m.Paths.File(suryList)); err == nil {
		redis = "php" + version + "-redis"
	}
	packages = append(packages, redis)

	if err := m.apt(ctx, fmt.Sprintf("PHP %s couldn't be installed.", version), append([]string{"install"}, packages...)...); err != nil {
		return err
	}

	if err := m.run(ctx, fmt.Sprintf("PHP %s's FPM service didn't start.", version), "systemctl", "enable", "--now", "php"+version+"-fpm"); err != nil {
		return err
	}

	if m.AfterInstall == nil {
		return nil
	}

	if err := m.AfterInstall(ctx, version); err != nil {
		return fmt.Errorf("PHP %s is installed, but the server's PHP settings couldn't be applied to it: %w", version, err)
	}

	return nil
}

// Remove purges a version no site runs on, that isn't the php command's, and isn't the last one.
func (m *Manager) Remove(ctx context.Context, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	installed := m.installed()
	if !slices.Contains(installed, version) {
		return nil
	}

	usedBy, err := m.usedBy()
	if err != nil {
		return err
	}
	if sites := usedBy[version]; len(sites) > 0 {
		return invalid("%s run on PHP %s. Move them to another version first.", strings.Join(sites, ", "), version)
	}
	if m.cli() == version {
		return invalid("The php command runs PHP %s. Pick another version for it first.", version)
	}
	if len(installed) == 1 {
		return invalid("PHP %s is the only version on this server.", version)
	}

	result, err := m.System.Run(ctx, system.Command{Name: "dpkg-query", Args: []string{"--show", "--showformat=${Package}\\n", "php" + version + "-*"}})
	if err != nil {
		return &Error{Summary: fmt.Sprintf("Couldn't list PHP %s's packages.", version), Output: system.Tail(result.Output, 10)}
	}

	packages := strings.Fields(string(result.Output))
	if len(packages) == 0 {
		return nil
	}

	_ = m.run(ctx, "", "systemctl", "disable", "--now", "php"+version+"-fpm")

	return m.apt(ctx, fmt.Sprintf("PHP %s couldn't be removed.", version), append([]string{"purge"}, packages...)...)
}

// SetCLI points the php command at an installed version.
func (m *Manager) SetCLI(ctx context.Context, version string) error {
	if !slices.Contains(m.installed(), version) {
		return invalid("PHP %s isn't installed on this server.", version)
	}

	return m.run(ctx, fmt.Sprintf("Couldn't make PHP %s the php command.", version), "update-alternatives", "--set", "php", "/usr/bin/php"+version)
}

func (m *Manager) installed() []string {
	matches, _ := filepath.Glob(m.Paths.File("/etc/php/*/fpm/php-fpm.conf"))

	var versions []string
	for _, version := range Candidates {
		if slices.Contains(matches, m.Paths.File("/etc/php/"+version+"/fpm/php-fpm.conf")) {
			versions = append(versions, version)
		}
	}

	return versions
}

func (m *Manager) cli() string {
	target, err := filepath.EvalSymlinks(m.Paths.File("/etc/alternatives/php"))
	if err != nil {
		return ""
	}

	version := strings.TrimPrefix(filepath.Base(target), "php")
	if !slices.Contains(Candidates, version) {
		return ""
	}

	return version
}

func (m *Manager) usedBy() (map[string][]string, error) {
	sites, err := m.Sites()
	if err != nil {
		return nil, err
	}

	usedBy := map[string][]string{}
	for _, s := range sites {
		if s.PHPVersion != "" {
			usedBy[s.PHPVersion] = append(usedBy[s.PHPVersion], s.DirectoryName())
		}
	}

	return usedBy, nil
}

func (m *Manager) apt(ctx context.Context, summary string, args ...string) error {
	command := system.Command{
		Name: "apt-get",
		Args: append([]string{"-y", "-q", "-o", "DPkg::Lock::Timeout=300", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}, args...),
		Env:  append(os.Environ(), "DEBIAN_FRONTEND=noninteractive"),
	}

	result, err := m.System.Run(ctx, command)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &Error{Summary: summary, Output: system.Tail(result.Output, 10)}
	}

	return nil
}

func (m *Manager) run(ctx context.Context, summary, name string, args ...string) error {
	result, err := m.System.Run(ctx, system.Command{Name: name, Args: args})
	if err != nil {
		return &Error{Summary: summary, Output: system.Tail(result.Output, 10)}
	}

	return nil
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "php", Reason: fmt.Sprintf(format, args...)}
}
