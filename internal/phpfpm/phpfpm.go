// Package phpfpm renders a site's PHP-FPM pool and the per-version PHP helpers deploy scripts use.
package phpfpm

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// RenderPool returns the site's own pool: its user, its socket, processes started on demand. Only Nginx (www-data)
// may connect to the socket: the shared serverdog user is in group www-data, so a group-writable socket would let it run
// code as any isolated site's user.
func RenderPool(siteID, user string, workers int) []byte {
	return []byte(fmt.Sprintf(`; Managed by ServerDog for site %[1]s.
[serverdog-%[1]s]
user = %[2]s
group = %[2]s
listen = %[3]s
listen.owner = www-data
listen.group = www-data
listen.mode = 0600
pm = ondemand
pm.max_children = %[4]d
pm.process_idle_timeout = 10s
pm.max_requests = 500
`, siteID, user, paths.FPMSocket(siteID), workers))
}

// Binary is the PHP CLI for a version, e.g. /usr/bin/php8.4.
func Binary(version string) string { return "/usr/bin/php" + version }

// RenderComposer is a wrapper that runs Composer on one PHP version.
func RenderComposer(version string) []byte {
	return []byte(fmt.Sprintf("#!/bin/sh\n# Managed by ServerDog: Composer on PHP %s.\nexec %s /usr/local/bin/composer \"$@\"\n", version, Binary(version)))
}

// Helpers are the php and composer commands for one version that deploy scripts find first in their PATH.
// Server setup writes them for every installed version, and saving a PHP site writes its version's.
func Helpers(p paths.Paths, version string) []apply.File {
	bin := paths.PHPHelperBin(version)

	return []apply.File{
		{Path: p.File(path.Join(bin, "php")), Link: Binary(version)},
		{Path: p.File(path.Join(bin, "composer")), Content: RenderComposer(version), Mode: 0o755},
	}
}

// Check validates every pool of a PHP version.
func Check(version string) system.Command {
	return system.Command{Name: fpmBinary(version), Args: []string{"-t"}}
}

// Installed reports whether a PHP version's FPM can still check and reload pools: its binary and its systemd unit
// exist. Once the package is removed neither does, and its sites must still be movable to another version or
// deletable.
func Installed(p paths.Paths, version string) bool {
	if _, err := os.Stat(p.File(fpmBinary(version))); err != nil {
		return false
	}

	for _, dir := range []string{"/usr/lib/systemd/system", "/lib/systemd/system"} {
		if _, err := os.Stat(p.File(path.Join(dir, "php"+version+"-fpm.service"))); err == nil {
			return true
		}
	}

	return false
}

func fpmBinary(version string) string { return "/usr/sbin/php-fpm" + version }

// Reload makes a PHP version's FPM pick up pool changes without dropping requests.
func Reload(version string) system.Command {
	return system.Command{Name: "systemctl", Args: []string{"reload", "php" + version + "-fpm"}}
}

// StockPoolLock closes the packaged "www" pool's socket to everyone but its owner. Left group-writable, the shared
// serverdog user (in group www-data) could have that pool run code as www-data, which every site's own socket trusts,
// and so reach an isolated site's user. The package's own file is left alone, so its upgrades never ask about it.
const StockPoolLock = `; Managed by ServerDog. Only www-data itself may use the packaged pool's socket.
[www]
listen.mode = 0600
`

// LockStockPool is the plan that tightens a version's packaged pool, or removes the lock once that pool is gone: a
// lock on its own would define a pool with no settings, which PHP-FPM refuses to load. A reload keeps the socket
// PHP-FPM already has open, mode included, so that socket is closed directly as well.
func LockStockPool(p paths.Paths, version string) apply.Plan {
	lock := apply.File{Path: p.File(paths.FPMStockPoolLock(version)), Content: []byte(StockPoolLock)}
	reloads := []system.Command{Reload(version)}

	stock, err := os.ReadFile(p.File(paths.FPMStockPool(version)))
	if err != nil {
		lock = apply.File{Path: lock.Path, Remove: true}
	} else if socket := stockSocket(stock); socket != "" {
		reloads = append(reloads, system.Command{Name: "chmod", Args: []string{"0600", socket}})
	}

	return apply.Plan{Files: []apply.File{lock}, Checks: []system.Command{Check(version)}, Reloads: reloads}
}

// stockSocket is the Unix socket the packaged pool listens on, or "" when it listens on a TCP address.
func stockSocket(conf []byte) string {
	socket := ""

	for _, line := range strings.Split(string(conf), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && strings.TrimSpace(key) == "listen" {
			socket = strings.TrimSpace(value)
		}
	}

	if !strings.HasPrefix(socket, "/") {
		return ""
	}

	return socket
}
