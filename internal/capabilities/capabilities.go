// Package capabilities finds out what a server has installed, so sites are only offered what it can run.
package capabilities

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Capabilities struct {
	PHPVersions     []string
	DatabaseEngine  string
	DatabaseVersion string
	NodeVersion     string
	NginxVersion    string
	PublicAddresses []string
	// PortGuard is true when the Node port guard is attached and no ephemeral port falls in the Node range, so no
	// other user can take a Node site's port.
	PortGuard bool
}

// Host is the part of Capabilities that site validation needs.
func (c Capabilities) Host() site.Host {
	return site.Host{PHPVersions: c.PHPVersions, HasNginx: c.NginxVersion != "", HasNode: c.NodeVersion != ""}
}

// NginxHTTP2Directive reports whether Nginx is 1.25.1 or newer, which enables HTTP/2 with "http2 on;"
// and deprecates the "http2" listen parameter. Ubuntu 24.04 ships 1.24.0; 26.04 ships 1.28.
func (c Capabilities) NginxHTTP2Directive() bool {
	version := parseVersion(c.NginxVersion)

	return compareVersions(version, []int{1, 25, 1}) >= 0
}

// Detector reads capabilities from a filesystem root and by running version commands.
type Detector struct {
	Root           string
	Runner         system.Runner
	InterfaceAddrs func() ([]net.Addr, error)
	// PortGuardAttached reports whether the Node port guard is attached (portguard.Guard.Attached). Nil means it isn't.
	PortGuardAttached func() bool
}

var (
	nginxVersion    = regexp.MustCompile(`nginx/(\d+\.\d+\.\d+)`)
	databaseVersion = regexp.MustCompile(`Ver (\d+\.\d+\.\d+)`)
)

func (d Detector) Detect(ctx context.Context) Capabilities {
	var c Capabilities

	c.PHPVersions = d.phpVersions()

	if match := nginxVersion.FindStringSubmatch(d.output(ctx, "nginx", "-v")); match != nil {
		c.NginxVersion = match[1]
	}

	if node := strings.TrimSpace(d.output(ctx, "node", "--version")); strings.HasPrefix(node, "v") {
		c.NodeVersion = node
	}

	c.DatabaseEngine, c.DatabaseVersion = d.database(ctx)
	c.PublicAddresses = d.publicAddresses()
	c.PortGuard = d.portGuard()

	return c
}

func (d Detector) portGuard() bool {
	if d.PortGuardAttached == nil || !d.PortGuardAttached() {
		return false
	}

	overlaps, _, err := LocalPortRangeOverlaps(d.Root)

	return err == nil && !overlaps
}

// LocalPortRangeOverlaps reports whether the kernel's ephemeral ports (net.ipv4.ip_local_port_range, which IPv6 uses
// too) overlap the Node ports, and returns the range as the kernel prints it. A listen() without a bind() takes an
// ephemeral port without passing the bind hook, so the port guard can't keep those ports. The default is 32768-60999.
func LocalPortRangeOverlaps(root string) (bool, string, error) {
	content, err := os.ReadFile(filepath.Join(root, "proc/sys/net/ipv4/ip_local_port_range"))
	if err != nil {
		return false, "", err
	}

	fields := strings.Fields(string(content))
	if len(fields) != 2 {
		return false, "", fmt.Errorf("unexpected ip_local_port_range %q", content)
	}

	low, lowErr := strconv.Atoi(fields[0])
	high, highErr := strconv.Atoi(fields[1])
	if lowErr != nil || highErr != nil {
		return false, "", fmt.Errorf("unexpected ip_local_port_range %q", content)
	}

	return low <= state.LastNodePort && high >= state.FirstNodePort, fields[0] + "-" + fields[1], nil
}

func (d Detector) phpVersions() []string {
	matches, _ := filepath.Glob(filepath.Join(d.Root, "etc/php/*/fpm/php-fpm.conf"))

	var versions []string
	for _, match := range matches {
		versions = append(versions, filepath.Base(filepath.Dir(filepath.Dir(match))))
	}

	slices.SortFunc(versions, func(a, b string) int {
		return compareVersions(parseVersion(b), parseVersion(a))
	})

	return versions
}

func (d Detector) database(ctx context.Context) (string, string) {
	if d.exists("usr/sbin/mariadbd") {
		return "mariadb", firstMatch(databaseVersion, d.output(ctx, "/usr/sbin/mariadbd", "--version"))
	}
	if d.exists("usr/sbin/mysqld") {
		return "mysql", firstMatch(databaseVersion, d.output(ctx, "/usr/sbin/mysqld", "--version"))
	}

	matches, _ := filepath.Glob(filepath.Join(d.Root, "usr/lib/postgresql/*/bin/postgres"))
	if len(matches) == 0 {
		return "", ""
	}

	var versions []string
	for _, match := range matches {
		versions = append(versions, filepath.Base(filepath.Dir(filepath.Dir(match))))
	}
	slices.SortFunc(versions, func(a, b string) int {
		return compareVersions(parseVersion(b), parseVersion(a))
	})

	return "postgres", versions[0]
}

func (d Detector) publicAddresses() []string {
	if d.InterfaceAddrs == nil {
		return nil
	}

	addresses, err := d.InterfaceAddrs()
	if err != nil {
		return nil
	}

	_, sharedSpace, _ := net.ParseCIDR("100.64.0.0/10")

	var public []string
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}

		ip := network.IP
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || sharedSpace.Contains(ip) {
			continue
		}

		public = append(public, ip.String())
	}

	return public
}

func (d Detector) output(ctx context.Context, name string, args ...string) string {
	result, err := d.Runner.Run(ctx, system.Command{Name: name, Args: args})
	if err != nil {
		return ""
	}

	return string(result.Output)
}

func (d Detector) exists(name string) bool {
	_, err := os.Stat(filepath.Join(d.Root, name))

	return err == nil
}

func firstMatch(pattern *regexp.Regexp, text string) string {
	if match := pattern.FindStringSubmatch(text); match != nil {
		return match[1]
	}

	return ""
}

func parseVersion(version string) []int {
	var parts []int
	for part := range strings.SplitSeq(version, ".") {
		value, err := strconv.Atoi(part)
		if err != nil {
			return parts
		}
		parts = append(parts, value)
	}

	return parts
}

func compareVersions(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			return x - y
		}
	}

	return 0
}
