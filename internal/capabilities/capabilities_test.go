package capabilities

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func touch(t *testing.T, root, name string) {
	t.Helper()

	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func output(text string) func(system.Command) (system.Result, error) {
	return func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(text)}, nil
	}
}

func TestDetect(t *testing.T) {
	root := t.TempDir()
	touch(t, root, "etc/php/8.3/fpm/php-fpm.conf")
	touch(t, root, "etc/php/8.4/fpm/php-fpm.conf")
	touch(t, root, "etc/php/7.4/cli/php.ini")
	touch(t, root, "usr/sbin/mysqld")

	runner := &systemtest.Fake{}
	runner.Handle("nginx", output("nginx version: nginx/1.24.0 (Ubuntu)\n"))
	runner.Handle("node", output("v24.22.0\n"))
	runner.Handle("uv", output("uv 0.13.9 (x86_64-unknown-linux-gnu)\n"))
	runner.Handle("bun", output("1.4.4\n"))
	runner.Handle("/usr/sbin/mysqld", output("/usr/sbin/mysqld  Ver 8.4.11 for Linux on aarch64 (MySQL Community Server - GPL)\n"))

	detector := Detector{
		Root:   root,
		Runner: runner,
		InterfaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{
				&net.IPNet{IP: net.ParseIP("127.0.0.1")},
				&net.IPNet{IP: net.ParseIP("10.0.0.5")},
				&net.IPNet{IP: net.ParseIP("100.64.1.1")},
				&net.IPNet{IP: net.ParseIP("204.168.251.65")},
				&net.IPNet{IP: net.ParseIP("fe80::1")},
				&net.IPNet{IP: net.ParseIP("2a01:4f9:c012:1234::1")},
			}, nil
		},
	}

	got := detector.Detect(context.Background())
	want := Capabilities{
		PHPVersions:     []string{"8.4", "8.3"},
		DatabaseEngine:  "mysql",
		DatabaseVersion: "8.4.11",
		NodeVersion:     "v24.22.0",
		UVVersion:       "0.13.9",
		BunVersion:      "1.4.4",
		NginxVersion:    "1.24.0",
		PublicAddresses: []string{"204.168.251.65", "2a01:4f9:c012:1234::1"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Detect =\n%+v\nwant\n%+v", got, want)
	}
	if got.NginxHTTP2Directive() {
		t.Error("nginx 1.24 doesn't support http2 on;")
	}
	if host := got.Host(); !host.HasNginx || !host.HasNode || len(host.PHPVersions) != 2 {
		t.Errorf("Host = %+v", host)
	}
}

func TestDetectMariaDBAndPostgres(t *testing.T) {
	mariadb := t.TempDir()
	touch(t, mariadb, "usr/sbin/mariadbd")
	touch(t, mariadb, "usr/sbin/mysqld")
	runner := &systemtest.Fake{}
	runner.Handle("/usr/sbin/mariadbd", output("/usr/sbin/mariadbd  Ver 11.8.3-MariaDB-0ubuntu1 for debian-linux-gnu\n"))

	got := Detector{Root: mariadb, Runner: runner, InterfaceAddrs: noAddrs}.Detect(context.Background())
	if got.DatabaseEngine != "mariadb" || got.DatabaseVersion != "11.8.3" {
		t.Errorf("mariadb = %q %q", got.DatabaseEngine, got.DatabaseVersion)
	}

	postgres := t.TempDir()
	touch(t, postgres, "usr/lib/postgresql/18/bin/postgres")
	got = Detector{Root: postgres, Runner: &systemtest.Fake{}, InterfaceAddrs: noAddrs}.Detect(context.Background())
	if got.DatabaseEngine != "postgres" || got.DatabaseVersion != "18" {
		t.Errorf("postgres = %q %q", got.DatabaseEngine, got.DatabaseVersion)
	}
}

func TestMissingToolsLeaveFieldsEmpty(t *testing.T) {
	runner := &systemtest.Fake{}
	runner.Fail("nginx", 127, "not found")
	runner.Fail("node", 127, "not found")

	got := Detector{Root: t.TempDir(), Runner: runner, InterfaceAddrs: noAddrs}.Detect(context.Background())
	if got.NginxVersion != "" || got.NodeVersion != "" || got.DatabaseEngine != "" || len(got.PHPVersions) != 0 {
		t.Errorf("got = %+v", got)
	}
}

func TestHTTP2Directive(t *testing.T) {
	for version, want := range map[string]bool{"1.24.0": false, "1.25.0": false, "1.25.1": true, "1.28.3": true, "2.0.0": true, "": false} {
		if got := (Capabilities{NginxVersion: version}).NginxHTTP2Directive(); got != want {
			t.Errorf("%q: %v", version, got)
		}
	}
}

func noAddrs() ([]net.Addr, error) { return nil, nil }

func writeFile(t *testing.T, root, name, content string) {
	t.Helper()

	touch(t, root, name)
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPortGuardNeedsTheGuardAndEphemeralPortsOutsideTheNodeRange(t *testing.T) {
	cases := []struct {
		name      string
		attached  func() bool
		portRange string
		want      bool
	}{
		{"attached, default range", func() bool { return true }, "32768\t60999\n", true},
		{"attached, range overlapping the Node ports", func() bool { return true }, "15000\t65000\n", false},
		{"attached, range ending inside the Node ports", func() bool { return true }, "10000\t20000\n", false},
		{"attached, range just below the Node ports", func() bool { return true }, "10000\t19999\n", true},
		{"detached", func() bool { return false }, "32768\t60999\n", false},
		{"no guard at all", nil, "32768\t60999\n", false},
	}

	for _, c := range cases {
		root := t.TempDir()
		writeFile(t, root, "proc/sys/net/ipv4/ip_local_port_range", c.portRange)

		got := Detector{Root: root, Runner: &systemtest.Fake{}, InterfaceAddrs: noAddrs, PortGuardAttached: c.attached}.Detect(context.Background())
		if got.PortGuard != c.want {
			t.Errorf("%s: PortGuard = %v, want %v", c.name, got.PortGuard, c.want)
		}
	}
}

func TestLocalPortRangeOverlapsReportsTheRange(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "proc/sys/net/ipv4/ip_local_port_range", "15000\t65000\n")

	overlaps, portRange, err := LocalPortRangeOverlaps(root)
	if err != nil || !overlaps || portRange != "15000-65000" {
		t.Errorf("LocalPortRangeOverlaps = %v %q %v", overlaps, portRange, err)
	}

	if _, _, err := LocalPortRangeOverlaps(t.TempDir()); err == nil {
		t.Error("a missing file must be an error, not a pass")
	}
}
