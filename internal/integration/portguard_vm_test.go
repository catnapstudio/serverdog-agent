//go:build vmtest

package integration

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/portguard"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// bindScript binds one socket and prints "ok" or the errno name. Arguments: tcp|udp, address, port.
const bindScript = `import errno, socket, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
s = socket.socket(family, socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM)
try:
    s.bind((host, port))
    print("ok")
except OSError as e:
    print(errno.errorcode.get(e.errno, str(e.errno)))
`

// bindIn binds address:port in a new process that runs as user (nil: root) inside the cgroup at cgroupDir ("": the
// test's own), and returns "ok" or the errno name.
func bindIn(t *testing.T, cgroupDir string, user *system.User, kind, address string, port int) string {
	t.Helper()

	return bindWith(t, &syscall.SysProcAttr{}, cgroupDir, user, kind, address, port)
}

// bindInNewNetns is bindIn in a fresh network namespace. Its loopback device is down, so bind a wildcard address.
func bindInNewNetns(t *testing.T, cgroupDir string, user *system.User, kind, address string, port int) string {
	t.Helper()

	return bindWith(t, &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}, cgroupDir, user, kind, address, port)
}

func bindWith(t *testing.T, attr *syscall.SysProcAttr, cgroupDir string, user *system.User, kind, address string, port int) string {
	t.Helper()

	if user != nil {
		attr.Credential = &syscall.Credential{Uid: user.UID, Gid: user.GID}
	}
	if cgroupDir != "" {
		dir, err := os.Open(cgroupDir)
		if err != nil {
			t.Fatal(err)
		}
		defer dir.Close()
		attr.UseCgroupFD, attr.CgroupFD = true, int(dir.Fd())
	}

	cmd := exec.Command("python3", "-c", bindScript, kind, address, strconv.Itoa(port))
	cmd.Dir, cmd.SysProcAttr = "/", attr
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bind %s %s:%d: %v\n%s", kind, address, port, err, output)
	}

	return strings.TrimSpace(string(output))
}

func lookup(t *testing.T, name string) *system.User {
	t.Helper()

	user, err := system.LookupUser(name)
	if err != nil {
		t.Fatal(err)
	}

	return &user
}

// TestPortGuardProgram loads the guard on a scratch child cgroup with its own pins and range, so the kernel's verifier
// checks the program and the server's own guard (20000-29999 on the root cgroup) doesn't get in the way.
func TestPortGuardProgram(t *testing.T) {
	cgroup := "/sys/fs/cgroup/serverdog-guard-test"
	guard := portguard.Guard{PinDir: "/sys/fs/bpf/serverdog-guard-test", Cgroup: cgroup, First: 31000, Last: 31999}

	guard.Remove()
	os.Remove(cgroup)
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		guard.Remove()
		os.Remove(cgroup)
	})

	if guard.Attached() {
		t.Fatal("attached before Ensure")
	}
	// The second Ensure replaces the attached programs through the pinned links and keeps the map.
	for range 2 {
		if err := guard.Ensure(); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}
	if !guard.Attached() {
		t.Fatal("not attached after Ensure")
	}

	owner, other := lookup(t, "serverdog"), lookup(t, "git")
	if err := guard.Sync(map[uint16]uint32{31500: owner.UID, 31501: owner.UID}); err != nil {
		t.Fatal(err)
	}
	if err := guard.Ensure(); err != nil {
		t.Fatalf("Ensure after Sync: %v", err)
	}
	// 31501 is no longer allocated, so it falls back to root only.
	if err := guard.Sync(map[uint16]uint32{31500: owner.UID}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		user *system.User
		kind string
		port int
		want string
	}{
		{"root on an allocated port", nil, "tcp", 31500, "ok"},
		{"root on an unallocated port", nil, "tcp", 31502, "ok"},
		{"the owner on its port", owner, "tcp", 31500, "ok"},
		{"the owner on its port over UDP", owner, "udp", 31500, "ok"},
		{"another user on the owner's port", other, "tcp", 31500, "EPERM"},
		{"another user on the owner's port over UDP", other, "udp", 31500, "EPERM"},
		{"the owner on a port it no longer has", owner, "tcp", 31501, "EPERM"},
		{"another user on the first port", other, "tcp", 31000, "EPERM"},
		{"another user on the last port", other, "tcp", 31999, "EPERM"},
		{"another user below the range", other, "tcp", 30999, "ok"},
		{"another user above the range", other, "tcp", 32000, "ok"},
		{"another user on any free port", other, "tcp", 0, "ok"},
	}
	for _, c := range cases {
		for _, address := range []string{"127.0.0.1", "0.0.0.0", "::"} {
			if got := bindIn(t, cgroup, c.user, c.kind, address, c.port); got != c.want {
				t.Errorf("%s (%s %s:%d) = %s, want %s", c.name, c.kind, address, c.port, got, c.want)
			}
		}
	}

	// In another network namespace (a container's) the guard doesn't apply either, to an allocated port or a free one.
	for _, port := range []int{31500, 31000} {
		for _, address := range []string{"0.0.0.0", "::"} {
			if got := bindInNewNetns(t, cgroup, other, "tcp", address, port); got != "ok" {
				t.Errorf("another user in another network namespace (%s:%d) = %s, want ok", address, port, got)
			}
			if got := bindIn(t, cgroup, other, "tcp", address, port); got != "EPERM" {
				t.Errorf("another user in the host network namespace (%s:%d) = %s, want EPERM", address, port, got)
			}
		}
	}

	// Outside the scratch cgroup the scratch guard doesn't apply.
	if got := bindIn(t, "", other, "tcp", "127.0.0.1", 31500); got != "ok" {
		t.Errorf("another user outside the cgroup = %s, want ok", got)
	}

	if err := guard.Remove(); err != nil {
		t.Fatal(err)
	}
	if guard.Attached() {
		t.Error("attached after Remove")
	}
	if got := bindIn(t, cgroup, other, "tcp", "127.0.0.1", 31500); got != "ok" {
		t.Errorf("another user after Remove = %s, want ok", got)
	}
}
