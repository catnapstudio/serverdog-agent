package listenowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

const tcp = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4E21 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1 0000000000000000 100 0 0 10 0
   1: 00000000:4E22 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:4E21 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 333 1 0000000000000000 20 4 30 10 -1
`

const tcp6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:4E23 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 444 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:4E21 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 555 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCPKeepsOnlyListeners(t *testing.T) {
	sockets, err := ParseProcNetTCP(strings.NewReader(tcp))
	if err != nil {
		t.Fatal(err)
	}
	want := []Socket{{Port: 20001, UID: 1000, Inode: 111}, {Port: 20002, UID: 1001, Inode: 222}}
	if !slices.Equal(sockets, want) {
		t.Errorf("tcp = %v, want %v", sockets, want)
	}

	sockets, err = ParseProcNetTCP(strings.NewReader(tcp6))
	if err != nil {
		t.Fatal(err)
	}
	want = []Socket{{Port: 20003, UID: 1001, Inode: 444}, {Port: 20001, UID: 1000, Inode: 555}}
	if !slices.Equal(sockets, want) {
		t.Errorf("tcp6 = %v, want %v", sockets, want)
	}
}

func TestParseProcNetTCPRejectsAGarbledTable(t *testing.T) {
	if _, err := ParseProcNetTCP(strings.NewReader("header\n   0: 0100007F:XYZ 00000000:0000 0A 0:0 0:0 0 1000 0 111\n")); err == nil {
		t.Error("a bad port parsed")
	}
}

const unit = "serverdog-site-abcdefghijkl@20001.service"

// fixture is a root where the unit's one process (pid 4242) holds sockets 111 and 555, and pid 5151 runs outside it.
func fixture(t *testing.T) Checker {
	t.Helper()

	root := t.TempDir()
	write := func(name, content string) {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(name, target string) {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}

	group := "/system.slice/system-serverdog\\x2dsite\\x2dabcdefghijkl.slice/" + unit
	write("proc/net/tcp", tcp)
	write("proc/net/tcp6", tcp6)
	write("sys/fs/cgroup"+group+"/cgroup.procs", "4242\n")
	link("proc/4242/fd/0", "/dev/null")
	link("proc/4242/fd/3", "socket:[111]")
	link("proc/4242/fd/4", "socket:[555]")
	link("proc/4242/fd/5", "pipe:[999]")
	link("proc/5151/fd/3", "socket:[222]")

	fake := &systemtest.Fake{}
	fake.Handle("systemctl", func(c system.Command) (system.Result, error) {
		if slices.Equal(c.Args, []string{"show", "--property=ControlGroup", "--value", unit}) {
			return system.Result{Output: []byte(group + "\n")}, nil
		}
		return system.Result{Output: []byte("\n")}, nil
	})

	return Checker{Paths: paths.Paths{Root: root}, System: fake}
}

func TestOwnedByAcceptsOnlyTheUnitsOwnListeners(t *testing.T) {
	c := fixture(t)

	if err := c.OwnedBy(context.Background(), 20001, unit); err != nil {
		t.Errorf("the unit's own IPv4 and IPv6 listeners: %v", err)
	}

	// 20002 is another user's IPv4 listener, 20003 another user's IPv6 wildcard.
	for _, port := range []int{20002, 20003} {
		err := c.OwnedBy(context.Background(), port, unit)
		var foreign *ForeignError
		if !errors.As(err, &foreign) || len(foreign.Foreign) != 1 || !strings.Contains(foreign.Detail(), "owned by uid 1001") {
			t.Errorf("port %d: %v", port, err)
			continue
		}
		if want := fmt.Sprintf("Port %d is held by a process outside the release.", port); err.Error() != want {
			t.Errorf("port %d message = %q, want %q", port, err, want)
		}
	}
}

func TestOwnedByRejectsAPortNothingListensOn(t *testing.T) {
	err := fixture(t).OwnedBy(context.Background(), 20004, unit)

	var foreign *ForeignError
	if !errors.As(err, &foreign) || len(foreign.Foreign) != 0 || !strings.Contains(foreign.Detail(), "Nothing listens on port 20004") {
		t.Errorf("OwnedBy = %v", err)
	}
}

func TestOwnedByRejectsListenersOfAUnitThatIsNotRunning(t *testing.T) {
	err := fixture(t).OwnedBy(context.Background(), 20001, "serverdog-site-abcdefghijkl@20000.service")

	var foreign *ForeignError
	if !errors.As(err, &foreign) || len(foreign.Foreign) != 2 {
		t.Errorf("OwnedBy = %v, want both listeners on 20001 foreign to a unit without a control group", err)
	}
}

func TestListeningReadsBothTables(t *testing.T) {
	sockets, err := Listening(fixture(t).Paths)
	if err != nil {
		t.Fatal(err)
	}

	want := []Socket{{Port: 20001, UID: 1000, Inode: 111}, {Port: 20002, UID: 1001, Inode: 222}, {Port: 20003, UID: 1001, Inode: 444}, {Port: 20001, UID: 1000, Inode: 555}}
	if !slices.Equal(sockets, want) {
		t.Errorf("Listening = %v, want %v", sockets, want)
	}
}
