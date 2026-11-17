// Package listenowner checks who listens on a TCP port: the LISTEN sockets in /proc/net/tcp and /proc/net/tcp6,
// matched by inode to the open sockets of the processes in a systemd unit's control group.
package listenowner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Socket is one LISTEN socket.
type Socket struct {
	Port  int
	UID   uint32
	Inode uint64
}

// listenState is TCP_LISTEN as /proc/net/tcp prints it.
const listenState = "0A"

// ParseProcNetTCP returns the LISTEN sockets of a /proc/net/tcp or /proc/net/tcp6 table.
func ParseProcNetTCP(r io.Reader) ([]Socket, error) {
	scanner := bufio.NewScanner(r)
	scanner.Scan() // the header

	var sockets []Socket
	for scanner.Scan() {
		// sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode ...
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			return nil, fmt.Errorf("unexpected line %q", scanner.Text())
		}
		if fields[3] != listenState {
			continue
		}

		_, hexPort, ok := strings.Cut(fields[1], ":")
		port, portErr := strconv.ParseUint(hexPort, 16, 16)
		uid, uidErr := strconv.ParseUint(fields[7], 10, 32)
		inode, inodeErr := strconv.ParseUint(fields[9], 10, 64)
		if !ok || portErr != nil || uidErr != nil || inodeErr != nil {
			return nil, fmt.Errorf("unexpected line %q", scanner.Text())
		}

		sockets = append(sockets, Socket{Port: int(port), UID: uint32(uid), Inode: inode})
	}

	return sockets, scanner.Err()
}

// ForeignError is a port that nothing listens on, or that a process outside the unit listens on.
type ForeignError struct {
	Port int
	// Foreign are the listeners outside the unit; none means nothing listens at all.
	Foreign []Socket
}

func (e *ForeignError) Error() string {
	return fmt.Sprintf("Port %d is held by a process outside the release.", e.Port)
}

// Detail says what was found, for the deploy log.
func (e *ForeignError) Detail() string {
	if len(e.Foreign) == 0 {
		return fmt.Sprintf("Nothing listens on port %d, though something answered there.", e.Port)
	}

	var uids []string
	for _, socket := range e.Foreign {
		uids = append(uids, strconv.FormatUint(uint64(socket.UID), 10))
	}
	slices.Sort(uids)

	return fmt.Sprintf("Port %d has a listener outside the release, owned by uid %s.", e.Port, strings.Join(slices.Compact(uids), ", "))
}

// Checker reads /proc and /sys/fs/cgroup under Paths.Root and asks systemctl for a unit's control group.
type Checker struct {
	Paths  paths.Paths
	System system.Runner
}

// OwnedBy returns nil when at least one socket listens on port and every one belongs to a process in unit's control
// group, and a *ForeignError otherwise.
func (c Checker) OwnedBy(ctx context.Context, port int, unit string) error {
	listeners, err := c.listeners(port)
	if err != nil {
		return err
	}

	owned, err := c.unitSockets(ctx, unit)
	if err != nil {
		return err
	}

	var foreign []Socket
	for _, socket := range listeners {
		if !owned[socket.Inode] {
			foreign = append(foreign, socket)
		}
	}
	if len(listeners) == 0 || len(foreign) > 0 {
		return &ForeignError{Port: port, Foreign: foreign}
	}

	return nil
}

func (c Checker) listeners(port int) ([]Socket, error) {
	sockets, err := Listening(c.Paths)
	if err != nil {
		return nil, err
	}

	var found []Socket
	for _, socket := range sockets {
		if socket.Port == port {
			found = append(found, socket)
		}
	}

	return found, nil
}

// Listening returns the LISTEN sockets of /proc/net/tcp and /proc/net/tcp6 under p's root: those of the reader's
// network namespace.
func Listening(p paths.Paths) ([]Socket, error) {
	var found []Socket
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		file, err := os.Open(p.File(table))
		if errors.Is(err, fs.ErrNotExist) {
			continue // no IPv6
		}
		if err != nil {
			return nil, err
		}

		sockets, err := ParseProcNetTCP(file)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", table, err)
		}

		found = append(found, sockets...)
	}

	return found, nil
}

// unitSockets returns the inodes of every socket the unit's processes hold open. A unit that isn't running has none.
func (c Checker) unitSockets(ctx context.Context, unit string) (map[uint64]bool, error) {
	result, err := c.System.Run(ctx, system.Command{Name: "systemctl", Args: []string{"show", "--property=ControlGroup", "--value", unit}})
	if err != nil {
		return nil, fmt.Errorf("find the control group of %s: %w", unit, err)
	}

	owned := map[uint64]bool{}
	group := strings.TrimSpace(string(result.Output))
	if group == "" {
		return owned, nil
	}

	var pids []string
	err = filepath.WalkDir(c.Paths.File(path.Join("/sys/fs/cgroup", group)), func(file string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // the unit stopped meanwhile
			}
			return err
		}
		if entry.Name() != "cgroup.procs" {
			return nil
		}

		content, err := os.ReadFile(file)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		pids = append(pids, strings.Fields(string(content))...)

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list the processes of %s: %w", unit, err)
	}

	for _, pid := range pids {
		dir := c.Paths.File(path.Join("/proc", pid, "fd"))
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // the process exited
		}

		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}

			inode, ok := strings.CutPrefix(target, "socket:[")
			if !ok {
				continue
			}
			if value, err := strconv.ParseUint(strings.TrimSuffix(inode, "]"), 10, 64); err == nil {
				owned[value] = true
			}
		}
	}

	return owned, nil
}
