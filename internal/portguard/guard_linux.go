//go:build linux

package portguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const mapName = "ports"

// userPortOffset is offsetof(struct bpf_sock_addr, user_port) in include/uapi/linux/bpf.h: user_family (4 bytes),
// user_ip4 (4) and user_ip6 (16) come first. The kernel allows a 4-byte read of it and fills it from sin_port or
// sin6_port, so the port is in network byte order in the low 16 bits.
const userPortOffset = 24

type hook struct {
	pin    string
	attach ebpf.AttachType
}

var hooks = []hook{
	{pin: "bind4", attach: ebpf.AttachCGroupInet4Bind},
	{pin: "bind6", attach: ebpf.AttachCGroupInet6Bind},
}

// Ensure attaches the guard, or replaces the attached programs in place (an atomic link update, so binds are never
// unguarded). The map is reused when it is pinned already, so its entries survive; a map from an incompatible
// earlier layout is replaced by an empty one.
func (g Guard) Ensure() error {
	if err := os.MkdirAll(g.PinDir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", g.PinDir, err)
	}

	hostNetns, err := netnsCookie()
	if err != nil {
		return err
	}

	ports, err := g.openMap()
	if err != nil {
		return err
	}
	defer ports.Close()

	for _, h := range hooks {
		program, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Name:         "serverdog_" + h.pin,
			Type:         ebpf.CGroupSockAddr,
			AttachType:   h.attach,
			Instructions: g.instructions(ports.FD(), hostNetns),
			License:      "Apache-2.0",
		})
		if err != nil {
			return fmt.Errorf("load the %s program: %w", h.pin, err)
		}

		err = g.attach(program, h)
		program.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

// netnsCookie returns the cookie of the caller's network namespace: the host's, since the boot unit and the agent run
// in it. It needs Linux 5.14 (SO_NETNS_COOKIE).
func netnsCookie() (uint64, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open a socket for the network namespace cookie: %w", err)
	}
	defer unix.Close(fd)

	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if err != nil {
		return 0, fmt.Errorf("read the network namespace cookie: %w", err)
	}

	return cookie, nil
}

func (g Guard) openMap() (*ebpf.Map, error) {
	spec := &ebpf.MapSpec{
		Name:       mapName,
		Type:       ebpf.Hash,
		KeySize:    2,
		ValueSize:  4,
		MaxEntries: uint32(g.Last) - uint32(g.First) + 1,
		Pinning:    ebpf.PinByName,
	}

	ports, err := ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: g.PinDir})
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		if err := os.Remove(filepath.Join(g.PinDir, mapName)); err != nil {
			return nil, fmt.Errorf("remove the old port map: %w", err)
		}
		ports, err = ebpf.NewMapWithOptions(spec, ebpf.MapOptions{PinPath: g.PinDir})
	}
	if err != nil {
		return nil, fmt.Errorf("open the port map: %w", err)
	}

	return ports, nil
}

func (g Guard) attach(program *ebpf.Program, h hook) error {
	path := filepath.Join(g.PinDir, h.pin)

	pinned, err := link.LoadPinnedLink(path, nil)
	if err == nil {
		defer pinned.Close()
		if err := pinned.Update(program); err != nil {
			return fmt.Errorf("replace the %s program: %w", h.pin, err)
		}

		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("open %s: %w", path, err)
	}

	attached, err := link.AttachCgroup(link.CgroupOptions{Path: g.Cgroup, Attach: h.attach, Program: program})
	if err != nil {
		return fmt.Errorf("attach the %s program to %s: %w", h.pin, g.Cgroup, err)
	}
	// Closing an unpinned link detaches it, so a failed pin leaves nothing behind.
	defer attached.Close()

	if err := attached.Pin(path); err != nil {
		return fmt.Errorf("pin %s: %w", path, err)
	}

	return nil
}

// instructions is the bind program. It returns 1 to allow the bind and 0 to fail it with EPERM. hostNetns is the
// host network namespace's cookie; Ensure loads the program again on every run, so it never goes stale.
func (g Guard) instructions(portsFD int, hostNetns uint64) asm.Instructions {
	return asm.Instructions{
		// r8 = the context, kept for the helper call below.
		asm.Mov.Reg(asm.R8, asm.R1),
		// r6 = the port being bound, in host order.
		asm.LoadMem(asm.R6, asm.R1, userPortOffset, asm.Word),
		asm.HostTo(asm.BE, asm.R6, asm.Half),
		// Ports outside the range, and port 0 (any free port), aren't the guard's business.
		asm.JLT.Imm(asm.R6, int32(g.First), "allow"),
		asm.JGT.Imm(asm.R6, int32(g.Last), "allow"),
		// Neither is a bind in another network namespace (a container's): it can't receive the host's loopback
		// traffic, which is what the guard keeps for the sites.
		asm.Mov.Reg(asm.R1, asm.R8),
		asm.FnGetNetnsCookie.Call(),
		asm.LoadImm(asm.R1, int64(hostNetns), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R1, "allow"),
		// r7 = the caller's real uid (not its effective uid), the low 32 bits of bpf_get_current_uid_gid(). A setuid
		// binary therefore binds as whoever ran it. Root may bind anything.
		asm.FnGetCurrentUidGid.Call(),
		asm.Mov.Reg32(asm.R7, asm.R0),
		asm.JEq.Imm(asm.R7, 0, "allow"),
		// r0 = ports[port], with the 2-byte key on the stack at fp-2.
		asm.StoreMem(asm.RFP, -2, asm.R6, asm.Half),
		asm.LoadMapPtr(asm.R1, portsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -2),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "deny"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.Word),
		asm.JEq.Reg(asm.R1, asm.R7, "allow"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("deny"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	}
}

// Attached reports whether both links and the map are pinned.
func (g Guard) Attached() bool {
	for _, h := range hooks {
		pinned, err := link.LoadPinnedLink(filepath.Join(g.PinDir, h.pin), nil)
		if err != nil {
			return false
		}
		pinned.Close()
	}

	ports, err := ebpf.LoadPinnedMap(filepath.Join(g.PinDir, mapName), nil)
	if err != nil {
		return false
	}
	ports.Close()

	return true
}

// Sync makes the map hold exactly allowed (port -> uid). New entries go in before stale ones come out, so a port
// that keeps its user never denies it in between.
func (g Guard) Sync(allowed map[uint16]uint32) error {
	ports, err := ebpf.LoadPinnedMap(filepath.Join(g.PinDir, mapName), nil)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotAttached
	}
	if err != nil {
		return fmt.Errorf("open the port map: %w", err)
	}
	defer ports.Close()

	for port, uid := range allowed {
		if err := ports.Update(port, uid, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("allow uid %d on port %d: %w", uid, port, err)
		}
	}

	var stale []uint16
	var port uint16
	var uid uint32
	entries := ports.Iterate()
	for entries.Next(&port, &uid) {
		if _, ok := allowed[port]; !ok {
			stale = append(stale, port)
		}
	}
	if err := entries.Err(); err != nil {
		return fmt.Errorf("read the port map: %w", err)
	}

	for _, port := range stale {
		if err := ports.Delete(port); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("remove port %d: %w", port, err)
		}
	}

	return nil
}

// Remove detaches the guard. Unpinning a link only detaches its program after an RCU grace period and a workqueue
// run, so each link is detached explicitly first: binds are unguarded as soon as Remove returns.
func (g Guard) Remove() error {
	var errs []error
	for _, h := range hooks {
		if err := g.detach(h); err != nil {
			errs = append(errs, err)
		}
	}

	if err := os.RemoveAll(g.PinDir); err != nil {
		errs = append(errs, fmt.Errorf("remove %s: %w", g.PinDir, err))
	}

	return errors.Join(errs...)
}

func (g Guard) detach(h hook) error {
	path := filepath.Join(g.PinDir, h.pin)

	pinned, err := link.LoadPinnedLink(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer pinned.Close()

	if err := pinned.Detach(); err != nil {
		return fmt.Errorf("detach the %s program: %w", h.pin, err)
	}

	return nil
}
