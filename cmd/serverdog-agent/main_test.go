package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/listenowner"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/portguard"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

func TestEnvExportsMissingFilePrintsNothing(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := envExports([]string{filepath.Join(t.TempDir(), "missing.env")}, &stdout, &stderr, func(string) (string, bool) { return "", false })

	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestEnvExportsSkipsVariablesAlreadySet(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(file, []byte("PORT=1\nAPP=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	lookup := func(key string) (string, bool) { return "3000", key == "PORT" }

	code := envExports([]string{file}, &stdout, &stderr, lookup)

	if code != 0 || stdout.String() != "export APP='x'" || stderr.Len() != 0 {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestEnvExportsExpandsReferencesFromTheFileOnly(t *testing.T) {
	file := filepath.Join(t.TempDir(), ".env")
	content := "APP=shop\nURL=\"https://${APP}.test\"\nHOME_DIR=\"${HOME}\"\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	lookup := func(key string) (string, bool) { return "/root", key == "HOME" }

	code := envExports([]string{file}, &stdout, &stderr, lookup)

	want := "export APP='shop'\nexport URL='https://shop.test'\nexport HOME_DIR='${HOME}'"
	if code != 0 || stdout.String() != want || stderr.Len() != 0 {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

func TestEnvExportsRejectsWrongArgumentCount(t *testing.T) {
	for _, args := range [][]string{nil, {"a", "b"}} {
		var stdout, stderr bytes.Buffer

		code := envExports(args, &stdout, &stderr, func(string) (string, bool) { return "", false })

		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "usage") {
			t.Errorf("args %v: code = %d, stdout = %q, stderr = %q", args, code, stdout.String(), stderr.String())
		}
	}
}

func TestEnvExportsReportsReadErrorsWithoutContent(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := envExports([]string{t.TempDir()}, &stdout, &stderr, func(string) (string, bool) { return "", false })

	if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
	}
}

type fakeServer struct {
	release chan struct{}
	stopped chan struct{}
}

func (f *fakeServer) GracefulStop() {
	<-f.release
}

func (f *fakeServer) Stop() {
	close(f.stopped)
	close(f.release)
}

func TestStopWithinForcesStopWhenGracefulStopHangs(t *testing.T) {
	server := &fakeServer{release: make(chan struct{}), stopped: make(chan struct{})}

	stopWithin(server, 20*time.Millisecond)

	select {
	case <-server.stopped:
	default:
		t.Error("Stop was not called")
	}
}

func TestStopWithinLeavesQuickGracefulStopAlone(t *testing.T) {
	server := &fakeServer{release: make(chan struct{}), stopped: make(chan struct{})}
	close(server.release)

	stopWithin(server, time.Minute)

	select {
	case <-server.stopped:
		t.Error("Stop was called")
	default:
	}
}

func TestPortGuardRejectsExtraArguments(t *testing.T) {
	if err := portGuard([]string{"now"}); err == nil || !strings.Contains(err.Error(), "usage: serverdog-agent port-guard") {
		t.Errorf("portGuard = %v", err)
	}
}

type bootGuardFake struct {
	calls     []string
	attached  bool
	ensureErr error
	syncErr   error
}

func (g *bootGuardFake) Ensure() error {
	g.calls = append(g.calls, "ensure")
	if g.ensureErr != nil {
		return g.ensureErr
	}

	g.attached = true

	return nil
}

func (g *bootGuardFake) Remove() error {
	g.calls = append(g.calls, "remove")
	g.attached = false

	return nil
}

func (g *bootGuardFake) Attached() bool { return g.attached }

func (g *bootGuardFake) Sync(map[uint16]uint32) error {
	g.calls = append(g.calls, "sync")

	return g.syncErr
}

type bootPortUsers struct {
	err   error
	reads *[]string
}

func (u bootPortUsers) NodePortUsers() (map[int]string, error) {
	*u.reads = append(*u.reads, "read")

	return map[int]string{20000: "serverdog"}, u.err
}

func bootSyncer(guard portguard.Target, users portguard.PortUsers, t *testing.T) portguard.Syncer {
	lookup := func(name string) (system.User, error) { return system.User{Name: name, UID: 1000}, nil }

	return portguard.Syncer{Guard: guard, Store: users, LookupUser: lookup, LockPath: filepath.Join(t.TempDir(), "port-guard.lock")}
}

func TestAttachPortGuardReadsTheStoreBeforeAttaching(t *testing.T) {
	guard := &bootGuardFake{}
	var reads []string
	users := bootPortUsers{reads: &reads}

	if err := attachPortGuard(context.Background(), guard, users, bootSyncer(guard, users, t)); err != nil {
		t.Fatal(err)
	}

	if want := []string{"ensure", "sync"}; !slices.Equal(guard.calls, want) || len(reads) != 2 {
		t.Errorf("guard calls = %v, store reads = %d, want %v and a read before attaching, one in the sync", guard.calls, len(reads), want)
	}
}

func TestAttachPortGuardStaysDetachedWhenTheStoreCannotBeRead(t *testing.T) {
	guard := &bootGuardFake{}
	var reads []string
	users := bootPortUsers{err: errors.New("database is locked"), reads: &reads}

	err := attachPortGuard(context.Background(), guard, users, bootSyncer(guard, users, t))
	if err == nil || !strings.Contains(err.Error(), "database is locked") {
		t.Errorf("attachPortGuard = %v", err)
	}
	if len(guard.calls) != 0 {
		t.Errorf("guard calls = %v; an unfilled guard must never attach", guard.calls)
	}
}

func TestAttachPortGuardDetachesWhenItCannotBeAttachedOrFilled(t *testing.T) {
	var reads []string
	users := bootPortUsers{reads: &reads}

	failing := &bootGuardFake{ensureErr: errors.New("load the bind4 program")}
	if err := attachPortGuard(context.Background(), failing, users, bootSyncer(failing, users, t)); err == nil {
		t.Error("a guard that failed to attach reported success")
	}
	if want := []string{"ensure", "remove"}; !slices.Equal(failing.calls, want) {
		t.Errorf("guard calls = %v, want %v", failing.calls, want)
	}

	unfilled := &bootGuardFake{}
	syncer := bootSyncer(unfilled, users, t)
	syncer.Guard = notAttached{}
	if err := attachPortGuard(context.Background(), unfilled, users, syncer); !errors.Is(err, portguard.ErrNotAttached) {
		t.Errorf("attachPortGuard = %v, want ErrNotAttached", err)
	}
	if want := []string{"ensure", "remove"}; !slices.Equal(unfilled.calls, want) {
		t.Errorf("guard calls = %v, want %v", unfilled.calls, want)
	}
}

type notAttached struct{}

func (notAttached) Attached() bool { return false }

func (notAttached) Sync(map[uint16]uint32) error { return nil }

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestEnsurePortGuardAttachesADetachedGuardLikeTheBootUnit(t *testing.T) {
	guard := &bootGuardFake{}
	var reads []string
	users := bootPortUsers{reads: &reads}

	ensurePortGuard(context.Background(), guard, bootSyncer(guard, users, t), t.TempDir(), discardLogger())

	if want := []string{"ensure", "sync"}; !slices.Equal(guard.calls, want) || len(reads) != 2 || !guard.attached {
		t.Errorf("guard calls = %v, store reads = %d, attached = %v, want %v, a read before attaching and an attached guard", guard.calls, len(reads), guard.attached, want)
	}
}

func TestEnsurePortGuardLeavesADetachedGuardDetachedWhenItCannotBeFilled(t *testing.T) {
	var reads []string

	unreadable := &bootGuardFake{}
	users := bootPortUsers{err: errors.New("database is locked"), reads: &reads}
	ensurePortGuard(context.Background(), unreadable, bootSyncer(unreadable, users, t), t.TempDir(), discardLogger())
	if len(unreadable.calls) != 0 || unreadable.attached {
		t.Errorf("guard calls = %v; an unfilled guard must never attach", unreadable.calls)
	}

	unfilled := &bootGuardFake{syncErr: errors.New("update the port map")}
	users = bootPortUsers{reads: &reads}
	ensurePortGuard(context.Background(), unfilled, bootSyncer(unfilled, users, t), t.TempDir(), discardLogger())
	if want := []string{"ensure", "sync", "remove"}; !slices.Equal(unfilled.calls, want) || unfilled.attached {
		t.Errorf("guard calls = %v, want %v and a detached guard", unfilled.calls, want)
	}
}

func TestEnsurePortGuardKeepsAnAttachedGuardWhenTheSyncFails(t *testing.T) {
	guard := &bootGuardFake{attached: true, syncErr: errors.New("update the port map")}
	var reads []string
	users := bootPortUsers{reads: &reads}

	ensurePortGuard(context.Background(), guard, bootSyncer(guard, users, t), t.TempDir(), discardLogger())

	if want := []string{"ensure", "sync"}; !slices.Equal(guard.calls, want) || !guard.attached {
		t.Errorf("guard calls = %v, attached = %v, want %v and the boot unit's guard kept", guard.calls, guard.attached, want)
	}
}

func TestEnsurePortGuardKeepsAnAttachedGuardWhenItCannotBeReplaced(t *testing.T) {
	guard := &bootGuardFake{attached: true, ensureErr: errors.New("replace the bind4 program")}
	var reads []string
	users := bootPortUsers{reads: &reads}

	ensurePortGuard(context.Background(), guard, bootSyncer(guard, users, t), t.TempDir(), discardLogger())

	if want := []string{"ensure"}; !slices.Equal(guard.calls, want) || !guard.attached {
		t.Errorf("guard calls = %v, attached = %v, want %v and the boot unit's guard kept", guard.calls, guard.attached, want)
	}
}

// nodePortTCP has, in order: a site's port, a MongoDB-like service on 27017, root on 25000, root on 22, a user above
// and below the range, a connection (not a listener) in the range, and another user's service on 21000.
const nodePortTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4E20 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 101 1 0000000000000000 100 0 0 10 0
   1: 00000000:6989 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 102 1 0000000000000000 100 0 0 10 0
   2: 00000000:61A8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 103 1 0000000000000000 100 0 0 10 0
   3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 104 1 0000000000000000 100 0 0 10 0
   4: 00000000:7530 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 105 1 0000000000000000 100 0 0 10 0
   5: 00000000:4E1F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 106 1 0000000000000000 100 0 0 10 0
   6: 0100007F:55F0 0100007F:5208 01 00000000:00000000 00:00000000 00000000  1000        0 107 1 0000000000000000 20 4 30 10 -1
   7: 0100007F:5208 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 108 1 0000000000000000 100 0 0 10 0
`

func TestStrayNodeListenersAreNonRootListenersOnPortsNoSiteHas(t *testing.T) {
	sockets, err := listenowner.ParseProcNetTCP(strings.NewReader(nodePortTCP))
	if err != nil {
		t.Fatal(err)
	}

	got := strayNodeListeners(sockets, map[int]string{20000: "serverdog", 21001: "bob"})

	want := []listenowner.Socket{{Port: 27017, UID: 999, Inode: 102}, {Port: 21000, UID: 1002, Inode: 108}}
	if !slices.Equal(got, want) {
		t.Errorf("strayNodeListeners = %v, want %v", got, want)
	}
}

func TestWarnAboutStrayNodeListenersLogsOneLinePerListener(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "proc/net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "proc/net/tcp"), []byte(nodePortTCP), 0o644); err != nil {
		t.Fatal(err)
	}
	var reads []string
	var logs bytes.Buffer

	warnAboutStrayNodeListeners(paths.Paths{Root: root}, bootPortUsers{reads: &reads}, slog.New(slog.NewTextHandler(&logs, nil)))

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "port=27017 uid=999") || !strings.Contains(lines[1], "port=21000 uid=1002") {
		t.Fatalf("logs:\n%s", logs.String())
	}
	if !strings.Contains(lines[0], "level=WARN") || !strings.Contains(lines[0], "port guard") {
		t.Errorf("log line = %s", lines[0])
	}
}
