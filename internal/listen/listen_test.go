package listen

import (
	"os"
	"path/filepath"
	"testing"
)

// shortDir returns a temp dir under /tmp: macOS limits socket paths to 104 bytes and t.TempDir() is longer.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "ca")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestUnixCreatesOwnerOnlySocket(t *testing.T) {
	path := filepath.Join(shortDir(t), "run", "agent.sock")

	listener, err := Unix(path)
	if err != nil {
		t.Fatalf("Unix: %v", err)
	}
	defer listener.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Errorf("%s is not a socket", path)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %o, want 600", perm)
	}
}

func TestUnixReplacesStaleSocketFile(t *testing.T) {
	path := filepath.Join(shortDir(t), "agent.sock")
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}

	listener, err := Unix(path)
	if err != nil {
		t.Fatalf("Unix: %v", err)
	}
	listener.Close()
}
