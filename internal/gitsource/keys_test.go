package gitsource

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

func TestPendingKeyIsStableThenInstalledForTheUser(t *testing.T) {
	root := t.TempDir()
	keys := Keys{Paths: paths.Paths{Root: root}}
	current, _ := user.Current()
	fs := userfs.FS{Runner: system.Exec{}}
	ctx := context.Background()

	first, err := keys.Pending("abcdefghijkl")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.PublicKey, "ssh-ed25519 ") || !strings.HasSuffix(first.PublicKey, " serverdog-abcdefghijkl") || !strings.HasPrefix(first.Fingerprint, "SHA256:") {
		t.Errorf("key = %+v", first)
	}

	again, _ := keys.Pending("abcdefghijkl")
	if again != first {
		t.Error("pending key changed between calls")
	}

	info, err := os.Stat(keys.PendingKeyPath("abcdefghijkl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("pending private key: %v %v", info, err)
	}

	if err := keys.Install(ctx, "abcdefghijkl", current.Username, fs); err != nil {
		t.Fatal(err)
	}

	installed, err := keys.Installed(ctx, "abcdefghijkl", current.Username, fs)
	if err != nil || installed != first {
		t.Errorf("installed = %+v %v, want the pending key", installed, err)
	}

	private := filepath.Join(root, "home", current.Username, ".ssh", "serverdog-abcdefghijkl")
	if info, err := os.Stat(private); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("installed private key: %v %v", info, err)
	}
	if _, err := os.Stat(keys.PendingKeyPath("abcdefghijkl")); err != nil {
		t.Errorf("Install removed the pending key: %v", err)
	}

	if err := keys.Install(ctx, "abcdefghijkl", current.Username, fs); err != nil {
		t.Errorf("second Install: %v", err)
	}
}
