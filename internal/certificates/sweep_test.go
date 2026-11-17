package certificates

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// A site delete that failed after forgetting the site leaves its certificate keys behind. The startup sweep removes
// them, logs each one, and leaves the folders of existing sites and anything not named like a site alone.
func TestRemoveOrphanFilesDeletesOnlyFoldersOfSitesThatAreGone(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	kept := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")

	orphan := f.file(paths.CertificateDir("zyxwvutsrqpo", "c1"))
	other := f.file(filepath.Join(paths.CertsDir, "not-a-site"))
	for _, dir := range []string{orphan, other} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(orphan, "privkey.pem"), []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	if err := f.manager.RemoveOrphanFiles(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(f.file(paths.SiteCertificates("zyxwvutsrqpo"))); !os.IsNotExist(err) {
		t.Errorf("the deleted site's certificates are still there: %v", err)
	}
	if _, err := os.Stat(certs.KeyFile(f.manager.Paths, "abcdefghijkl", kept.ID)); err != nil {
		t.Errorf("an existing site's key is gone: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("a folder not named like a site is gone: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(logged.String()), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "site=zyxwvutsrqpo") || !strings.Contains(lines[0], "path="+f.file(paths.SiteCertificates("zyxwvutsrqpo"))) {
		t.Errorf("log =\n%s", logged.String())
	}
}

func TestRemoveOrphanFilesWithoutACertificatesFolder(t *testing.T) {
	f := newFixture(t)

	if err := f.manager.RemoveOrphanFiles(); err != nil {
		t.Errorf("RemoveOrphanFiles = %v", err)
	}
}
