package frankenphp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// serve is GitHub: a release that lists the asset with listed's digest, and the asset itself, which is body.
func serve(t *testing.T, body, listed string) (*Installer, *atomic.Int32) {
	t.Helper()

	var downloads atomic.Int32
	sum := sha256.Sum256([]byte(listed))
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/release":
			fmt.Fprintf(w, `{"assets":[{"name":"frankenphp-linux-x86_64","browser_download_url":"%s/asset","digest":"sha256:%s"}]}`, server.URL, hex.EncodeToString(sum[:]))
		case "/asset":
			downloads.Add(1)
			w.Write([]byte(body))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "usr/local/bin"), 0o755)

	return &Installer{Paths: paths.Paths{Root: root}, Client: server.Client(), ReleaseURL: server.URL + "/release", Arch: "amd64"}, &downloads
}

func TestInstallVerifiesAndSkipsTheSameBinary(t *testing.T) {
	installer, requests := serve(t, "binary", "binary")

	if err := installer.Refresh(context.Background()); err != nil || requests.Load() != 0 {
		t.Fatalf("Refresh without a binary = %v after %d requests", err, requests.Load())
	}

	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(installer.Paths.File(Binary))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("binary = %v, %v", info, err)
	}

	if err := installer.Install(context.Background()); err != nil || requests.Load() != 1 {
		t.Errorf("a second Install = %v after %d requests", err, requests.Load())
	}
}

func TestACorruptDownloadIsNotInstalled(t *testing.T) {
	installer, _ := serve(t, "damaged", "binary")

	var download *DownloadError
	if err := installer.Install(context.Background()); !errors.As(err, &download) {
		t.Fatalf("Install = %v", err)
	}
	for _, name := range []string{Binary, Binary + ".download"} {
		if _, err := os.Stat(installer.Paths.File(name)); !os.IsNotExist(err) {
			t.Errorf("%s is there: %v", name, err)
		}
	}
}

// A FrankenPHP someone installed by hand is theirs: an agent start never replaces it. One ServerDog installed is
// brought to this agent's version.
func TestRefreshOnlyReplacesWhatServerDogInstalled(t *testing.T) {
	installer, requests := serve(t, "this version", "this version")
	binary := installer.Paths.File(Binary)

	if err := os.WriteFile(binary, []byte("their own build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := installer.Refresh(context.Background()); err != nil || requests.Load() != 0 {
		t.Fatalf("Refresh = %v after %d requests", err, requests.Load())
	}
	if content, _ := os.ReadFile(binary); string(content) != "their own build" {
		t.Fatalf("a hand-installed binary was replaced: %q", content)
	}

	// Octane was turned on from the app, which installs it: from then on it is ServerDog's to keep current.
	if err := installer.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	// An agent update brings a new Version: the binary an older agent installed is replaced.
	os.WriteFile(binary, []byte("an older version"), 0o755)
	if err := os.WriteFile(installer.Paths.File(Marker), []byte("1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installer.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if content, _ := os.ReadFile(binary); string(content) != "this version" {
		t.Fatalf("Refresh left %q", content)
	}
}
