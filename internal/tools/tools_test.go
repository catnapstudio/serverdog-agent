package tools

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

func tarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	writer := tar.NewWriter(compressed)
	for name, content := range files {
		writer.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content)), Typeflag: tar.TypeReg})
		writer.Write([]byte(content))
	}
	writer.Close()
	compressed.Close()

	return buffer.Bytes()
}

func zipped(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		file, _ := writer.Create(name)
		file.Write([]byte(content))
	}
	writer.Close()

	return buffer.Bytes()
}

// serve is GitHub serving body as the tool's archive; the tool expects listed's checksum.
func serve(t *testing.T, archive string, body, listed []byte, binaries ...string) (*Installer, Tool, *atomic.Int32) {
	t.Helper()

	var downloads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		w.Write(body)
	}))
	t.Cleanup(server.Close)

	sum := sha256.Sum256(listed)
	tool := Tool{
		Name: "tool", Version: "1.0.0", Binaries: binaries,
		URL:    func(asset string) string { return server.URL + "/" + asset },
		assets: map[string]asset{"amd64": {archive, hex.EncodeToString(sum[:])}},
	}

	return &Installer{Paths: paths.Paths{Root: t.TempDir()}, Client: server.Client(), Arch: "amd64"}, tool, &downloads
}

func TestInstallsTheBinariesFromATarGz(t *testing.T) {
	archive := tarGz(t, map[string]string{"uv-x86_64/uv": "uv binary", "uv-x86_64/uvx": "uvx binary", "uv-x86_64/README": "no"})
	installer, tool, downloads := serve(t, "uv.tar.gz", archive, archive, "uv", "uvx")

	if err := installer.Install(context.Background(), tool); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]string{"uv": "uv binary", "uvx": "uvx binary"} {
		file := installer.Paths.File("/usr/local/bin/" + name)
		content, err := os.ReadFile(file)
		if err != nil || string(content) != want {
			t.Errorf("%s = %q, %v", name, content, err)
		}
		if info, _ := os.Stat(file); info == nil || info.Mode().Perm() != 0o755 {
			t.Errorf("%s isn't executable", name)
		}
	}
	if _, err := os.Stat(installer.Paths.File("/usr/local/bin/README")); err == nil {
		t.Error("a file that isn't a binary was installed")
	}

	if err := installer.Install(context.Background(), tool); err != nil || downloads.Load() != 1 {
		t.Errorf("installing again downloaded %d times, %v", downloads.Load(), err)
	}
}

func TestInstallsTheBinaryFromAZip(t *testing.T) {
	archive := zipped(t, map[string]string{"bun-linux-x64/bun": "bun binary"})
	installer, tool, _ := serve(t, "bun.zip", archive, archive, "bun")

	if err := installer.Install(context.Background(), tool); err != nil {
		t.Fatal(err)
	}

	if content, _ := os.ReadFile(installer.Paths.File("/usr/local/bin/bun")); string(content) != "bun binary" {
		t.Errorf("bun = %q", content)
	}
}

func TestADownloadThatDoesntMatchTheChecksumInstallsNothing(t *testing.T) {
	archive := zipped(t, map[string]string{"bun": "replaced"})
	installer, tool, _ := serve(t, "bun.zip", archive, []byte("the real archive"), "bun")

	err := installer.Install(context.Background(), tool)
	if !errors.As(err, new(*DownloadError)) {
		t.Fatalf("err = %v, want a DownloadError", err)
	}

	if _, err := os.Stat(installer.Paths.File("/usr/local/bin/bun")); err == nil {
		t.Error("the binary was installed")
	}
	if _, err := os.Stat(installer.Paths.File(Marker(tool))); err == nil {
		t.Error("the tool was marked installed")
	}
}

func TestAnArchiveWithoutTheBinaryInstallsNothing(t *testing.T) {
	archive := tarGz(t, map[string]string{"uv": "uv binary"})
	installer, tool, _ := serve(t, "uv.tar.gz", archive, archive, "uv", "uvx")

	if err := installer.Install(context.Background(), tool); !errors.As(err, new(*DownloadError)) {
		t.Fatalf("err = %v, want a DownloadError", err)
	}

	if _, err := os.Stat(installer.Paths.File("/usr/local/bin/uv")); err == nil {
		t.Error("part of the tool was installed")
	}
}

func TestRefreshLeavesToolsServerDogNeverInstalled(t *testing.T) {
	installer := &Installer{Paths: paths.Paths{Root: t.TempDir()}, Client: &http.Client{Transport: failing{}}, Arch: "amd64"}

	if err := installer.Refresh(context.Background()); err != nil {
		t.Errorf("Refresh downloaded: %v", err)
	}
}

func TestRefreshUpdatesAToolServerDogInstalled(t *testing.T) {
	installer := &Installer{Paths: paths.Paths{Root: t.TempDir()}, Client: &http.Client{Transport: failing{}}, Arch: "amd64"}
	os.MkdirAll(filepath.Dir(installer.Paths.File(Marker(UV))), 0o755)
	os.WriteFile(installer.Paths.File(Marker(UV)), []byte("0.0.1\n"), 0o644)

	if err := installer.Refresh(context.Background()); !errors.As(err, new(*DownloadError)) {
		t.Errorf("Refresh = %v, want it to try to download uv", err)
	}
}

func TestNamed(t *testing.T) {
	if tool, ok := Named("uv"); !ok || tool.Version != UV.Version {
		t.Error("uv")
	}
	if _, ok := Named("pip"); ok {
		t.Error("pip")
	}
	for _, tool := range []Tool{UV, Bun} {
		for _, arch := range []string{"amd64", "arm64"} {
			if len(tool.assets[arch].sha256) != 64 {
				t.Errorf("%s has no checksum for %s", tool.Name, arch)
			}
		}
	}
}

type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) { return nil, errors.New("offline") }
