// Package tools installs the server-wide uv (Python sites) and Bun (a package manager for Node builds) on the PATH
// systemd and deploys give every site user. Each version and its archives' checksums are pinned here: their releases
// are never rebuilt, so a download is checked against a sum this agent was built with.
package tools

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// BinDir is where the binaries go.
const BinDir = "/usr/local/bin"

type asset struct {
	name   string
	sha256 string
}

// Tool is one installable tool: a release archive per architecture holding Binaries.
type Tool struct {
	Name     string
	Version  string
	Binaries []string
	// URL is the release's download URL for an asset name.
	URL    func(asset string) string
	assets map[string]asset
}

// UV and Bun are the tools the agent installs, from their GitHub releases (checked 2026-11-19).
var (
	UV = Tool{
		Name: "uv", Version: "0.13.9", Binaries: []string{"uv", "uvx"},
		URL: func(asset string) string {
			return "https://github.com/astral-sh/uv/releases/download/0.13.9/" + asset
		},
		assets: map[string]asset{
			"amd64": {"uv-x86_64-unknown-linux-gnu.tar.gz", "a7fbaff2b9a271d85c1bdb540941090fd1ce011797b4abeb48e4dcd39c2471d5"},
			"arm64": {"uv-aarch64-unknown-linux-gnu.tar.gz", "0797542018e541a9288855df555c8077eed06f7a47d206362030480e8ecc9f3d"},
		},
	}
	Bun = Tool{
		Name: "bun", Version: "1.4.4", Binaries: []string{"bun"},
		URL: func(asset string) string {
			return "https://github.com/oven-sh/bun/releases/download/bun-v1.4.4/" + asset
		},
		assets: map[string]asset{
			"amd64": {"bun-linux-x64.zip", "bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c"},
			"arm64": {"bun-linux-aarch64.zip", "baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e"},
		},
	}
)

// Named returns the tool called name ("uv" or "bun").
func Named(name string) (Tool, bool) {
	for _, tool := range []Tool{UV, Bun} {
		if tool.Name == name {
			return tool, true
		}
	}

	return Tool{}, false
}

// DownloadError is a failed or corrupted download: nothing was installed, and installing again retries.
type DownloadError struct {
	Tool   Tool
	Reason string
}

func (e *DownloadError) Error() string {
	return fmt.Sprintf("Couldn't install %s %s: %s", e.Tool.Name, e.Tool.Version, e.Reason)
}

// The archives are tens of megabytes; anything far larger isn't the release.
const maxArchive = 256 << 20

type Installer struct {
	Paths  paths.Paths
	Client *http.Client
	// Arch is runtime.GOARCH.
	Arch string

	mu sync.Mutex
}

// Install puts the tool's pinned version in place unless ServerDog installed it already. The archive and each binary
// stream to temporary files beside the binaries, so a ~100 MB Bun never sits in the agent's memory, and each binary is
// renamed over the old one only once all of them are extracted: a running deploy never sees a partial file.
func (i *Installer) Install(ctx context.Context, tool Tool) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.installed(tool) {
		return nil
	}

	archive, supported := tool.assets[i.Arch]
	if !supported {
		return &DownloadError{Tool: tool, Reason: fmt.Sprintf("there's no build for %s servers", i.Arch)}
	}

	dir := i.Paths.File(BinDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	downloaded := filepath.Join(dir, "."+tool.Name+".download")
	defer os.Remove(downloaded)

	if err := i.download(ctx, tool, archive, downloaded); err != nil {
		return err
	}

	extracted := map[string]string{}
	defer func() {
		for _, file := range extracted {
			os.Remove(file)
		}
	}()

	if err := extract(downloaded, archive.name, tool.Binaries, func(name string) string {
		extracted[name] = filepath.Join(dir, "."+name+".new")
		return extracted[name]
	}); err != nil {
		return &DownloadError{Tool: tool, Reason: err.Error()}
	}

	for _, name := range tool.Binaries {
		if err := os.Rename(extracted[name], filepath.Join(dir, name)); err != nil {
			return err
		}
	}

	return i.mark(tool)
}

// Refresh moves each tool ServerDog installed to this agent's pinned version, as after an agent update. A tool
// ServerDog never installed is left alone.
func (i *Installer) Refresh(ctx context.Context) error {
	var failures []error

	for _, tool := range []Tool{UV, Bun} {
		if _, err := os.Stat(i.Paths.File(Marker(tool))); err != nil {
			continue
		}

		failures = append(failures, i.Install(ctx, tool))
	}

	return errors.Join(failures...)
}

// Marker records the version ServerDog installed, so Refresh never replaces a tool put there by hand.
func Marker(tool Tool) string { return path.Join(paths.StateDir, tool.Name) }

func (i *Installer) installed(tool Tool) bool {
	marked, _ := os.ReadFile(i.Paths.File(Marker(tool)))
	if strings.TrimSpace(string(marked)) != tool.Version {
		return false
	}

	for _, name := range tool.Binaries {
		if _, err := os.Stat(i.Paths.File(path.Join(BinDir, name))); err != nil {
			return false
		}
	}

	return true
}

// download writes the archive to file, refusing it unless its SHA-256 is the pinned one.
func (i *Installer) download(ctx context.Context, tool Tool, archive asset, file string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tool.URL(archive.name), nil)
	if err != nil {
		return err
	}

	response, err := i.Client.Do(request)
	if err != nil {
		return &DownloadError{Tool: tool, Reason: err.Error()}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return &DownloadError{Tool: tool, Reason: "GitHub answered " + response.Status}
	}

	out, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}

	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(out, hash), io.LimitReader(response.Body, maxArchive+1))
	if err := errors.Join(copyErr, out.Close()); err != nil {
		return &DownloadError{Tool: tool, Reason: err.Error()}
	}

	if written > maxArchive || hex.EncodeToString(hash.Sum(nil)) != archive.sha256 {
		return &DownloadError{Tool: tool, Reason: "the download didn't match the checksum ServerDog expects, so it wasn't installed. Try again"}
	}

	return nil
}

// extract writes each named binary in the archive, matched by file name whatever folder holds it, to the file target
// names, executable. It fails unless every one is there.
func extract(file, archive string, names []string, target func(name string) string) error {
	in, err := os.Open(file)
	if err != nil {
		return err
	}
	defer in.Close()

	found := map[string]bool{}
	write := func(name string, content io.Reader) error {
		out, err := os.OpenFile(target(name), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}

		written, copyErr := io.Copy(out, io.LimitReader(content, maxArchive))
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}

		found[name] = written > 0
		return nil
	}
	wanted := func(entry string) (string, bool) {
		name := path.Base(entry)
		return name, slices.Contains(names, name)
	}

	switch {
	case strings.HasSuffix(archive, ".tar.gz"):
		compressed, err := gzip.NewReader(in)
		if err != nil {
			return err
		}

		reader := tar.NewReader(compressed)
		for {
			header, err := reader.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return err
			}

			if name, ok := wanted(header.Name); ok && header.Typeflag == tar.TypeReg {
				if err := write(name, reader); err != nil {
					return err
				}
			}
		}
	case strings.HasSuffix(archive, ".zip"):
		info, err := in.Stat()
		if err != nil {
			return err
		}

		reader, err := zip.NewReader(in, info.Size())
		if err != nil {
			return err
		}

		for _, entry := range reader.File {
			name, ok := wanted(entry.Name)
			if !ok || entry.FileInfo().IsDir() {
				continue
			}

			opened, err := entry.Open()
			if err != nil {
				return err
			}
			err = write(name, opened)
			opened.Close()
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("%s isn't an archive ServerDog reads", archive)
	}

	for _, name := range names {
		if !found[name] {
			return fmt.Errorf("the archive has no %s", name)
		}
	}

	return nil
}

func (i *Installer) mark(tool Tool) error {
	if err := os.MkdirAll(filepath.Dir(i.Paths.File(Marker(tool))), 0o755); err != nil {
		return err
	}

	return os.WriteFile(i.Paths.File(Marker(tool)), []byte(tool.Version+"\n"), 0o644)
}
