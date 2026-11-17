// Package frankenphp installs one FrankenPHP binary for the whole server, where Laravel Octane finds it on PATH. Octane
// would otherwise download its own into each release, which is ~175 MB on every zero-downtime deploy.
package frankenphp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// Version is the FrankenPHP release this agent installs. Its assets aren't pinned by checksum: FrankenPHP rebuilds
// its newest release's binaries every night, so a pinned sum is stale within a day. A download is checked against
// the SHA-256 GitHub lists for the asset instead, which catches a damaged download, not a replaced build.
const Version = "1.13.5"

// Binary is where it goes: on the PATH systemd gives every unit.
const Binary = "/usr/local/bin/frankenphp"

var assets = map[string]string{
	"amd64": "frankenphp-linux-x86_64",
	"arm64": "frankenphp-linux-aarch64",
}

// DownloadError is a failed or corrupted download: nothing was installed, and installing again retries.
type DownloadError struct{ Reason string }

func (e *DownloadError) Error() string {
	return fmt.Sprintf("Couldn't install FrankenPHP %s: %s", Version, e.Reason)
}

type Installer struct {
	Paths  paths.Paths
	Client *http.Client
	// ReleaseURL describes the release as GitHub's API does, with each asset's download URL and digest, e.g.
	// https://api.github.com/repos/php/frankenphp/releases/tags/v1.13.5.
	ReleaseURL string
	// Arch is runtime.GOARCH.
	Arch string

	mu sync.Mutex
}

// Install puts this version's binary in place unless ServerDog installed it already. The download goes to a
// temporary file that replaces the binary only once its checksum matches, so running Octane servers never see a
// partial file.
func (i *Installer) Install(ctx context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	name, supported := assets[i.Arch]
	if !supported {
		return &DownloadError{Reason: fmt.Sprintf("there's no build for %s servers", i.Arch)}
	}

	target := i.Paths.File(Binary)
	if marked, _ := os.ReadFile(i.Paths.File(Marker)); strings.TrimSpace(string(marked)) == Version {
		if _, err := os.Stat(target); err == nil {
			return nil
		}
	}

	url, digest, err := i.find(ctx, name)
	if err != nil {
		return err
	}

	response, err := i.get(ctx, url)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	temporary := target + ".download"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	defer os.Remove(temporary)

	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(file, hash), response.Body)
	if err := errors.Join(copyErr, file.Close()); err != nil {
		return &DownloadError{Reason: err.Error()}
	}
	if sum := "sha256:" + hex.EncodeToString(hash.Sum(nil)); sum != digest {
		return &DownloadError{Reason: "the download didn't match the checksum GitHub lists for it, so it wasn't installed. Try again"}
	}

	if err := os.Chmod(temporary, 0o755); err != nil {
		return err
	}

	if err := os.Rename(temporary, target); err != nil {
		return err
	}

	return i.mark()
}

// find returns where GitHub serves the release's asset and the digest it lists for it.
func (i *Installer) find(ctx context.Context, name string) (url, digest string, err error) {
	response, err := i.get(ctx, i.ReleaseURL)
	if err != nil {
		return "", "", err
	}
	defer response.Body.Close()

	var release struct {
		Assets []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&release); err != nil {
		return "", "", &DownloadError{Reason: "GitHub's description of the release couldn't be read"}
	}

	for _, asset := range release.Assets {
		if asset.Name == name && asset.URL != "" && strings.HasPrefix(asset.Digest, "sha256:") {
			return asset.URL, asset.Digest, nil
		}
	}

	return "", "", &DownloadError{Reason: "GitHub lists no " + name + " with a checksum in that release"}
}

func (i *Installer) get(ctx context.Context, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := i.Client.Do(request)
	if err != nil {
		return nil, &DownloadError{Reason: err.Error()}
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()

		return nil, &DownloadError{Reason: "GitHub answered " + response.Status}
	}

	return response, nil
}

// Marker records that ServerDog installed the binary, so Refresh never replaces one put there by hand.
const Marker = paths.StateDir + "/frankenphp"

func (i *Installer) mark() error {
	if err := os.MkdirAll(filepath.Dir(i.Paths.File(Marker)), 0o755); err != nil {
		return err
	}

	return os.WriteFile(i.Paths.File(Marker), []byte(Version+"\n"), 0o644)
}

// Refresh replaces the binary ServerDog installed, when it is another version, with this one, as after an agent
// update. A server where ServerDog never installed FrankenPHP downloads nothing and keeps whatever is there.
func (i *Installer) Refresh(ctx context.Context) error {
	if _, err := os.Stat(i.Paths.File(Marker)); errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return i.Install(ctx)
}
