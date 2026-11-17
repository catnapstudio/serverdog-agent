package gitsource

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
	"golang.org/x/crypto/ssh"
)

// DeployKey is the public half the user adds to their Git host.
type DeployKey struct {
	PublicKey   string
	Fingerprint string
}

// Keys manages per-site deploy keys. A key is generated "pending" (root-owned) when the New Site sheet asks for it,
// then installed into the site user's ~/.ssh when the site is created.
type Keys struct {
	Paths paths.Paths
}

func (k Keys) PendingKeyPath(siteID string) string {
	return filepath.Join(k.Paths.File(paths.PendingKeyDir(siteID)), "id_ed25519")
}

func (k Keys) PendingKnownHostsPath(siteID string) string {
	return filepath.Join(k.Paths.File(paths.PendingKeyDir(siteID)), "known_hosts")
}

// Pending returns the key of a site that doesn't exist yet, generating it on first use.
func (k Keys) Pending(siteID string) (DeployKey, error) {
	private := k.PendingKeyPath(siteID)

	if line, err := os.ReadFile(private + ".pub"); err == nil {
		return describe(line)
	}

	if err := os.MkdirAll(filepath.Dir(private), 0o700); err != nil {
		return DeployKey{}, fmt.Errorf("create key dir: %w", err)
	}

	privatePEM, publicLine, err := generate("serverdog-" + siteID)
	if err != nil {
		return DeployKey{}, err
	}

	if err := os.WriteFile(private, privatePEM, 0o600); err != nil {
		return DeployKey{}, fmt.Errorf("write deploy key: %w", err)
	}
	if err := os.WriteFile(private+".pub", publicLine, 0o644); err != nil {
		return DeployKey{}, fmt.Errorf("write deploy key: %w", err)
	}

	return describe(publicLine)
}

// Install puts the site's key into ~/.ssh/serverdog-<site-id> of userName, writing as that user. The pending copy stays
// (and is generated first when missing), so a key shown to the user before the site was saved is the one installed;
// the caller removes the pending directory once the site is stored.
func (k Keys) Install(ctx context.Context, siteID, userName string, files userfs.FS) error {
	installed := k.Paths.File(paths.DeployKey(userName, siteID))

	if _, ok, err := files.ReadFile(ctx, installed+".pub"); err != nil {
		return err
	} else if ok {
		return nil
	}

	if _, err := k.Pending(siteID); err != nil {
		return err
	}

	privatePEM, err := os.ReadFile(k.PendingKeyPath(siteID))
	if err != nil {
		return fmt.Errorf("read pending deploy key: %w", err)
	}
	publicLine, err := os.ReadFile(k.PendingKeyPath(siteID) + ".pub")
	if err != nil {
		return fmt.Errorf("read pending deploy key: %w", err)
	}

	if err := files.MkdirAll(ctx, "0700", filepath.Dir(installed)); err != nil {
		return err
	}
	if err := files.WriteFile(ctx, installed, privatePEM, "0600"); err != nil {
		return err
	}

	return files.WriteFile(ctx, installed+".pub", publicLine, "0644")
}

// Installed returns the public key of an existing site.
func (k Keys) Installed(ctx context.Context, siteID, userName string, files userfs.FS) (DeployKey, error) {
	line, ok, err := files.ReadFile(ctx, k.Paths.File(paths.DeployKey(userName, siteID))+".pub")
	if err != nil {
		return DeployKey{}, err
	}
	if !ok {
		return DeployKey{}, errors.New("the site's deploy key is missing; save the site again to create one")
	}

	return describe(line)
}

func generate(comment string) ([]byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate deploy key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(private, comment)
	if err != nil {
		return nil, nil, fmt.Errorf("encode deploy key: %w", err)
	}

	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, nil, fmt.Errorf("encode deploy key: %w", err)
	}

	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublic))) + " " + comment + "\n"

	return pem.EncodeToMemory(block), []byte(line), nil
}

func describe(line []byte) (DeployKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return DeployKey{}, fmt.Errorf("read deploy key: %w", err)
	}

	return DeployKey{PublicKey: strings.TrimSpace(string(line)), Fingerprint: ssh.FingerprintSHA256(key)}, nil
}
