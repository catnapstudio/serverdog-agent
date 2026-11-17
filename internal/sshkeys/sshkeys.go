// Package sshkeys keeps the SSH keys the app added to root's and the site users' authorized_keys. They live between two
// marker lines that are rewritten whole; every other line, such as the key the app itself connects with, is kept.
package sshkeys

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

type Key struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	User      string `json:"user"`
	PublicKey string `json:"publicKey"`
}

// Other is a key in an authorized_keys file that ServerDog didn't add.
type Other struct {
	User        string
	Fingerprint string
	Comment     string
}

type Status struct {
	Keys     []Key
	Revision uint64
	Other    []Other
	// Users are the accounts keys can go to: root, then the sites' users.
	Users []string
}

const (
	MaxKeys  = 100
	document = "ssh_keys"
	begin    = "# ServerDog keys: added in the app. The lines up to the end marker are rewritten; add your own keys outside them."
	end      = "# End of ServerDog keys"
)

type Manager struct {
	Store      *state.Store
	Sites      func() ([]site.Site, error)
	LookupUser func(string) (system.User, error)
	// FS reads and writes as the account whose file it is, so a site user's symlink can't redirect a root write.
	FS func(system.User) userfs.FS

	mu sync.Mutex
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	keys, revision, err := m.list()
	if err != nil {
		return Status{}, err
	}

	users, err := m.users()
	if err != nil {
		return Status{}, err
	}

	status := Status{Keys: keys, Revision: revision, Users: users}

	for _, name := range users {
		account, err := m.LookupUser(name)
		if err != nil {
			continue
		}

		content, _, err := m.FS(account).ReadFile(ctx, file(account))
		if err != nil {
			return Status{}, err
		}

		outside, _ := split(string(content))
		for _, line := range outside {
			key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
			if err != nil {
				continue
			}
			status.Other = append(status.Other, Other{User: name, Fingerprint: ssh.FingerprintSHA256(key), Comment: strings.ToValidUTF8(comment, "\uFFFD")})
		}
	}

	return status, nil
}

// Put replaces the app's keys. Each account whose keys changed gets its block rewritten; nothing is saved unless
// every file was written.
func (m *Manager) Put(ctx context.Context, keys []Key, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	users, err := m.users()
	if err != nil {
		return 0, err
	}

	if err := validate(keys, users); err != nil {
		return 0, err
	}

	old, current, err := m.list()
	if err != nil {
		return 0, err
	}
	if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	for _, name := range touched(old, keys) {
		account, err := m.LookupUser(name)
		if err != nil {
			return 0, invalid("This server has no user %s.", name)
		}

		if err := m.write(ctx, account, keys); err != nil {
			return 0, err
		}
	}

	encoded, err := json.Marshal(keys)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

func (m *Manager) write(ctx context.Context, account system.User, keys []Key) error {
	fs := m.FS(account)

	if err := fs.MkdirAll(ctx, "0700", path.Dir(file(account))); err != nil {
		return err
	}

	content, _, err := fs.ReadFile(ctx, file(account))
	if err != nil {
		return err
	}

	outside, _ := split(string(content))

	var lines []string
	for _, key := range keys {
		if key.User == account.Name {
			lines = append(lines, render(key))
		}
	}

	return fs.WriteFile(ctx, file(account), []byte(join(outside, lines)), "0600")
}

func (m *Manager) list() ([]Key, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, revision, err
	}

	var keys []Key

	return keys, revision, json.Unmarshal(encoded, &keys)
}

func (m *Manager) users() ([]string, error) {
	sites, err := m.Sites()
	if err != nil {
		return nil, err
	}

	users := []string{"root"}
	for _, s := range sites {
		if !slices.Contains(users, s.User) {
			users = append(users, s.User)
		}
	}

	return users, nil
}

func file(account system.User) string {
	return path.Join(account.Home, ".ssh", "authorized_keys")
}

// touched lists the accounts whose keys differ between old and new, in a stable order.
func touched(old, keys []Key) []string {
	lines := func(list []Key) map[string][]string {
		byUser := map[string][]string{}
		for _, key := range list {
			byUser[key.User] = append(byUser[key.User], render(key))
		}
		return byUser
	}
	before, after := lines(old), lines(keys)

	var users []string
	for _, list := range [][]Key{keys, old} {
		for _, key := range list {
			if !slices.Contains(users, key.User) && !slices.Equal(before[key.User], after[key.User]) {
				users = append(users, key.User)
			}
		}
	}

	return users
}

// split returns the file's lines outside the block, and the block's.
func split(content string) (outside, inside []string) {
	in := false

	for _, line := range strings.Split(strings.TrimRight(content, "\n"), "\n") {
		switch {
		case line == begin:
			in = true
		case line == end:
			in = false
		case in:
			inside = append(inside, line)
		case line != "" || len(outside) > 0:
			outside = append(outside, line)
		}
	}

	return outside, inside
}

func join(outside, keys []string) string {
	lines := slices.Clone(outside)
	if len(keys) > 0 {
		lines = append(lines, begin)
		lines = append(lines, keys...)
		lines = append(lines, end)
	}
	if len(lines) == 0 {
		return ""
	}

	return strings.Join(lines, "\n") + "\n"
}

// render writes the key from its parsed form, so nothing but a key type, its data and the name reaches the file.
func render(key Key) string {
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(parsed))) + " " + key.Name
}

func validate(keys []Key, users []string) error {
	if len(keys) > MaxKeys {
		return invalid("A server can have at most %d SSH keys added in the app.", MaxKeys)
	}

	seen := map[string]bool{}
	for _, key := range keys {
		if !ids.Valid(key.ID) || seen[key.ID] {
			return invalid("The key id %q isn't valid or is listed twice.", key.ID)
		}
		seen[key.ID] = true

		if strings.TrimSpace(key.Name) == "" || strings.ContainsAny(key.Name, "\r\n") || len(key.Name) > 60 {
			return invalid("An SSH key needs a single-line name of at most 60 characters.")
		}
		if !slices.Contains(users, key.User) {
			return invalid("%s: keys go to root or a site's user, and %q is neither.", key.Name, key.User)
		}

		_, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(key.PublicKey))
		if err != nil || strings.ContainsAny(key.PublicKey, "\r\n") || len(rest) > 0 {
			return invalid("%s isn't a public key. Paste one line, like the contents of ~/.ssh/id_ed25519.pub.", key.Name)
		}
		if len(options) > 0 {
			return invalid("%s has options before the key; paste the key alone.", key.Name)
		}
	}

	return nil
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "sshKeys", Reason: fmt.Sprintf(format, args...)}
}
