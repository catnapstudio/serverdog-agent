package credentials

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()

	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}

	return &Manager{
		Paths:  paths.Paths{Root: root},
		Runner: system.Exec{},
		LookupUser: func(name string) (system.User, error) {
			switch name {
			case "alice":
				return system.User{Name: name, Home: "/home/alice"}, nil
			case "root":
				return system.User{Name: name, Home: "/root"}, nil
			}
			return system.User{}, errors.New("unknown user")
		},
	}, home
}

func TestComposerLoginsReplaceOnlyHTTPBasic(t *testing.T) {
	m, home := newManager(t)
	ctx := context.Background()
	os.MkdirAll(filepath.Join(home, ".composer"), 0o700)
	os.WriteFile(filepath.Join(home, ".composer", "auth.json"), []byte(`{"github-oauth":{"github.com":"gho_x"},"http-basic":{"old.example.com":{"username":"a","password":"b"}}}`), 0o600)

	nova := Composer{Host: "nova.laravel.com", Username: "me@example.com", Password: "secret"}
	if err := m.PutComposer(ctx, "alice", []Composer{nova}); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(filepath.Join(home, ".composer", "auth.json"))
	if !strings.Contains(string(content), `"github.com": "gho_x"`) || strings.Contains(string(content), "old.example.com") {
		t.Errorf("auth.json =\n%s", content)
	}

	list, err := m.Composer(ctx, "alice")
	if err != nil || !reflect.DeepEqual(list, []Composer{nova}) {
		t.Errorf("Composer = %v, %v", list, err)
	}

	if err := m.PutComposer(ctx, "alice", nil); err != nil {
		t.Fatal(err)
	}
	content, _ = os.ReadFile(filepath.Join(home, ".composer", "auth.json"))
	if strings.Contains(string(content), "http-basic") || !strings.Contains(string(content), "github-oauth") {
		t.Errorf("after removing every login, auth.json =\n%s", content)
	}
}

func TestComposerFileIsCreatedPrivate(t *testing.T) {
	m, home := newManager(t)

	if err := m.PutComposer(context.Background(), "alice", []Composer{{Host: "repo.example.com:8443", Username: "u", Password: "p"}}); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(home, ".composer", "auth.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("auth.json: %v %v", info, err)
	}
}

func TestNPMTokensReplaceOnlyTokenLines(t *testing.T) {
	m, home := newManager(t)
	ctx := context.Background()
	os.WriteFile(filepath.Join(home, ".npmrc"), []byte("@acme:registry=https://npm.pkg.github.com\n//registry.npmjs.org/:_authToken=old\n"), 0o600)

	tokens := []NPM{{Registry: "npm.pkg.github.com", Token: "ghp_1"}, {Registry: "registry.npmjs.org", Token: "npm_2"}}
	if err := m.PutNPM(ctx, "alice", tokens); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(filepath.Join(home, ".npmrc"))
	want := "@acme:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=ghp_1\n//registry.npmjs.org/:_authToken=npm_2\n"
	if string(content) != want {
		t.Errorf(".npmrc =\n%s\nwant\n%s", content, want)
	}

	list, err := m.NPM(ctx, "alice")
	if err != nil || !reflect.DeepEqual(list, tokens) {
		t.Errorf("NPM = %v, %v", list, err)
	}
}

func TestInvalidInputIsRefused(t *testing.T) {
	m, home := newManager(t)
	ctx := context.Background()

	if err := m.PutComposer(ctx, "root", nil); err == nil {
		t.Error("root's home was accepted")
	}
	if err := m.PutComposer(ctx, "bob", nil); err == nil {
		t.Error("an unknown user was accepted")
	}
	if err := m.PutComposer(ctx, "alice", []Composer{{Host: "https://x.com", Username: "u", Password: "p"}}); err == nil {
		t.Error("a URL was accepted as a host")
	}
	if err := m.PutComposer(ctx, "alice", []Composer{{Host: "x.com", Username: "u"}}); err == nil {
		t.Error("a login without a password was accepted")
	}
	if err := m.PutNPM(ctx, "alice", []NPM{{Registry: "registry.npmjs.org", Token: "a b"}}); err == nil {
		t.Error("a token with a space was accepted")
	}
	if err := m.PutNPM(ctx, "alice", []NPM{{Registry: "x.com/\n//evil", Token: "t"}}); err == nil {
		t.Error("a registry with a line break was accepted")
	}

	os.MkdirAll(filepath.Join(home, ".composer"), 0o700)
	os.WriteFile(filepath.Join(home, ".composer", "auth.json"), []byte("{broken"), 0o600)
	if err := m.PutComposer(ctx, "alice", nil); err == nil {
		t.Error("a broken auth.json was overwritten")
	}
}

func TestAComposerFileHoldingNullIsTreatedAsEmpty(t *testing.T) {
	m, home := newManager(t)
	os.MkdirAll(filepath.Join(home, ".composer"), 0o700)
	os.WriteFile(filepath.Join(home, ".composer", "auth.json"), []byte("null"), 0o600)

	if err := m.PutComposer(context.Background(), "alice", []Composer{{Host: "repo.example.com", Username: "u", Password: "p"}}); err != nil {
		t.Fatal(err)
	}
}
