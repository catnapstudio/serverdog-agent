package sites

import (
	"errors"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

const selfHosted = "[git.example.com]:2222"

// providerKey returns one of the providers' published keys, as a stand-in for any host's key.
func providerKey(t *testing.T, name, keyType string) gitsource.HostKey {
	t.Helper()

	for _, key := range gitsource.ParseKnownHosts(gitsource.ProviderKnownHosts) {
		if key.Names(name) && key.Type == keyType {
			return key
		}
	}
	t.Fatalf("no %s key for %s", keyType, name)

	return gitsource.HostKey{}
}

// lineFor rewrites a provider's key line so it names host instead.
func lineFor(key gitsource.HostKey, host string) string {
	return host + " " + strings.SplitN(key.Line, " ", 2)[1]
}

func TestRemoveHostKeysRewritesTheFileAsTheSiteUser(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}

	trusted := providerKey(t, "github.com", "ssh-ed25519")
	other := lineFor(providerKey(t, "gitlab.com", "ssh-ed25519"), "gitea.example.org")
	f.store.AddHostKey("abcdefghijkl", lineFor(trusted, selfHosted))
	f.store.AddHostKey("abcdefghijkl", other)

	exec := &systemtest.Fake{}
	user := system.User{Name: "serverdog", UID: 4242, GID: 4343}
	f.manager.Exec, f.manager.AsUser = exec, true
	f.manager.LookupUser = func(string) (system.User, error) { return user, nil }
	f.system.Reset()

	removed, err := f.manager.RemoveHostKeys(ctx, "abcdefghijkl", selfHosted, trusted.Fingerprint, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(removed, []string{trusted.Fingerprint}) {
		t.Errorf("removed = %v", removed)
	}

	if lines, _ := f.store.HostKeys("abcdefghijkl"); !slices.Equal(lines, []string{other}) {
		t.Errorf("rows = %v, want only the other host's key", lines)
	}

	calls := exec.Calls()
	if len(calls) != 1 || calls[0].Name != "sh" || calls[0].User == nil || !reflect.DeepEqual(*calls[0].User, user) {
		t.Fatalf("file writes = %v", exec.Commands())
	}
	if path := calls[0].Args[3]; path != f.file("/home/serverdog/.ssh/serverdog-abcdefghijkl.known_hosts") {
		t.Errorf("wrote %s", path)
	}
	if content, _ := io.ReadAll(calls[0].Stdin); string(content) != "# Managed by ServerDog.\n"+other+"\n" {
		t.Errorf("known_hosts = %q", content)
	}

	if commands := f.system.Commands(); len(commands) != 0 {
		t.Errorf("ran as root: %v", commands)
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	summary := "Removed the trusted host key " + trusted.Fingerprint + " for [git.example.com]:2222."
	if len(activity) != 1 || activity[0].Kind != "hostkey.removed" || activity[0].Actor != "Mac" || activity[0].Summary != summary {
		t.Errorf("activity = %+v", activity)
	}
}

func TestRemoveHostKeysRefusalsChangeNothing(t *testing.T) {
	trusted := providerKey(t, "github.com", "ssh-ed25519")

	cases := map[string]struct {
		host, fingerprint string
		deploying         bool
		want              error
	}{
		"wrong fingerprint":    {host: selfHosted, fingerprint: "SHA256:somethingelse", want: ErrHostKeyMoved},
		"no key the site owns": {host: "github.com", fingerprint: trusted.Fingerprint, want: ErrNoHostKey},
		"deploy running":       {host: selfHosted, fingerprint: trusted.Fingerprint, deploying: true, want: state.ErrDeployRunning},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
				t.Fatal(err)
			}
			line := lineFor(trusted, selfHosted)
			f.store.AddHostKey("abcdefghijkl", line)
			if err := f.manager.RefreshKnownHosts(ctx, "abcdefghijkl"); err != nil {
				t.Fatal(err)
			}
			if c.deploying {
				f.store.CreateDeployment(state.Deployment{ID: "dddddddddddd", SiteID: "abcdefghijkl", Kind: state.KindDeploy, State: state.Running, Actor: "Mac", StartedAt: time.Now()})
			}

			if _, err := f.manager.RemoveHostKeys(ctx, "abcdefghijkl", c.host, c.fingerprint, "Mac"); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}

			if lines, _ := f.store.HostKeys("abcdefghijkl"); !slices.Equal(lines, []string{line}) {
				t.Errorf("rows = %v", lines)
			}
			if content, _ := os.ReadFile(f.file("/home/serverdog/.ssh/serverdog-abcdefghijkl.known_hosts")); string(content) != "# Managed by ServerDog.\n"+line+"\n" {
				t.Errorf("known_hosts = %q", content)
			}
			if activity, _ := f.store.ListActivity("abcdefghijkl", 1); len(activity) != 1 || activity[0].Kind != "site.created" {
				t.Errorf("activity = %+v", activity)
			}
		})
	}
}

func TestRemoveHostKeysBeforeTheSiteExistsRewritesThePendingFile(t *testing.T) {
	f := newFixture(t)
	trusted := providerKey(t, "github.com", "ssh-ed25519")
	f.store.AddHostKey("abcdefghijkl", lineFor(trusted, selfHosted))
	if err := f.manager.RefreshKnownHosts(ctx, "abcdefghijkl"); err != nil {
		t.Fatal(err)
	}

	if _, err := f.manager.RemoveHostKeys(ctx, "abcdefghijkl", selfHosted, trusted.Fingerprint, "Mac"); err != nil {
		t.Fatal(err)
	}

	if content, _ := os.ReadFile(f.manager.Keys.PendingKnownHostsPath("abcdefghijkl")); string(content) != "# Managed by ServerDog.\n" {
		t.Errorf("pending known_hosts = %q", content)
	}
	if lines, _ := f.store.HostKeys("abcdefghijkl"); len(lines) != 0 {
		t.Errorf("rows = %v", lines)
	}
	if activity, _ := f.store.ListActivity("abcdefghijkl", 10); len(activity) != 0 {
		t.Errorf("activity for a site not created yet: %+v", activity)
	}
}

func TestRemoveHostKeysDropsEveryKeyForTheHost(t *testing.T) {
	f := newFixture(t)
	if _, _, err := f.manager.Put(ctx, laravel(), 0, "Mac"); err != nil {
		t.Fatal(err)
	}
	ed25519 := providerKey(t, "github.com", "ssh-ed25519")
	ecdsa := providerKey(t, "github.com", "ecdsa-sha2-nistp256")
	f.store.AddHostKey("abcdefghijkl", lineFor(ed25519, selfHosted))
	f.store.AddHostKey("abcdefghijkl", lineFor(ecdsa, selfHosted))

	removed, err := f.manager.RemoveHostKeys(ctx, "abcdefghijkl", selfHosted, ecdsa.Fingerprint, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 2 || !slices.Contains(removed, ed25519.Fingerprint) || !slices.Contains(removed, ecdsa.Fingerprint) {
		t.Errorf("removed = %v", removed)
	}
	if lines, _ := f.store.HostKeys("abcdefghijkl"); len(lines) != 0 {
		t.Errorf("rows = %v", lines)
	}
	if activity, _ := f.store.ListActivity("abcdefghijkl", 1); len(activity) != 1 || !strings.HasPrefix(activity[0].Summary, "Removed the trusted host keys SHA256:") {
		t.Errorf("activity = %+v", activity)
	}
}
