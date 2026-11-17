package state

import (
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestActivityNewestFirst(t *testing.T) {
	store := open(t)

	store.AddActivity("s1", Activity{At: now, Kind: "site.created", Actor: "Mac", Summary: "Created"})
	store.AddActivity("s1", Activity{At: now.Add(time.Minute), Kind: "deploy.succeeded", Actor: "Mac", Summary: "Deployed abc"})
	store.AddActivity("s2", Activity{At: now, Kind: "site.created", Actor: "Mac", Summary: "Other"})

	entries, err := store.ListActivity("s1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Kind != "deploy.succeeded" {
		t.Errorf("entries = %+v", entries)
	}
}

func TestHostKeysAreDeduplicated(t *testing.T) {
	store := open(t)

	store.AddHostKey("s1", "git.example.com ssh-ed25519 AAAA")
	store.AddHostKey("s1", "git.example.com ssh-ed25519 AAAA")

	keys, err := store.HostKeys("s1")
	if err != nil || len(keys) != 1 {
		t.Errorf("keys = %v %v", keys, err)
	}
}

func TestRemoveHostKeysDeletesOnlyTheGivenLines(t *testing.T) {
	store := open(t)

	store.AddHostKey("s1", "[git.example.com]:2222 ssh-ed25519 AAAA")
	store.AddHostKey("s1", "gitea.example.org ssh-ed25519 BBBB")
	store.AddHostKey("s2", "[git.example.com]:2222 ssh-ed25519 AAAA")

	if err := store.RemoveHostKeys("s1", []string{"[git.example.com]:2222 ssh-ed25519 AAAA"}); err != nil {
		t.Fatal(err)
	}

	if keys, _ := store.HostKeys("s1"); len(keys) != 1 || keys[0] != "gitea.example.org ssh-ed25519 BBBB" {
		t.Errorf("s1 keys = %v", keys)
	}
	if keys, _ := store.HostKeys("s2"); len(keys) != 1 {
		t.Errorf("another site's key went: %v", keys)
	}
}

func TestNodePortsAreStableAndDistinct(t *testing.T) {
	store := open(t)

	first, err := store.NodePorts("s1")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := store.NodePorts("s1")
	other, _ := store.NodePorts("s2")

	if first != again {
		t.Errorf("ports changed: %v then %v", first, again)
	}
	if first[0] != 20000 || first[1] != 20001 || other[0] != 20002 {
		t.Errorf("ports = %v and %v", first, other)
	}

	if live, _ := store.LivePort("s1"); live != 0 {
		t.Errorf("live before any deploy = %d", live)
	}
	store.SetLivePort("s1", first[1])
	if live, _ := store.LivePort("s1"); live != first[1] {
		t.Errorf("live = %d", live)
	}
}

func TestOpenMigratesAFoundationDatabase(t *testing.T) {
	dir := t.TempDir()

	legacy, err := sql.Open("sqlite", filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE agent_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, started_at TEXT NOT NULL);
INSERT INTO meta VALUES ('installed_at', '2026-10-01T12:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	installed, err := store.InstalledAt()
	if err != nil || installed.Year() != 2026 {
		t.Errorf("installed = %v %v", installed, err)
	}
	if _, err := store.ListSites(); err != nil {
		t.Errorf("sites table missing: %v", err)
	}
}

func TestConcurrentOpensMigrateOnce(t *testing.T) {
	foundation := func(t *testing.T) string {
		dir := t.TempDir()

		legacy, err := sql.Open("sqlite", filepath.Join(dir, "state.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer legacy.Close()

		if _, err := legacy.Exec(`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE agent_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, version TEXT NOT NULL, started_at TEXT NOT NULL);`); err != nil {
			t.Fatal(err)
		}

		return dir
	}

	cases := map[string]func(*testing.T) string{
		"fresh":      func(t *testing.T) string { return t.TempDir() },
		"foundation": foundation,
	}

	for name, prepare := range cases {
		t.Run(name, func(t *testing.T) {
			dir := prepare(t)

			const openers = 6
			errs := make(chan error, openers)
			stores := make(chan *Store, openers)

			var wg sync.WaitGroup
			for range openers {
				wg.Add(1)
				go func() {
					defer wg.Done()

					store, err := Open(dir)
					if err != nil {
						errs <- err
						return
					}
					if _, err := store.ListSites(); err != nil {
						errs <- err
					}
					stores <- store
				}()
			}
			wg.Wait()
			close(errs)
			close(stores)

			for store := range stores {
				store.Close()
			}
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

// Deployments recorded before the script snapshot existed read back with no script; the runner then reads the site's.
func TestOpenMigratesDeploymentsWithoutAScript(t *testing.T) {
	dir := t.TempDir()

	legacy, err := sql.Open("sqlite", filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations[:3] {
		if _, err := legacy.Exec(migration); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := legacy.Exec(`PRAGMA user_version = 3;
INSERT INTO deployments(id, site_id, kind, state, actor, started_at) VALUES ('d1', 's1', 'deploy', 'running', 'Mac', '2026-10-18T12:00:00.000000000Z');`); err != nil {
		t.Fatal(err)
	}
	legacy.Close()

	store, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	old, err := store.GetDeployment("d1")
	if err != nil || old.Script != "" || old.State != Running {
		t.Errorf("old deployment = %+v %v", old, err)
	}
}
