package backups

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	m := &Manager{Store: store, Paths: paths.Paths{Root: root}, Applier: apply.Applier{Runner: &systemtest.Fake{}, LockPath: filepath.Join(root, "apply.lock")}}

	return m, filepath.Join(root, paths.BackupsCron)
}

func nightly() Plan {
	return Plan{
		ID: "nightlynight", Name: "Nightly", Databases: []string{"orchard"}, Schedule: "0 3 * * *", Keep: 7,
		Storage: Storage{Endpoint: "s3.eu-central-1.amazonaws.com", Region: "eu-central-1", Bucket: "acme-backups", Prefix: "app", AccessKey: "AKIA", SecretKey: "s3cret"},
	}
}

func TestAPlanSavedWithoutItsSecretKeepsIt(t *testing.T) {
	m, cron := newManager(t)

	if _, err := m.Put(context.Background(), []Plan{nightly()}, 0); err != nil {
		t.Fatal(err)
	}

	changed := nightly()
	changed.Storage.SecretKey, changed.Keep = "", 3
	if _, err := m.Put(context.Background(), []Plan{changed}, 1); err != nil {
		t.Fatal(err)
	}

	plan, err := m.Get("nightlynight")
	if err != nil || plan.Storage.SecretKey != "s3cret" || plan.Keep != 3 {
		t.Errorf("plan = %+v, %v", plan, err)
	}

	content, _ := os.ReadFile(cron)
	if !strings.Contains(string(content), "0 3 * * * root /usr/local/bin/serverdog-agent run-backup nightlynight >/dev/null 2>&1\n") {
		t.Errorf("cron =\n%s", content)
	}

	if _, err := m.Put(context.Background(), nil, 1); err == nil {
		t.Error("a stale revision was accepted")
	}
}

func TestInvalidPlansAreRefused(t *testing.T) {
	cases := map[string]func(*Plan){
		"no databases":       func(p *Plan) { p.Databases = nil },
		"database injection": func(p *Plan) { p.Databases = []string{"app; rm -rf /"} },
		"option database":    func(p *Plan) { p.Databases = []string{"--all-databases x"} },
		"at boot":            func(p *Plan) { p.Schedule = "@reboot" },
		"keep none":          func(p *Plan) { p.Keep = 0 },
		"plain http":         func(p *Plan) { p.Storage.Endpoint = "http://s3.example.com" },
		"ftp":                func(p *Plan) { p.Storage.Endpoint = "ftp://s3.example.com" },
		"endpoint path":      func(p *Plan) { p.Storage.Endpoint = "https://s3.example.com/bucket" },
		"bucket":             func(p *Plan) { p.Storage.Bucket = "Acme" },
		"leading slash":      func(p *Plan) { p.Storage.Prefix = "/app" },
		"dot dot":            func(p *Plan) { p.Storage.Prefix = "app/../x" },
		"no secret":          func(p *Plan) { p.Storage.SecretKey = "" },
	}

	for name, change := range cases {
		m, cron := newManager(t)
		plan := nightly()
		change(&plan)

		if _, err := m.Put(context.Background(), []Plan{plan}, 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(cron); !os.IsNotExist(err) {
			t.Errorf("%s: wrote cron", name)
		}
	}

	for _, accepted := range []string{"https://abc.r2.cloudflarestorage.com", "http://127.0.0.1:9000", "http://localhost:9000", "s3.us-west-002.backblazeb2.com"} {
		if _, _, err := endpoint(accepted); err != nil {
			t.Errorf("%s refused: %v", accepted, err)
		}
	}
}
