package meilisearch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func setup(t *testing.T, handler http.HandlerFunc) (*Manager, *systemtest.Fake, string) {
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := "MEILI_ENV=production\nMEILI_HTTP_ADDR=" + strings.TrimPrefix(server.URL, "http://") + "\nMEILI_DB_PATH=/var/lib/meilisearch/data\nMEILI_MASTER_KEY=abc123\n"
	if err := os.WriteFile(filepath.Join(root, "etc/meilisearch.env"), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}

	fake := &systemtest.Fake{}
	return &Manager{Paths: paths.Paths{Root: root}, Runner: fake, StartWait: 300 * time.Millisecond}, fake, root
}

func healthy(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestConfigHidesTheManagedLinesAndSavingKeepsThem(t *testing.T) {
	m, fake, root := setup(t, healthy)

	config, err := m.Config()
	if err != nil {
		t.Fatal(err)
	}
	if config != "MEILI_ENV=production\nMEILI_DB_PATH=/var/lib/meilisearch/data\n" {
		t.Fatalf("config = %q", config)
	}

	if err := m.PutConfig(context.Background(), "# search\nMEILI_ENV=production\nMEILI_MAX_INDEXING_MEMORY=2 GiB\n"); err != nil {
		t.Fatal(err)
	}

	saved, _ := os.ReadFile(filepath.Join(root, "etc/meilisearch.env"))
	if !strings.HasPrefix(string(saved), "# search\nMEILI_ENV=production\nMEILI_MAX_INDEXING_MEMORY=2 GiB\nMEILI_HTTP_ADDR=") || !strings.HasSuffix(string(saved), "MEILI_MASTER_KEY=abc123\n") {
		t.Errorf("saved:\n%s", saved)
	}
	if info, _ := os.Stat(filepath.Join(root, "etc/meilisearch.env")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	if got := strings.Join(fake.Commands(), "\n"); !strings.Contains(got, "systemctl restart meilisearch") {
		t.Errorf("commands:\n%s", got)
	}
}

func TestPutConfigRefusesManagedAndMalformedLines(t *testing.T) {
	m, fake, _ := setup(t, healthy)

	var invalid *site.InvalidError
	for _, config := range []string{"MEILI_MASTER_KEY=mine\n", "MEILI_HTTP_ADDR=0.0.0.0:7700\n", "rm -rf /\n", "PATH=/tmp\n"} {
		if err := m.PutConfig(context.Background(), config); !errors.As(err, &invalid) {
			t.Errorf("%q: err = %v", config, err)
		}
	}
	if len(fake.Commands()) != 0 {
		t.Errorf("restarted on a refused config: %v", fake.Commands())
	}
}

func TestPutConfigRestoresThePreviousFileWhenMeilisearchDoesNotAnswer(t *testing.T) {
	var up atomic.Bool
	m, fake, root := setup(t, func(w http.ResponseWriter, _ *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	before, _ := os.ReadFile(filepath.Join(root, "etc/meilisearch.env"))

	err := m.PutConfig(context.Background(), "MEILI_ENV=nonsense\n")
	if err == nil || !strings.Contains(err.Error(), "previous ones are back") {
		t.Fatalf("err = %v", err)
	}

	after, _ := os.ReadFile(filepath.Join(root, "etc/meilisearch.env"))
	if string(after) != string(before) {
		t.Errorf("not restored:\n%s", after)
	}
	if n := strings.Count(strings.Join(fake.Commands(), "\n"), "systemctl restart meilisearch"); n != 2 {
		t.Errorf("restarts = %d", n)
	}
}

func TestKeysAreReadWithTheMasterKey(t *testing.T) {
	m, _, _ := setup(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/keys" || r.Header.Get("Authorization") != "Bearer abc123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"results":[{"name":"Default Search API Key","description":"Use it to search","key":"s3arch","actions":["search"],"indexes":["*"],"expiresAt":null}]}`))
	})

	keys, err := m.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Name != "Default Search API Key" || keys[0].Key != "s3arch" || keys[0].Actions[0] != "search" || keys[0].ExpiresAt != "" {
		t.Errorf("keys = %+v", keys)
	}
}

func TestNoMeilisearch(t *testing.T) {
	m := &Manager{Paths: paths.Paths{Root: t.TempDir()}, Runner: &systemtest.Fake{}}

	var invalid *site.InvalidError
	if _, err := m.Config(); !errors.As(err, &invalid) || m.Installed() {
		t.Errorf("err = %v", err)
	}
}
