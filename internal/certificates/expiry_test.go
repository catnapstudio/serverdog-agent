package certificates

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestExpiryWatcherPostsEachStageOnceAndTheRenewal(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	cert := state.Certificate{
		ID: "c1", SiteID: "s1", Domain: "example.com", Source: state.CertLetsEncrypt, Names: []string{"example.com"},
		Status: state.CertRenewalFailing, Active: true, Error: "The domain doesn't reach this server.\n\nDetails",
		NotBefore: now.Add(-80 * 24 * time.Hour), NotAfter: now.Add(10 * 24 * time.Hour), CreatedAt: now,
	}
	if err := store.CreateCertificate(cert); err != nil {
		t.Fatal(err)
	}
	// Not served, so never posted.
	inactive := cert
	inactive.ID, inactive.Active = "c2", false
	if err := store.CreateCertificate(inactive); err != nil {
		t.Fatal(err)
	}

	var posts []string
	watcher := func() *ExpiryWatcher {
		return &ExpiryWatcher{
			Store: store, Host: func() string { return "web-1" }, Now: func() time.Time { return now },
			Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Post:   func(_ context.Context, text string) error { posts = append(posts, text); return nil },
		}
	}
	check := func(want string) {
		t.Helper()
		before := len(posts)
		watcher().Check(context.Background()) // a new watcher each time: what was posted survives a restart
		got := posts[before:]
		if want == "" && len(got) != 0 || want != "" && (len(got) != 1 || !strings.Contains(got[0], want)) {
			t.Fatalf("posted %q, want one containing %q", got, want)
		}
	}

	check("expires in 10 days (24 Nov 2026). It isn't renewing: The domain doesn't reach this server.")
	check("")

	now = now.Add(8 * 24 * time.Hour)
	check("expires in 2 days")
	check("")

	now = now.Add(3 * 24 * time.Hour)
	check("expired on 24 Nov 2026")
	check("")

	if _, err := store.UpdateCertificate("c1", func(c *state.Certificate) {
		c.Status, c.Error, c.NotAfter = state.CertIssued, "", now.Add(90*24*time.Hour)
	}); err != nil {
		t.Fatal(err)
	}
	check("was renewed and is valid until")
	check("")
}
