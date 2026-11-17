package state

import (
	"errors"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

var now = time.Date(2026, 10, 16, 18, 0, 0, 0, time.UTC)

func open(t *testing.T) *Store {
	t.Helper()

	store, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	return store
}

func sample(id string, domains ...string) site.Site {
	s := site.Site{ID: id, Runtime: site.Static, User: site.DefaultUser, Directory: "/home/serverdog/" + domains[0]}
	for i, name := range domains {
		s.Domains = append(s.Domains, site.Domain{Name: name, Redirect: site.FromWWW, Primary: i == 0})
	}

	return s
}

func TestPutSiteCreatesThenUpdatesWithRevisions(t *testing.T) {
	store := open(t)

	created, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now)
	if err != nil {
		t.Fatal(err)
	}
	if created.Revision != 1 || !created.CreatedAt.Equal(now) {
		t.Errorf("created = rev %d at %v", created.Revision, created.CreatedAt)
	}

	if _, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now); !errors.Is(err, ErrStaleRevision) {
		t.Errorf("second create err = %v, want ErrStaleRevision", err)
	}

	changed := created
	changed.Branch = "develop"
	updated, err := store.PutSite(changed, 1, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || !updated.CreatedAt.Equal(now) {
		t.Errorf("updated = rev %d created %v", updated.Revision, updated.CreatedAt)
	}

	got, err := store.GetSite("aaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	if got.Branch != "develop" {
		t.Errorf("branch = %q", got.Branch)
	}
}

func TestPutSiteRejectsADomainOwnedByAnotherSite(t *testing.T) {
	store := open(t)

	if _, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now); err != nil {
		t.Fatal(err)
	}

	_, err := store.PutSite(sample("bbbbbbbbbbbb", "b.com", "a.com"), 0, now)

	var taken *DomainTakenError
	if !errors.As(err, &taken) || taken.Name != "a.com" || taken.SiteID != "aaaaaaaaaaaa" {
		t.Fatalf("err = %v", err)
	}

	if _, err := store.GetSite("bbbbbbbbbbbb"); !errors.Is(err, ErrNotFound) {
		t.Errorf("rejected site was stored: %v", err)
	}
}

func TestRemovingADomainFreesIt(t *testing.T) {
	store := open(t)

	s, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com", "old.com"), 0, now)
	if err != nil {
		t.Fatal(err)
	}

	s.Domains = s.Domains[:1]
	if _, err := store.PutSite(s, s.Revision, now); err != nil {
		t.Fatal(err)
	}

	if _, err := store.PutSite(sample("bbbbbbbbbbbb", "old.com"), 0, now); err != nil {
		t.Errorf("freed domain still taken: %v", err)
	}
}

func TestUpdateSiteBumpsRevision(t *testing.T) {
	store := open(t)

	if _, err := store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now); err != nil {
		t.Fatal(err)
	}

	updated, err := store.UpdateSite("aaaaaaaaaaaa", func(s *site.Site) { s.NginxCustomised = true }, now)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.NginxCustomised || updated.Revision != 2 {
		t.Errorf("updated = %+v", updated)
	}
}

func TestListAndDeleteSites(t *testing.T) {
	store := open(t)

	store.PutSite(sample("bbbbbbbbbbbb", "b.com"), 0, now)
	store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now.Add(time.Second))

	sites, err := store.ListSites()
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 2 || sites[0].ID != "bbbbbbbbbbbb" {
		t.Errorf("sites = %+v (want creation order)", sites)
	}

	if err := store.DeleteSiteData("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.DomainOwner("a.com"); ok {
		t.Error("deleted site's domain is still owned")
	}
}
