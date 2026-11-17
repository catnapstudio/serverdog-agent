package state

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func certificate(id, siteID, domain string) Certificate {
	return Certificate{
		ID: id, SiteID: siteID, Domain: domain, Source: CertLetsEncrypt, KeyType: "ecdsaP256",
		Names: []string{domain, "www." + domain}, Status: CertWaitingForDNS, CreatedAt: now,
		NextAttempt: now, WaitingSince: now,
	}
}

func TestCertificateRoundTrip(t *testing.T) {
	store := open(t)

	if err := store.CreateCertificate(certificate("c1", "s1", "a.com")); err != nil {
		t.Fatal(err)
	}

	updated, err := store.UpdateCertificate("c1", func(c *Certificate) {
		c.Status, c.Issuer = CertIssued, "R11"
		c.NotBefore, c.NotAfter = now, now.Add(90*24*time.Hour)
		c.NextAttempt = time.Time{}
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := store.GetCertificate("c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != CertIssued || got.Issuer != "R11" || !got.NotAfter.Equal(updated.NotAfter) || !got.NextAttempt.IsZero() || !slices.Equal(got.Names, []string{"a.com", "www.a.com"}) {
		t.Errorf("got = %+v", got)
	}
	if !got.Usable() {
		t.Error("an issued certificate isn't usable")
	}

	if _, err := store.GetCertificate("missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing err = %v", err)
	}
}

func TestOneActiveCertificatePerDomain(t *testing.T) {
	store := open(t)
	store.CreateCertificate(certificate("c1", "s1", "a.com"))
	store.CreateCertificate(certificate("c2", "s1", "a.com"))
	store.CreateCertificate(certificate("c3", "s1", "b.com"))

	if err := store.SetActiveCertificate("s1", "a.com", "c1"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveCertificate("s1", "b.com", "c3"); err != nil {
		t.Fatal(err)
	}
	if err := store.SetActiveCertificate("s1", "a.com", "c2"); err != nil {
		t.Fatal(err)
	}

	list, _ := store.ListCertificates("s1")
	active := map[string]bool{}
	for _, c := range list {
		active[c.ID] = c.Active
	}
	if active["c1"] || !active["c2"] || !active["c3"] {
		t.Errorf("active = %v", active)
	}

	if err := store.SetActiveCertificate("s1", "a.com", ""); err != nil {
		t.Fatal(err)
	}
	if c, _ := store.GetCertificate("c2"); c.Active {
		t.Error("clearing left c2 active")
	}
}

func TestDueCertificates(t *testing.T) {
	store := open(t)

	soon := certificate("soon", "s1", "a.com")
	soon.NextAttempt = now.Add(time.Minute)
	past := certificate("past", "s1", "b.com")
	past.NextAttempt = now.Add(-time.Minute)
	idle := certificate("idle", "s1", "c.com")
	idle.NextAttempt = time.Time{}

	for _, c := range []Certificate{soon, past, idle} {
		if err := store.CreateCertificate(c); err != nil {
			t.Fatal(err)
		}
	}

	due, err := store.DueCertificates(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(due) != 1 || due[0].ID != "past" {
		t.Errorf("due = %+v", due)
	}

	issuing, _ := store.CertificatesWithStatus(CertWaitingForDNS)
	if len(issuing) != 3 {
		t.Errorf("by status = %d", len(issuing))
	}
}

func TestDeleteSiteDataRemovesCertificates(t *testing.T) {
	store := open(t)
	store.PutSite(sample("aaaaaaaaaaaa", "a.com"), 0, now)
	store.CreateCertificate(certificate("c1", "aaaaaaaaaaaa", "a.com"))

	if err := store.DeleteSiteData("aaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetCertificate("c1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("certificate survived: %v", err)
	}

	if err := store.DeleteCertificate("missing"); err != nil {
		t.Errorf("deleting a missing certificate: %v", err)
	}
}
