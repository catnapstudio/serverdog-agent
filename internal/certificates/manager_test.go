package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestANewDomainWaitsForLetsEncrypt(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	list := f.certificates("abcdefghijkl")
	if len(list) != 1 {
		t.Fatalf("certificates = %+v", list)
	}

	c := list[0]
	if c.Source != state.CertLetsEncrypt || c.Status != state.CertWaitingForDNS || c.KeyType != "ecdsaP256" ||
		!slices.Equal(c.Names, []string{"orchard.com", "www.orchard.com"}) || !c.NextAttempt.Equal(f.clock()) || !c.WaitingSince.Equal(f.clock()) {
		t.Errorf("certificate = %+v", c)
	}

	select {
	case <-f.manager.kicks():
	default:
		t.Error("the scheduler wasn't woken")
	}

	more := laravel()
	more.Domains = append(more.Domains, site.Domain{Name: "orchard.dev", Redirect: site.NoRedirect})
	f.put(more)

	if list := f.certificates("abcdefghijkl"); len(list) != 2 {
		t.Errorf("after adding a domain: %+v", list)
	}
}

func TestDeletingTheOnlyCertificateDoesNotBringItBack(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	if err := f.manager.Delete(ctx, f.certificates("abcdefghijkl")[0].ID, "Mac"); err != nil {
		t.Fatal(err)
	}

	changed := laravel()
	changed.WebDirectory = "web"
	f.put(changed)

	if list := f.certificates("abcdefghijkl"); len(list) != 0 {
		t.Errorf("certificates = %+v", list)
	}
}

func TestRemovingADomainDeletesItsCertificates(t *testing.T) {
	f := newFixture(t)
	two := laravel()
	two.Domains = append(two.Domains, site.Domain{Name: "orchard.dev", Redirect: site.NoRedirect})
	f.put(two)
	uploaded := f.upload("abcdefghijkl", "orchard.dev", "orchard.dev")

	f.put(laravel())

	for _, c := range f.certificates("abcdefghijkl") {
		if c.Domain == "orchard.dev" {
			t.Errorf("left behind: %+v", c)
		}
	}
	if _, err := os.Lstat(f.file(paths.CertificateDir("abcdefghijkl", uploaded.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("certificate files: %v", err)
	}
	if _, err := os.Lstat(f.file("/etc/serverdog/certs/abcdefghijkl/orchard.dev")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("active link directory: %v", err)
	}
}

func TestChangingTheRedirectRequestsTheNewNames(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.advance(time.Hour)

	changed := laravel()
	changed.Domains[0].Redirect = site.NoRedirect
	f.put(changed)

	c := f.certificates("abcdefghijkl")[0]
	if !slices.Equal(c.Names, []string{"orchard.com"}) || !c.NextAttempt.Equal(f.clock()) {
		t.Errorf("certificate = %+v", c)
	}
}

func TestSigningRequestThenInstall(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	request, csrPEM, err := f.manager.CreateSigningRequest(ctx, "abcdefghijkl", "orchard.com", certs.RSA2048, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if request.Status != state.CertAwaitingCertificate || request.Source != state.CertSigningRequest || request.KeyType != "rsa2048" {
		t.Errorf("request = %+v", request)
	}
	if info, err := os.Stat(certs.KeyFile(f.manager.Paths, "abcdefghijkl", request.ID)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", info, err)
	}
	if info, err := os.Stat(f.file(paths.CertificateDir("abcdefghijkl", request.ID))); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("certificate directory: %v %v", info, err)
	}

	leafPEM, caPEM := signCSR(t, csrPEM, f.clock())
	installed, err := f.manager.Install(ctx, "abcdefghijkl", "orchard.com", request.ID, Upload{Certificate: leafPEM, Chain: caPEM}, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	if installed.ID != request.ID || installed.Status != state.CertIssued || !installed.Active || installed.Issuer != "ServerDog Test CA" {
		t.Errorf("installed = %+v", installed)
	}

	config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl")))
	if !strings.Contains(string(config), "ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;") {
		t.Errorf("config:\n%s", config)
	}
	if target, _ := os.Readlink(f.file(paths.ActiveCertificateDir("abcdefghijkl", "orchard.com"))); target != "../"+request.ID {
		t.Errorf("active link = %q", target)
	}
}

func TestInstallRefusesACertificateForAnotherKey(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	request, _, _ := f.manager.CreateSigningRequest(ctx, "abcdefghijkl", "orchard.com", certs.ECDSAP256, "Mac")

	otherKey, _, _ := certs.GenerateKey(certs.ECDSAP256)
	otherCSR, _ := certs.CreateCSR(otherKey, []string{"orchard.com", "www.orchard.com"})
	leafPEM, caPEM := signCSR(t, otherCSR, f.clock())

	_, err := f.manager.Install(ctx, "abcdefghijkl", "orchard.com", request.ID, Upload{Certificate: leafPEM, Chain: caPEM}, "Mac")

	var invalid *site.InvalidError
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v", err)
	}
	if c, _ := f.store.GetCertificate(request.ID); c.Status != state.CertAwaitingCertificate {
		t.Errorf("request = %+v", c)
	}
}

func TestInstallNeedsAKeyAndCoverage(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	fullchain, key, _ := selfSigned(t, []string{"orchard.com"}, f.clock().Add(-time.Hour), 24*time.Hour)

	var invalid *site.InvalidError
	if _, err := f.manager.Install(ctx, "abcdefghijkl", "orchard.com", "", Upload{Certificate: fullchain}, "Mac"); !errors.As(err, &invalid) || invalid.Field != "privateKey" {
		t.Errorf("without a key: %v", err)
	}
	if _, err := f.manager.Install(ctx, "abcdefghijkl", "orchard.com", "", Upload{Certificate: fullchain, PrivateKey: key}, "Mac"); !errors.As(err, &invalid) || !strings.Contains(invalid.Reason, "www.orchard.com") {
		t.Errorf("without www: %v", err)
	}
	if _, err := f.manager.Install(ctx, "abcdefghijkl", "other.com", "", Upload{Certificate: fullchain, PrivateKey: key}, "Mac"); !errors.As(err, &invalid) || invalid.Field != "domain" {
		t.Errorf("another domain: %v", err)
	}
}

func TestUploadsActivateOnlyTheFirstAndActivateSwitches(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	first := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")
	second := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")
	if !first.Active || second.Active || first.Source != state.CertUploaded || first.KeyType != "ecdsaP256" {
		t.Fatalf("first = %+v, second = %+v", first, second)
	}

	activated, err := f.manager.Activate(ctx, second.ID, "Mac")
	if err != nil || !activated.Active {
		t.Fatalf("Activate = %+v %v", activated, err)
	}
	if again, _ := f.store.GetCertificate(first.ID); again.Active {
		t.Error("the first certificate is still active")
	}
	if target, _ := os.Readlink(f.file(paths.ActiveCertificateDir("abcdefghijkl", "orchard.com"))); target != "../"+second.ID {
		t.Errorf("active link = %q", target)
	}
}

func TestActivateNeedsAUsableCertificate(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	waiting := f.certificates("abcdefghijkl")[0]

	var invalid *site.InvalidError
	if _, err := f.manager.Activate(ctx, waiting.ID, "Mac"); !errors.As(err, &invalid) {
		t.Errorf("err = %v", err)
	}
}

func TestCloneCopiesAnotherSitesCertificate(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	source := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com", "orchard.dev")

	other := laravel()
	other.ID = "mnopqrstuvwx"
	other.Domains = []site.Domain{{Name: "orchard.dev", Redirect: site.NoRedirect, Primary: true}}
	f.put(other)

	clone, err := f.manager.Clone(ctx, "mnopqrstuvwx", "orchard.dev", source.ID, "Mac")
	if err != nil {
		t.Fatal(err)
	}
	if clone.Source != state.CertCloned || !clone.Active || clone.SiteID != "mnopqrstuvwx" || !clone.NotAfter.Equal(source.NotAfter) {
		t.Errorf("clone = %+v", clone)
	}

	original, _ := os.ReadFile(certs.FullchainFile(f.manager.Paths, "abcdefghijkl", source.ID))
	copied, _ := os.ReadFile(certs.FullchainFile(f.manager.Paths, "mnopqrstuvwx", clone.ID))
	if string(original) != string(copied) {
		t.Error("the clone's files differ")
	}
}

func TestCloneRefusesACertificateThatDoesNotCoverTheDomain(t *testing.T) {
	f := newFixture(t)
	two := laravel()
	two.Domains = append(two.Domains, site.Domain{Name: "orchard.dev", Redirect: site.NoRedirect})
	f.put(two)
	source := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")

	var invalid *site.InvalidError
	if _, err := f.manager.Clone(ctx, "abcdefghijkl", "orchard.dev", source.ID, "Mac"); !errors.As(err, &invalid) || !strings.Contains(invalid.Reason, "orchard.dev") {
		t.Errorf("err = %v", err)
	}
}

func TestDeletingTheActiveCertificateTurnsHTTPSOff(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	active := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")

	if err := f.manager.Delete(ctx, active.ID, "Mac"); err != nil {
		t.Fatal(err)
	}

	config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl")))
	if strings.Contains(string(config), "listen 443") {
		t.Errorf("config still serves HTTPS:\n%s", config)
	}
	if _, err := os.Lstat(f.file(paths.ActiveCertificateDir("abcdefghijkl", "orchard.com"))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("active link: %v", err)
	}
	if _, err := os.Lstat(f.file(paths.CertificateDir("abcdefghijkl", active.ID))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("files: %v", err)
	}
	if _, err := f.store.GetCertificate(active.ID); !errors.Is(err, state.ErrNotFound) {
		t.Errorf("row: %v", err)
	}
}

func TestRequestLetsEncryptRetriesAWaitingRequest(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	waiting := f.certificates("abcdefghijkl")[0]
	f.store.UpdateCertificate(waiting.ID, func(c *state.Certificate) { c.NextAttempt = f.clock().Add(10 * time.Minute) })
	<-f.manager.kicks()
	f.advance(time.Minute)

	c, err := f.manager.RequestLetsEncrypt(ctx, "abcdefghijkl", "orchard.com", certs.RSA2048, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	if c.ID != waiting.ID || !c.NextAttempt.Equal(f.clock()) || c.KeyType != "rsa2048" {
		t.Errorf("certificate = %+v", c)
	}
	if len(f.certificates("abcdefghijkl")) != 1 {
		t.Error("a second request was added")
	}
	select {
	case <-f.manager.kicks():
	default:
		t.Error("the scheduler wasn't woken")
	}
}

func TestRequestLetsEncryptAddsARequestBesideAnIssuedCertificate(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Delete(ctx, f.certificates("abcdefghijkl")[0].ID, "Mac")
	f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")

	c, err := f.manager.RequestLetsEncrypt(ctx, "abcdefghijkl", "orchard.com", certs.ECDSAP256, "Mac")
	if err != nil || c.Status != state.CertWaitingForDNS || c.Active {
		t.Errorf("RequestLetsEncrypt = %+v %v", c, err)
	}
}

func TestRequestLetsEncryptRetriesARenewalThatIsFailing(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	current := f.certificates("abcdefghijkl")[0]
	f.store.UpdateCertificate(current.ID, func(c *state.Certificate) {
		c.Status, c.KeyType, c.NextAttempt = state.CertRenewalFailing, "ecdsaP256", f.clock().Add(10*time.Hour)
	})
	<-f.manager.kicks()

	c, err := f.manager.RequestLetsEncrypt(ctx, "abcdefghijkl", "orchard.com", certs.RSA2048, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	if c.ID != current.ID || c.Status != state.CertRenewalFailing || c.KeyType != "ecdsaP256" || !c.NextAttempt.Equal(f.clock()) {
		t.Errorf("certificate = %+v", c)
	}
	if len(f.certificates("abcdefghijkl")) != 1 {
		t.Error("a second request was added")
	}
	select {
	case <-f.manager.kicks():
	default:
		t.Error("the scheduler wasn't woken")
	}
}

func TestRequestLetsEncryptLeavesAnIssuedCertificateOfTheSameKeyTypeAlone(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	current := f.certificates("abcdefghijkl")[0]
	next := f.clock().Add(10 * time.Hour)
	f.store.UpdateCertificate(current.ID, func(c *state.Certificate) {
		c.Status, c.KeyType, c.NextAttempt = state.CertIssued, "ecdsaP256", next
	})
	<-f.manager.kicks()

	c, err := f.manager.RequestLetsEncrypt(ctx, "abcdefghijkl", "orchard.com", certs.ECDSAP256, "Mac")
	if err != nil {
		t.Fatal(err)
	}

	if c.ID != current.ID || c.Status != state.CertIssued || !c.NextAttempt.Equal(next) {
		t.Errorf("certificate = %+v", c)
	}
	if len(f.certificates("abcdefghijkl")) != 1 {
		t.Error("a second request was added")
	}
	select {
	case <-f.manager.kicks():
	default:
		t.Error("the scheduler wasn't woken")
	}
}

// signCSR signs csrPEM with a throwaway "ServerDog Test CA" and returns the leaf and CA PEMs.
func signCSR(t *testing.T, csrPEM []byte, now time.Time) (leafPEM, caPEM []byte) {
	t.Helper()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ServerDog Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)

	block, _ := pem.Decode(csrPEM)
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: request.Subject, DNSNames: request.DNSNames,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, request.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

// Request Now starts the request over: the old failure count would stretch the next backoff, and the old error
// would show until the next attempt.
func TestRequestLetsEncryptStartsAFailedRequestOver(t *testing.T) {
	for _, status := range []string{state.CertFailed, state.CertWaitingForDNS, state.CertRenewalFailing} {
		t.Run(status, func(t *testing.T) {
			f := newFixture(t)
			f.put(laravel())
			current := f.certificates("abcdefghijkl")[0]
			f.store.UpdateCertificate(current.ID, func(c *state.Certificate) {
				c.Status, c.Failures, c.Error, c.NextAttempt = status, 4, "Let's Encrypt couldn't verify the domain.", f.clock().Add(8*time.Hour)
			})
			<-f.manager.kicks()

			c, err := f.manager.RequestLetsEncrypt(ctx, "abcdefghijkl", "orchard.com", certs.ECDSAP256, "Mac")
			if err != nil {
				t.Fatal(err)
			}

			if c.ID != current.ID || c.Status != status || c.Failures != 0 || c.Error != "" || !c.NextAttempt.Equal(f.clock()) {
				t.Errorf("certificate = %+v", c)
			}
		})
	}
}
