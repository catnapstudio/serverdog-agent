package certificates

import (
	"context"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/go-acme/lego/v5/acme"
)

func (f *fixture) only() state.Certificate {
	f.t.Helper()

	list := f.certificates("abcdefghijkl")
	if len(list) != 1 {
		f.t.Fatalf("certificates = %+v", list)
	}

	return list[0]
}

func (f *fixture) fullchain(c state.Certificate) string {
	content, _ := os.ReadFile(certs.FullchainFile(f.manager.Paths, c.SiteID, c.ID))
	return string(content)
}

func (f *fixture) servesHTTPS() bool {
	config, _ := os.ReadFile(f.file(paths.NginxSiteAvailable("abcdefghijkl")))
	return strings.Contains(string(config), "ssl_certificate /etc/serverdog/certs/abcdefghijkl/orchard.com/active/fullchain.pem;")
}

func TestUnreachableDomainNeverContactsLetsEncrypt(t *testing.T) {
	f := newFixture(t)
	f.dns.set(false)
	f.put(laravel())
	started := f.clock()

	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertWaitingForDNS || !c.NextAttempt.Equal(f.clock().Add(10*time.Minute)) || !strings.Contains(c.Error, "doesn't point at this server") {
		t.Errorf("after the first check: %+v", c)
	}

	for range 3 {
		f.advance(10 * time.Minute)
		f.manager.Tick(ctx)
	}
	f.advance(7 * 24 * time.Hour)
	f.manager.Tick(ctx)

	c = f.only()
	if !c.NextAttempt.Equal(f.clock().Add(time.Hour)) || !c.WaitingSince.Equal(started) {
		t.Errorf("after a week: %+v", c)
	}
	if calls := f.acme.calls(); calls != 0 {
		t.Errorf("Let's Encrypt was contacted %d times", calls)
	}
}

func TestReachableDomainIsIssuedAndServed(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertIssued || !c.Active || c.Error != "" || !c.NextAttempt.Equal(f.clock().Add(12*time.Hour)) || !c.NotAfter.Equal(f.clock().Add(90*24*time.Hour)) {
		t.Errorf("certificate = %+v", c)
	}
	if !slices.Equal(f.acme.obtained[0], []string{"orchard.com", "www.orchard.com"}) || f.acme.keyTypes[0] != certs.ECDSAP256 {
		t.Errorf("obtained %v %v", f.acme.obtained, f.acme.keyTypes)
	}
	if info, err := os.Stat(certs.KeyFile(f.manager.Paths, c.SiteID, c.ID)); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file: %v %v", info, err)
	}
	if !f.servesHTTPS() {
		t.Error("the site doesn't serve the certificate")
	}

	activity, _ := f.store.ListActivity("abcdefghijkl", 1)
	if activity[0].Kind != "certificate.issued" || activity[0].Actor != "ServerDog" {
		t.Errorf("activity = %+v", activity[0])
	}
}

func TestRenewsWhenAThirdOfTheLifetimeIsLeft(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)
	first := f.fullchain(f.only())

	f.advance(12 * time.Hour)
	f.manager.Tick(ctx)
	if calls := f.acme.calls(); calls != 1 {
		t.Fatalf("renewed too early (%d calls)", calls)
	}

	f.advance(60 * 24 * time.Hour)
	f.system.Reset()
	f.manager.Tick(ctx)

	c := f.only()
	if f.acme.calls() != 2 || f.fullchain(c) == first || c.Status != state.CertIssued || !c.Active {
		t.Errorf("after renewal: %d calls, %+v", f.acme.calls(), c)
	}
	if commands := strings.Join(f.system.Commands(), "\n"); !strings.Contains(commands, "reload-nginx") {
		t.Errorf("Nginx wasn't reloaded: %s", commands)
	}
}

func TestFailedRenewalKeepsServingTheCurrentCertificate(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)
	before := f.fullchain(f.only())

	f.advance(61 * 24 * time.Hour)
	f.acme.fail(&acme.ProblemDetails{Type: acme.ConnectionErrorType, Detail: "Timeout during connect (likely firewall problem)"})
	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertRenewalFailing || !c.Active || c.Failures != 1 || !c.NextAttempt.Equal(f.clock().Add(time.Hour)) || !strings.Contains(c.Error, "port 80") {
		t.Errorf("certificate = %+v", c)
	}
	if f.fullchain(c) != before || !f.servesHTTPS() {
		t.Error("the current certificate isn't served any more")
	}

	f.advance(time.Hour)
	f.manager.Tick(ctx)
	if c := f.only(); !c.NextAttempt.Equal(f.clock().Add(2 * time.Hour)) {
		t.Errorf("second failure: %+v", c)
	}
}

func TestRenewalThatNginxRejectsKeepsTheOldFiles(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)
	before := f.fullchain(f.only())

	f.advance(61 * 24 * time.Hour)
	f.system.Fail("nginx", 1, "nginx: [emerg] SSL_CTX_use_PrivateKey failed")
	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertRenewalFailing || !c.Active || !strings.Contains(c.Error, "SSL_CTX_use_PrivateKey") {
		t.Errorf("certificate = %+v", c)
	}
	if f.fullchain(c) != before {
		t.Error("the previous files weren't restored")
	}
}

func TestRateLimitedIssueWaitsForRetryAfter(t *testing.T) {
	f := newFixture(t)
	f.acme.fail(&acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, Detail: "too many certificates"}, RetryAfter: 3 * time.Hour})
	f.put(laravel())

	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertFailed || !c.NextAttempt.Equal(f.clock().Add(3*time.Hour)) || !strings.HasPrefix(c.Error, "Let's Encrypt's rate limit") {
		t.Errorf("certificate = %+v", c)
	}

	f.advance(2 * time.Hour)
	f.manager.Tick(ctx)
	if calls := f.acme.calls(); calls != 1 {
		t.Errorf("retried before Retry-After (%d calls)", calls)
	}
}

func TestFailedIssueBacksOffUpToADay(t *testing.T) {
	f := newFixture(t)
	f.acme.fail(errors.New("connection reset by peer"))
	f.put(laravel())

	f.manager.Tick(ctx)
	if c := f.only(); !c.NextAttempt.Equal(f.clock().Add(time.Hour)) {
		t.Errorf("first failure: %+v", c)
	}

	f.advance(time.Hour)
	f.manager.Tick(ctx)
	if c := f.only(); !c.NextAttempt.Equal(f.clock().Add(2 * time.Hour)) {
		t.Errorf("second failure: %+v", c)
	}

	f.store.UpdateCertificate(f.only().ID, func(c *state.Certificate) { c.Failures = 10; c.NextAttempt = f.clock() })
	f.manager.Tick(ctx)
	if c := f.only(); !c.NextAttempt.Equal(f.clock().Add(24 * time.Hour)) {
		t.Errorf("eleventh failure: %+v", c)
	}
}

func TestRunRetriesCertificatesLeftIssuing(t *testing.T) {
	f := newFixture(t)
	f.dns.set(false)
	f.put(laravel())
	c := f.only()
	f.store.UpdateCertificate(c.ID, func(c *state.Certificate) { c.Status, c.NextAttempt = state.CertIssuing, time.Time{} })
	f.dns.set(true)

	running, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		f.manager.Run(running)
		close(done)
	}()
	defer func() { stop(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if got, _ := f.store.GetCertificate(c.ID); got.Status == state.CertIssued {
			break
		}
		if time.Now().After(deadline) {
			got, _ := f.store.GetCertificate(c.ID)
			t.Fatalf("still %+v", got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChangingTheRedirectReissuesWithTheNewNames(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)

	changed := laravel()
	changed.Domains[0].Redirect = site.NoRedirect
	f.put(changed)
	f.manager.Tick(ctx)

	if f.acme.calls() != 2 || !slices.Equal(f.acme.obtained[1], []string{"orchard.com"}) {
		t.Errorf("obtained %v", f.acme.obtained)
	}
	if c := f.only(); c.Status != state.CertIssued || !c.Active {
		t.Errorf("certificate = %+v", c)
	}
}

func TestAnIssueForARemovedCertificateIsDropped(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	c := f.only()
	issued, _ := f.acme.Obtain(ctx, c.Names, certs.ECDSAP256)
	f.store.DeleteCertificate(c.ID)

	if err := f.manager.install(ctx, c, issued, false, f.clock().Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(certs.FullchainFile(f.manager.Paths, c.SiteID, c.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("files were written: %v", err)
	}
}

func TestOnlyLetsEncryptCertificatesAreScheduled(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Delete(ctx, f.only().ID, "Mac")
	uploaded := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")
	f.store.UpdateCertificate(uploaded.ID, func(c *state.Certificate) { c.NextAttempt = f.clock() })

	f.manager.Tick(ctx)

	if c := f.only(); f.acme.calls() != 0 || !c.NextAttempt.IsZero() {
		t.Errorf("%d calls, %+v", f.acme.calls(), c)
	}
}

func TestStoppingDuringTheDnsCheckLeavesAnIssuedCertificateAlone(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)
	f.advance(61 * 24 * time.Hour)
	before := f.only()

	stopping, stop := context.WithCancel(ctx)
	f.dns.set(false)
	f.dns.onCheck = stop
	f.manager.renew(stopping, before)

	if c := f.only(); c.Status != state.CertIssued || c.Failures != 0 || c.Error != "" || !c.NextAttempt.Equal(before.NextAttempt) {
		t.Errorf("certificate = %+v", c)
	}
	if f.acme.calls() != 1 {
		t.Errorf("Let's Encrypt was contacted %d times", f.acme.calls())
	}
}

func TestStoppingDuringTheDnsCheckKeepsAFirstRequestWaiting(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	before := f.only()

	stopping, stop := context.WithCancel(ctx)
	f.dns.set(false)
	f.dns.onCheck = stop
	f.manager.issue(stopping, before)

	if c := f.only(); c.Error != "" || !c.NextAttempt.Equal(before.NextAttempt) {
		t.Errorf("certificate = %+v", c)
	}
}

func TestNamesChangedWhileRenewalWasCheckedAreRenewedAtOnce(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.manager.Tick(ctx)
	f.advance(12 * time.Hour)

	f.acme.onRenewalTime = func() {
		changed := laravel()
		changed.Domains[0].Redirect = site.NoRedirect
		f.put(changed)
	}
	f.manager.Tick(ctx)

	if c := f.only(); !c.NextAttempt.Equal(f.clock()) || !slices.Equal(c.Names, []string{"orchard.com"}) {
		t.Errorf("certificate = %+v", c)
	}

	f.acme.onRenewalTime = nil
	f.manager.Tick(ctx)

	if f.acme.calls() != 2 || !slices.Equal(f.acme.obtained[1], []string{"orchard.com"}) {
		t.Errorf("obtained %v", f.acme.obtained)
	}
}

func TestNamesChangedWhileIssuingAreRenewedAtOnce(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	f.acme.afterObtain = func() {
		changed := laravel()
		changed.Domains[0].Redirect = site.NoRedirect
		f.put(changed)
	}
	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertIssued || !c.NextAttempt.Equal(f.clock()) || !slices.Equal(c.Names, []string{"orchard.com"}) {
		t.Errorf("certificate = %+v", c)
	}

	f.acme.afterObtain = nil
	f.manager.Tick(ctx)

	if f.acme.calls() != 2 || !slices.Equal(f.acme.obtained[1], []string{"orchard.com"}) {
		t.Errorf("obtained %v", f.acme.obtained)
	}
}

// A certificate Let's Encrypt issued but Nginx refused to serve is activated by a later tick once Nginx accepts it.
func TestAFailedActivationIsRetried(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.system.Fail("nginx", 1, "nginx: [emerg] cannot load certificate")

	f.manager.Tick(ctx)

	c := f.only()
	if c.Status != state.CertIssued || c.Active || !strings.HasPrefix(c.Error, "The certificate was issued, but Nginx didn't accept it") || f.servesHTTPS() {
		t.Fatalf("after the refused activation: %+v", c)
	}

	f.system.Handle("nginx", func(system.Command) (system.Result, error) { return system.Result{}, nil })
	f.advance(12 * time.Hour)
	f.manager.Tick(ctx)

	c = f.only()
	if !c.Active || c.Error != "" || !f.servesHTTPS() {
		t.Errorf("after the retry: %+v, serves HTTPS = %v", c, f.servesHTTPS())
	}
	if calls := f.acme.calls(); calls != 1 {
		t.Errorf("Let's Encrypt was asked %d times, want once", calls)
	}
	if !c.NextAttempt.After(f.clock()) {
		t.Errorf("next attempt = %v, want the renewal check after %v", c.NextAttempt, f.clock())
	}
}

// Another certificate made active meanwhile is fine too: the error goes, and the active one stays.
func TestAFailedActivationIsClearedWhenAnotherCertificateIsActive(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())
	f.system.Fail("nginx", 1, "nginx: [emerg] cannot load certificate")
	f.manager.Tick(ctx)
	failed := f.only()

	f.system.Handle("nginx", func(system.Command) (system.Result, error) { return system.Result{}, nil })
	uploaded := f.upload("abcdefghijkl", "orchard.com", "orchard.com", "www.orchard.com")
	f.advance(12 * time.Hour)
	f.manager.Tick(ctx)

	after, err := f.store.GetCertificate(failed.ID)
	if err != nil || after.Active || after.Error != "" {
		t.Errorf("the issued certificate = %+v %v", after, err)
	}
	if active, _ := f.store.GetCertificate(uploaded.ID); !active.Active {
		t.Errorf("the uploaded certificate lost its place: %+v", active)
	}
}

// siteLocked reports whether something holds the site's lock, as an edit of the site would find it.
func (f *fixture) siteLocked(siteID string) bool {
	acquired := make(chan func(), 1)
	go func() { acquired <- f.sites.Locks.Lock(siteID) }()

	select {
	case unlock := <-acquired:
		unlock()
		return false
	case <-time.After(100 * time.Millisecond):
		go func() { (<-acquired)() }()
		return true
	}
}

// Asking Let's Encrypt when to renew is a network call; edits of the site must not wait for it.
func TestTheRenewalTimeIsLookedUpWithoutTheSiteLock(t *testing.T) {
	f := newFixture(t)
	f.put(laravel())

	var locked []bool
	f.acme.onRenewalTime = func() { locked = append(locked, f.siteLocked("abcdefghijkl")) }

	f.manager.Tick(ctx)
	f.advance(61 * 24 * time.Hour)
	f.manager.Tick(ctx)

	if f.acme.calls() != 2 {
		t.Fatalf("Let's Encrypt was asked %d times, want an issue and a renewal", f.acme.calls())
	}
	if len(locked) < 2 || slices.Contains(locked, true) {
		t.Errorf("renewal time looked up with the site locked: %v", locked)
	}
}
