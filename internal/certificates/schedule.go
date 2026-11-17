package certificates

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/acmeclient"
	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/certs"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// automatic is the actor recorded for what the agent does on its own.
const automatic = "ServerDog"

const (
	dnsRecheck     = 10 * time.Minute
	slowDNSRecheck = time.Hour
	slowAfter      = 7 * 24 * time.Hour
	renewalCheck   = 12 * time.Hour
)

// Run issues and renews certificates until ctx ends: every minute, and at once after Kick. Certificates a previous
// run left issuing (the agent stopped mid-request) are queued again first.
func (m *Manager) Run(ctx context.Context) {
	if err := m.requeueInterrupted(); err != nil {
		slog.Warn("could not requeue interrupted certificate requests", "error", err)
	}

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		m.Tick(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.kicks():
		}
	}
}

func (m *Manager) requeueInterrupted() error {
	left, err := m.Store.CertificatesWithStatus(state.CertIssuing)
	if err != nil {
		return err
	}

	now := m.Now()
	var failures []error

	for _, c := range left {
		_, err := m.Store.UpdateCertificate(c.ID, func(c *state.Certificate) {
			c.Status, c.NextAttempt = state.CertWaitingForDNS, now
			if c.WaitingSince.IsZero() {
				c.WaitingSince = now
			}
		})
		failures = append(failures, err)
	}

	return errors.Join(failures...)
}

// Tick handles every certificate whose next attempt is due.
func (m *Manager) Tick(ctx context.Context) {
	due, err := m.Store.DueCertificates(m.Now())
	if err != nil {
		slog.Warn("could not list due certificates", "error", err)
		return
	}

	for _, c := range due {
		if ctx.Err() != nil {
			return
		}

		switch {
		case c.Source != state.CertLetsEncrypt:
			m.update(c.ID, func(c *state.Certificate) { c.NextAttempt = time.Time{} })
		case c.Usable():
			if activationFailed(c) {
				m.retryActivation(ctx, c)
			}
			m.renew(ctx, c)
		case c.Status == state.CertWaitingForDNS || c.Status == state.CertFailed:
			m.issue(ctx, c)
		}
	}
}

// issue asks Let's Encrypt for a first certificate, but only once every name reaches this server.
func (m *Manager) issue(ctx context.Context, c state.Certificate) {
	now := m.Now()

	reachable, reason := m.Domains.Reachable(ctx, c.Names)
	if ctx.Err() != nil {
		return // The agent is stopping, so the answer says nothing about the domain.
	}
	if !reachable {
		m.update(c.ID, func(c *state.Certificate) {
			if c.Status != state.CertWaitingForDNS || c.WaitingSince.IsZero() {
				c.WaitingSince = now
			}
			c.Status, c.Error = state.CertWaitingForDNS, "Waiting for DNS.\n\n"+reason
			c.NextAttempt = now.Add(recheck(now.Sub(c.WaitingSince)))
		})
		return
	}

	if !m.update(c.ID, func(c *state.Certificate) { c.Status, c.Error, c.NextAttempt = state.CertIssuing, "", time.Time{} }) {
		return
	}

	issued, err := m.ACME.Obtain(ctx, c.Names, certs.KeyType(c.KeyType))
	if ctx.Err() != nil {
		return // The agent is stopping; Run requeues it on the next start.
	}
	if err != nil {
		failure := acmeclient.Classify(err)
		slog.Warn("certificate request failed", "site", c.SiteID, "domain", c.Domain, "error", err)
		m.issueFailed(c, failure.Message, failure.RetryAfter)
		return
	}

	if err := m.install(ctx, c, issued, false, m.renewalTime(ctx, issued.Leaf)); err != nil {
		if ctx.Err() != nil {
			return
		}
		m.issueFailed(c, "Let's Encrypt issued the certificate, but installing it failed.\n\n"+err.Error(), 0)
	}
}

func (m *Manager) issueFailed(c state.Certificate, message string, retryAfter time.Duration) {
	now := m.Now()

	m.update(c.ID, func(stored *state.Certificate) {
		stored.Failures++
		wait := retryAfter
		if wait <= 0 {
			wait = backoff(stored.Failures, time.Hour, 24*time.Hour)
		}
		stored.Status, stored.Error, stored.WaitingSince = state.CertFailed, message, time.Time{}
		stored.NextAttempt = m.retryAt(c, *stored, now.Add(wait))
	})
}

// renew renews the certificate when Let's Encrypt says so (or its names changed). A failed renewal leaves the files
// Nginx serves alone; the certificate says renewalFailing and is retried with backoff.
func (m *Manager) renew(ctx context.Context, c state.Certificate) {
	fullchain, err := os.ReadFile(certs.FullchainFile(m.Paths, c.SiteID, c.ID))
	var leaf *x509.Certificate
	if err == nil {
		leaf, err = certs.Leaf(fullchain)
	}

	if err == nil && sameNames(leaf.DNSNames, c.Names) {
		if at := m.renewalTime(ctx, leaf); at.After(m.Now()) {
			m.update(c.ID, func(stored *state.Certificate) { stored.NextAttempt = m.retryAt(c, *stored, at) })
			return
		}
	}

	reachable, reason := m.Domains.Reachable(ctx, c.Names)
	if ctx.Err() != nil {
		return // The agent is stopping, so the answer says nothing about the domain.
	}
	if !reachable {
		m.renewalFailed(c, "The certificate couldn't be renewed because the domain doesn't reach this server.\n\n"+reason, 0)
		return
	}

	issued, err := m.ACME.Obtain(ctx, c.Names, certs.KeyType(c.KeyType))
	if ctx.Err() != nil {
		return // Still due: retried on the next start.
	}
	if err != nil {
		failure := acmeclient.Classify(err)
		slog.Warn("certificate renewal failed", "site", c.SiteID, "domain", c.Domain, "error", err)
		m.renewalFailed(c, failure.Message, failure.RetryAfter)
		return
	}

	if err := m.install(ctx, c, issued, true, m.renewalTime(ctx, issued.Leaf)); err != nil {
		if ctx.Err() != nil {
			return
		}
		m.renewalFailed(c, "Let's Encrypt renewed the certificate, but Nginx didn't accept it, so the current one is still served.\n\n"+err.Error(), 0)
	}
}

func (m *Manager) renewalFailed(c state.Certificate, message string, retryAfter time.Duration) {
	now := m.Now()

	m.update(c.ID, func(stored *state.Certificate) {
		stored.Failures++
		wait := max(retryAfter, backoff(stored.Failures, time.Hour, 12*time.Hour))
		stored.Status, stored.Error = state.CertRenewalFailing, message
		stored.NextAttempt = m.retryAt(c, *stored, now.Add(wait))
	})
}

// install writes an issued certificate and serves it, under the site's lock. A certificate deleted while Let's Encrypt
// was answering (its domain or site removed) is dropped. The active certificate's files change in one validated
// change with an Nginx reload; if Nginx rejects them, the previous files stay. next is when to check for renewal,
// looked up before the lock because asking Let's Encrypt is a network call.
func (m *Manager) install(ctx context.Context, c state.Certificate, issued acmeclient.Issued, renewal bool, next time.Time) error {
	defer m.Sites.Locks.Lock(c.SiteID)()

	current, err := m.Store.GetCertificate(c.ID)
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := m.certificateDir(c.SiteID, c.ID); err != nil {
		return err
	}

	files := certs.Files(m.Paths, c.SiteID, c.ID, issued.Fullchain, issued.PrivateKey)

	if current.Active {
		active, err := m.Active(c.SiteID)
		if err != nil {
			return err
		}
		if err := m.Sites.ApplyCertificates(ctx, c.SiteID, files, active, nil); err != nil {
			return err
		}
	} else if _, err := m.Applier.Apply(ctx, apply.Plan{Files: files}); err != nil {
		return err
	}

	current, err = m.Store.UpdateCertificate(c.ID, func(stored *state.Certificate) {
		describe(stored, issued.Leaf)
		stored.NextAttempt = m.retryAt(c, *stored, next)
	})
	if err != nil {
		return err
	}

	kind, summary := "certificate.issued", "Let's Encrypt issued a certificate for "+c.Domain+"."
	if renewal {
		kind, summary = "certificate.renewed", "Renewed the certificate for "+c.Domain+"."
	}
	m.Store.AddActivity(c.SiteID, state.Activity{At: m.Now(), Kind: kind, Actor: automatic, Summary: summary})

	if err := m.activateIfFirst(ctx, current); err != nil {
		slog.Warn("could not activate the new certificate", "site", c.SiteID, "domain", c.Domain, "error", err)
		m.update(c.ID, func(c *state.Certificate) { c.Error = activationRefused + "\n\n" + err.Error() })
	}

	return nil
}

// activationRefused starts the error of an issued certificate Nginx didn't accept; Tick tries to activate it again.
const activationRefused = "The certificate was issued, but Nginx didn't accept it, so it isn't active."

func activationFailed(c state.Certificate) bool {
	return c.Status == state.CertIssued && !c.Active && strings.HasPrefix(c.Error, activationRefused)
}

// retryActivation serves an issued certificate whose activation failed, unless its domain got an active certificate
// meanwhile. Either way the error goes; if Nginx refuses again, it is recorded again.
func (m *Manager) retryActivation(ctx context.Context, c state.Certificate) {
	defer m.Sites.Locks.Lock(c.SiteID)()

	current, err := m.Store.GetCertificate(c.ID)
	if err != nil || !activationFailed(current) {
		return
	}

	if err := m.activateIfFirst(ctx, current); err != nil {
		slog.Warn("could not activate the certificate again", "site", c.SiteID, "domain", c.Domain, "error", err)
		m.update(c.ID, func(c *state.Certificate) { c.Error = activationRefused + "\n\n" + err.Error() })
		return
	}

	m.update(c.ID, func(c *state.Certificate) { c.Error = "" })
}

// renewalTime is when to look at the certificate again: Let's Encrypt's renewal time, but at most 12 hours away.
func (m *Manager) renewalTime(ctx context.Context, leaf *x509.Certificate) time.Time {
	now := m.Now()

	at, err := m.ACME.RenewalTime(ctx, leaf, now)
	if err != nil {
		slog.Warn("could not get the renewal time from Let's Encrypt", "error", err)
	}

	next := now.Add(renewalCheck)
	if !at.IsZero() && at.Before(next) {
		next = at
	}

	return next
}

// update changes a certificate's row. It returns false when the row is gone (its domain or site was removed).
func (m *Manager) update(id string, change func(*state.Certificate)) bool {
	_, err := m.Store.UpdateCertificate(id, change)
	if errors.Is(err, state.ErrNotFound) {
		return false
	}
	if err != nil {
		slog.Warn("could not update a certificate", "certificate", id, "error", err)
		return false
	}

	return true
}

// retryAt is when to look at a certificate again after the scheduler worked from the snapshot of its row. When SyncSite
// changed the names meanwhile, the certificate is due now instead, so the change isn't left waiting.
func (m *Manager) retryAt(snapshot, stored state.Certificate, at time.Time) time.Time {
	if sameNames(snapshot.Names, stored.Names) {
		return at
	}

	return m.Now()
}

func recheck(waited time.Duration) time.Duration {
	if waited >= slowAfter {
		return slowDNSRecheck
	}

	return dnsRecheck
}

// backoff doubles base for each failure after the first, up to ceiling.
func backoff(failures int, base, ceiling time.Duration) time.Duration {
	wait := base
	for i := 1; i < failures && wait < ceiling; i++ {
		wait *= 2
	}

	return min(wait, ceiling)
}

func sameNames(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)

	return slices.EqualFunc(a, b, strings.EqualFold)
}
