package certificates

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"math"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// expiryStages are the days left at which a served certificate is posted, again at each: 14 days, 3 days, expired.
// Let's Encrypt certificates renew 30 days ahead, so one inside 14 days means its renewals keep failing; an uploaded
// one needs replacing by hand. The app warns from 14 days too.
var expiryStages = []int{14, 3, 0}

// warningsDocument keeps what was posted (certificate ID → days of the last stage), so a restart doesn't repeat it.
const warningsDocument = "certificate_warnings"

// ExpiryWatcher posts to the server's webhook when a served certificate nears expiry, and once more when it's renewed.
type ExpiryWatcher struct {
	Store  *state.Store
	Post   func(ctx context.Context, text string) error
	Host   func() string
	Now    func() time.Time
	Logger *slog.Logger
}

// Run checks at once, then every interval until ctx ends.
func (w *ExpiryWatcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		w.Check(ctx)

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Check posts each served certificate that reached a new stage, and each warned one that was renewed since.
func (w *ExpiryWatcher) Check(ctx context.Context) {
	encoded, revision, err := w.Store.Document(warningsDocument)
	if err != nil {
		w.Logger.Warn("could not read the certificate warnings", "error", err)
		return
	}

	posted := map[string]int{}
	if encoded != nil {
		if err := json.Unmarshal(encoded, &posted); err != nil {
			w.Logger.Warn("the certificate warnings are unreadable; starting over", "error", err)
			posted = map[string]int{}
		}
	}

	serving, err := w.serving()
	if err != nil {
		w.Logger.Warn("could not list the served certificates", "error", err)
		return
	}

	now := w.Now()
	next := map[string]int{}

	for _, c := range serving {
		previous, warned := posted[c.ID]
		left := c.NotAfter.Sub(now)
		stage, due := expiryStage(left)

		var text string
		switch {
		case !due && warned:
			text = fmt.Sprintf("✅ The certificate for %s on %s was renewed and is valid until %s.", c.Domain, w.Host(), c.NotAfter.Format("2 Jan 2006"))
		case !due:
			continue
		case warned && previous <= stage:
			next[c.ID] = previous
			continue
		default:
			text = expiryText(c, w.Host(), left)
		}

		if err := w.Post(ctx, text); err != nil {
			// Not recorded, so the next check tries again.
			w.Logger.Warn("could not post a certificate warning", "domain", c.Domain, "error", err)
			if warned {
				next[c.ID] = previous
			}
			continue
		}

		if due {
			next[c.ID] = stage
		}
	}

	// Certificates no longer served (replaced, or their domain removed) drop out without a message.
	if maps.Equal(posted, next) {
		return
	}

	encoded, err = json.Marshal(next)
	if err == nil {
		_, err = w.Store.PutDocument(warningsDocument, encoded, revision)
	}
	if err != nil {
		w.Logger.Warn("could not save the certificate warnings", "error", err)
	}
}

// serving returns the certificates Nginx serves: the active one of each domain, with files.
func (w *ExpiryWatcher) serving() ([]state.Certificate, error) {
	var serving []state.Certificate

	for _, status := range []string{state.CertIssued, state.CertRenewalFailing} {
		list, err := w.Store.CertificatesWithStatus(status)
		if err != nil {
			return nil, err
		}

		for _, c := range list {
			if c.Active && !c.NotAfter.IsZero() {
				serving = append(serving, c)
			}
		}
	}

	return serving, nil
}

// expiryStage returns the smallest stage left has reached, and false while it is outside them all.
func expiryStage(left time.Duration) (int, bool) {
	stage, due := 0, false

	for _, days := range expiryStages {
		if left <= time.Duration(days)*24*time.Hour {
			stage, due = days, true
		}
	}

	return stage, due
}

func expiryText(c state.Certificate, host string, left time.Duration) string {
	if left <= 0 {
		return fmt.Sprintf("❌ The certificate for %s on %s expired on %s, so browsers warn visitors away. %s", c.Domain, host, c.NotAfter.Format("2 Jan 2006"), expiryAdvice(c))
	}

	days := int(math.Ceil(left.Hours() / 24))
	unit := "days"
	if days == 1 {
		unit = "day"
	}

	return fmt.Sprintf("⚠️ The certificate for %s on %s expires in %d %s (%s). %s", c.Domain, host, days, unit, c.NotAfter.Format("2 Jan 2006"), expiryAdvice(c))
}

func expiryAdvice(c state.Certificate) string {
	if c.Source != state.CertLetsEncrypt {
		return "Replace it in ServerDog."
	}

	reason, _, _ := strings.Cut(strings.TrimSpace(c.Error), "\n\n")
	if reason == "" {
		return "Let's Encrypt renewals keep failing."
	}

	return "It isn't renewing: " + reason
}
