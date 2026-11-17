package sites

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

var (
	// ErrNoHostKey means the site trusts no key of its own for the host. A key from the providers' list isn't the
	// site's to remove.
	ErrNoHostKey = errors.New("The site has no trusted key for this host.\n\nA key from the built-in list of GitHub, GitLab and Bitbucket keys can't be removed.")
	// ErrHostKeyMoved means none of the site's keys for the host has the fingerprint the user confirmed.
	ErrHostKeyMoved = errors.New("The trusted key changed since you looked. Test access again.")
)

// RemoveHostKeys drops the keys the site trusts for host (a known_hosts name, e.g. "[git.example.com]:2222"), but only
// when one of them has the fingerprint the user confirmed. It returns the removed keys' fingerprints. It never trusts
// the host's new key: the user does that with TrustHostKey after testing access again.
//
// The file is written before the rows are deleted: a failure in between leaves the old rows with the old file, and the
// next Test Access rewrites the file from the rows.
func (m *Manager) RemoveHostKeys(ctx context.Context, siteID, host, fingerprint, actor string) ([]string, error) {
	defer m.Locks.Lock(siteID)()

	// A deploy reads the file while it fetches.
	if _, running, err := m.Store.RunningDeployment(siteID); err != nil {
		return nil, err
	} else if running {
		return nil, state.ErrDeployRunning
	}

	lines, err := m.Store.HostKeys(siteID)
	if err != nil {
		return nil, err
	}

	var kept, removed, fingerprints []string
	confirmed := false
	for _, line := range lines {
		keys := gitsource.ParseKnownHosts(line)
		if len(keys) != 1 || !keys[0].Names(host) {
			kept = append(kept, line)
			continue
		}

		removed = append(removed, line)
		fingerprints = append(fingerprints, keys[0].Fingerprint)
		if keys[0].Fingerprint == fingerprint {
			confirmed = true
		}
	}

	if len(removed) == 0 {
		return nil, ErrNoHostKey
	}
	if !confirmed {
		return nil, ErrHostKeyMoved
	}

	exists, err := m.writeKnownHosts(ctx, siteID, kept)
	if err != nil {
		return nil, err
	}

	if err := m.Store.RemoveHostKeys(siteID, removed); err != nil {
		return nil, err
	}

	slog.Info("hostkey.removed", "site", siteID, "host", host, "fingerprints", fingerprints, "actor", actor)

	// Activity belongs to created sites: a site still being created would keep an entry nothing ever deletes.
	if !exists {
		return fingerprints, nil
	}

	m.Store.AddActivity(siteID, state.Activity{At: m.Now(), Kind: "hostkey.removed", Actor: actor, Summary: removedSummary(fingerprints, host)})

	return fingerprints, nil
}

// removedSummary names the fingerprints, never the keys: "Removed the trusted host key SHA256:… for git.example.com."
func removedSummary(fingerprints []string, host string) string {
	if len(fingerprints) == 1 {
		return fmt.Sprintf("Removed the trusted host key %s for %s.", fingerprints[0], host)
	}

	return fmt.Sprintf("Removed the trusted host keys %s for %s.", strings.Join(fingerprints, ", "), host)
}
