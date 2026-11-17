package certificates

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
)

// RemoveOrphanFiles deletes the certificate folders of sites that no longer exist, logging each one: a site delete
// that failed after forgetting the site leaves its keys behind. It looks only in paths.CertsDir, which root owns, and
// only at folders named like a site id. The agent runs it at startup, before it serves requests or runs the
// scheduler, so no site is created or given a certificate meanwhile.
func (m *Manager) RemoveOrphanFiles() error {
	entries, err := os.ReadDir(m.Paths.File(paths.CertsDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list the certificate folders: %w", err)
	}

	stored, err := m.Store.ListSites()
	if err != nil {
		return err
	}

	known := map[string]bool{}
	for _, s := range stored {
		known[s.ID] = true
	}

	var failures []error
	for _, entry := range entries {
		siteID := entry.Name()
		if known[siteID] || !ids.Valid(siteID) {
			continue
		}

		folder := m.Paths.File(paths.SiteCertificates(siteID))
		if err := os.RemoveAll(folder); err != nil {
			failures = append(failures, fmt.Errorf("remove %s: %w", folder, err))
			continue
		}
		slog.Info("removed the certificate files of a deleted site", "site", siteID, "path", folder)
	}

	return errors.Join(failures...)
}
