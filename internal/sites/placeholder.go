package sites

import (
	"context"
	"os"
	"path"
	"path/filepath"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

// placeholderPage is what a new site serves until its first release is live. It names no domain, so it never needs
// rewriting when the site's domains change.
var placeholderPage = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Nothing deployed yet</title>
<style>
body { margin: 0; min-height: 100vh; display: grid; place-items: center; font: 16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #1d1d1f; background: #f5f5f7; }
main { max-width: 32rem; padding: 2rem; text-align: center; }
h1 { font-size: 1.5rem; margin: 0 0 .5rem; }
p { margin: 0; color: #6e6e73; }
@media (prefers-color-scheme: dark) { body { color: #f5f5f7; background: #1d1d1f; } p { color: #a1a1a6; } }
</style>
</head>
<body>
<main>
<h1>This site is set up on ServerDog.</h1>
<p>Nothing is deployed here yet.</p>
</main>
</body>
</html>
`)

// writePlaceholder gives a new site its placeholder page, written as the site user (root never writes in the home).
func (m *Manager) writePlaceholder(ctx context.Context, s site.Site, files userfs.FS) error {
	dir := m.Paths.File(paths.Placeholder(s.Directory))
	if err := files.MkdirAll(ctx, "0750", dir); err != nil {
		return err
	}

	return files.WriteFile(ctx, filepath.Join(dir, "index.html"), placeholderPage, "0644")
}

// showsPlaceholder reports whether the site still has its placeholder page, so its generated config serves it.
// Root only looks: the site user writes the page, and the deploy that makes the first release live removes it.
//
// That deploy renders, switches and removes the page under the apply lock, and the agent looks under it too
// (renderNginx), so a config the agent writes never brings back a page the deploy removed.
func (m *Manager) showsPlaceholder(s site.Site) bool {
	info, err := os.Lstat(m.Paths.File(path.Join(paths.Placeholder(s.Directory), "index.html")))

	return err == nil && info.Mode().IsRegular()
}

// ReleaseConfig renders the Nginx config that serves the site's releases instead of its placeholder page, or its
// Octane server instead of PHP-FPM, for the deploy that makes its first release live or brings Octane up, on a server with caps. A customised config is left alone (spec §6.1), so
// there is nothing to write. The deploy calls it under the apply lock, so it reads what the agent saved with the config
// it last applied; caps is detected before that lock, since detecting waits on version commands.
func (m *Manager) ReleaseConfig(ctx context.Context, siteID string, caps capabilities.Capabilities) ([]apply.File, error) {
	s, err := m.Store.GetSite(siteID)
	if err != nil {
		return nil, err
	}
	if s.NginxCustomised {
		return nil, nil
	}

	// The deploy that calls this is about to move Nginx to the release's Octane server, before its port is recorded.
	content, err := m.render(s, caps, false, true)
	if err != nil {
		return nil, err
	}

	return []apply.File{{Path: m.Paths.File(paths.NginxSiteAvailable(siteID)), Content: content}}, nil
}
