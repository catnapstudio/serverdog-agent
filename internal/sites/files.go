package sites

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// ensureUser returns the site's user, creating an isolated user on first Put. A retry after a failed Put finds the
// user it created through the marker file; any other existing user is refused.
func (m *Manager) ensureUser(ctx context.Context, s site.Site, creating bool) (system.User, error) {
	user, err := m.LookupUser(s.User)

	if !s.Isolated {
		if err != nil {
			return system.User{}, fmt.Errorf("The %s user is missing. Repair the server's setup.", s.User)
		}
		return user, m.joinWebGroup(ctx, s.User)
	}

	marker := m.Paths.File(path.Join(paths.UserHome(s.User), ".serverdog-site"))

	switch {
	case err != nil && !creating:
		return system.User{}, fmt.Errorf("The site's user %s is missing.", s.User)

	case err != nil:
		if _, err := m.System.Run(ctx, system.Command{Name: "useradd", Args: []string{"--create-home", "--shell", "/bin/bash", s.User}}); err != nil {
			return system.User{}, fmt.Errorf("create user %s: %w", s.User, err)
		}
		if user, err = m.LookupUser(s.User); err != nil {
			return system.User{}, err
		}

		files := m.files(user)
		if err := files.MkdirAll(ctx, "0750", m.Paths.File(paths.UserHome(s.User))); err != nil {
			return system.User{}, err
		}
		if err := files.WriteFile(ctx, marker, []byte(s.ID+"\n"), "0644"); err != nil {
			return system.User{}, err
		}

	case creating:
		content, ok, err := m.files(user).ReadFile(ctx, marker)
		if err != nil || !ok || strings.TrimSpace(string(content)) != s.ID {
			return system.User{}, &site.InvalidError{Field: "user", Reason: fmt.Sprintf("A user named %s already exists on this server. Choose another name.", s.User)}
		}
	}

	return user, m.joinWebGroup(ctx, s.User)
}

// joinWebGroup lets Nginx (www-data) read the user's home, which Ubuntu creates with mode 0750.
func (m *Manager) joinWebGroup(ctx context.Context, group string) error {
	if _, err := m.System.Run(ctx, system.Command{Name: "usermod", Args: []string{"-aG", group, "www-data"}}); err != nil {
		return fmt.Errorf("add www-data to %s: %w", group, err)
	}

	return nil
}

// prepareFiles creates the site's directories, deploy key, known_hosts (once it has a repository), placeholder page
// (when it is created) and empty environment file, all as the site user.
func (m *Manager) prepareFiles(ctx context.Context, s site.Site, user system.User, creating bool) error {
	files := m.files(user)
	dir := m.Paths.File(s.Directory)

	dirs := []string{dir}
	if s.ZeroDowntime {
		dirs = append(dirs, filepath.Join(dir, "releases"), filepath.Join(dir, "shared"))
	} else {
		dirs = append(dirs, filepath.Join(dir, "current"))
	}
	if err := files.MkdirAll(ctx, "0750", dirs...); err != nil {
		return err
	}

	if err := m.Keys.Install(ctx, s.ID, s.User, files); err != nil {
		return err
	}

	if s.HasRepository() {
		if err := m.writeSiteKnownHosts(ctx, s, user); err != nil {
			return err
		}
	}

	if creating && s.HasWebsite() {
		if err := m.writePlaceholder(ctx, s, files); err != nil {
			return err
		}
	}

	if s.EnvironmentFile == "" {
		return nil
	}

	environment := m.environmentPath(s)
	if _, ok, err := files.ReadFile(ctx, environment); err != nil {
		return err
	} else if !ok {
		return files.WriteFile(ctx, environment, nil, "0600")
	}

	return nil
}

// DeployKey returns the site's public deploy key, generating a pending one before the site exists.
// The site's lock makes concurrent first calls agree on one key, and keeps Put from installing a key mid-generation.
func (m *Manager) DeployKey(ctx context.Context, siteID string) (gitsource.DeployKey, error) {
	defer m.Locks.Lock(siteID)()

	s, err := m.Store.GetSite(siteID)
	if errors.Is(err, state.ErrNotFound) {
		return m.Keys.Pending(siteID)
	}
	if err != nil {
		return gitsource.DeployKey{}, err
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		return gitsource.DeployKey{}, err
	}

	return m.Keys.Installed(ctx, siteID, s.User, m.files(user))
}

// RepositoryCredentials says how Test Access reaches the repository: as the site user, or as root with the pending key.
// It may generate the pending key, so it holds the site's lock like DeployKey.
func (m *Manager) RepositoryCredentials(ctx context.Context, siteID string) (gitsource.Credentials, error) {
	defer m.Locks.Lock(siteID)()

	global := m.Paths.File(paths.KnownHosts)

	s, err := m.Store.GetSite(siteID)
	if errors.Is(err, state.ErrNotFound) {
		if _, err := m.Keys.Pending(siteID); err != nil {
			return gitsource.Credentials{}, err
		}
		return gitsource.Credentials{
			KeyPath:              m.Keys.PendingKeyPath(siteID),
			KnownHostsPath:       m.Keys.PendingKnownHostsPath(siteID),
			GlobalKnownHostsPath: global,
			Home:                 "/root",
			Path:                 "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		}, nil
	}
	if err != nil {
		return gitsource.Credentials{}, err
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		return gitsource.Credentials{}, err
	}

	credentials := gitsource.Credentials{
		KeyPath:              m.Paths.File(paths.DeployKey(s.User, siteID)),
		KnownHostsPath:       m.Paths.File(paths.SiteKnownHosts(s.User, siteID)),
		GlobalKnownHostsPath: global,
		Home:                 user.Home,
		Path:                 "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	if m.AsUser {
		credentials.User = &user
	}

	return credentials, nil
}

// RefreshKnownHosts rewrites the site's known_hosts from the host keys the user trusted.
func (m *Manager) RefreshKnownHosts(ctx context.Context, siteID string) error {
	lines, err := m.Store.HostKeys(siteID)
	if err != nil {
		return err
	}

	_, err = m.writeKnownHosts(ctx, siteID, lines)

	return err
}

// writeKnownHosts writes lines as the site's known_hosts: in the site user's home through userfs, or as the
// root-owned pending file before the site exists. It reports whether the site exists. It takes no lock, so
// RemoveHostKeys can call it while holding the site's lock.
func (m *Manager) writeKnownHosts(ctx context.Context, siteID string, lines []string) (bool, error) {
	s, err := m.Store.GetSite(siteID)
	if errors.Is(err, state.ErrNotFound) {
		pending := m.Keys.PendingKnownHostsPath(siteID)
		if err := os.MkdirAll(filepath.Dir(pending), 0o700); err != nil {
			return false, err
		}

		return false, os.WriteFile(pending, gitsource.RenderKnownHosts(lines), 0o644)
	}
	if err != nil {
		return false, err
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		return true, err
	}

	return true, m.files(user).WriteFile(ctx, m.Paths.File(paths.SiteKnownHosts(s.User, s.ID)), gitsource.RenderKnownHosts(lines), "0644")
}

func (m *Manager) writeSiteKnownHosts(ctx context.Context, s site.Site, user system.User) error {
	lines, err := m.Store.HostKeys(s.ID)
	if err != nil {
		return err
	}

	return m.files(user).WriteFile(ctx, m.Paths.File(paths.SiteKnownHosts(s.User, s.ID)), gitsource.RenderKnownHosts(lines), "0644")
}
