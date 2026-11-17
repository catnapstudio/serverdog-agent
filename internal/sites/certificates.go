package sites

import (
	"context"
	"fmt"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/dotenv"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// ApplyCertificates installs certificate files (and active links) and regenerates the site's Nginx config with active
// as the domains' certificates, in one validated change: if Nginx rejects it, the previous files are back.
// A customised config isn't regenerated: it references the stable active paths, so the reload picks up new files.
// commit, when set, saves the change once Nginx serves it, still under the apply lock: a deploy leaving the
// placeholder page renders from the store under that lock, so it must find the certificates it serves there.
// The caller holds the site's lock.
func (m *Manager) ApplyCertificates(ctx context.Context, siteID string, files []apply.File, active map[string]nginx.Certificate, commit func() error) error {
	caps := m.Capabilities(ctx)

	return m.Applier.Hold(ctx, func(applier apply.Applier) error {
		s, err := m.Store.GetSite(siteID)
		if err != nil {
			return err
		}

		plan := apply.Plan{Files: files, Checks: []system.Command{nginx.Check}, Reloads: []system.Command{nginx.Reload}}

		if !s.NginxCustomised {
			content := nginx.Render(nginx.Input{Site: s, HTTP2Directive: caps.NginxHTTP2Directive(), Certificates: active, Placeholder: m.showsPlaceholder(s)})
			plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.NginxSiteAvailable(siteID)), Content: content})
		}

		if _, err := applier.Apply(ctx, plan); err != nil {
			return err
		}
		if commit == nil {
			return nil
		}

		return commit()
	})
}

// CheckEnvWritable checks, before a database is created for the site, that MergeEnv will find the site's user and its
// environment file. A missing one is an InvalidError, so nothing is created and the caller can say why.
func (m *Manager) CheckEnvWritable(ctx context.Context, id string) error {
	s, err := m.Store.GetSite(id)
	if err != nil {
		return err
	}
	if s.EnvironmentFile == "" {
		return &site.InvalidError{Field: "environmentFile", Reason: "This site has no environment file to write the database settings to."}
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		return &site.InvalidError{Field: "user", Reason: fmt.Sprintf("The site's user %s is missing, so the database settings can't be written.", s.User)}
	}

	_, exists, err := m.files(user).ReadFile(ctx, m.environmentPath(s))
	if err != nil {
		return err
	}
	if !exists {
		return &site.InvalidError{Field: "environmentFile", Reason: fmt.Sprintf("The site's %s is missing, so the database settings can't be written. Deploy the site or create the file, then try again.", s.EnvironmentFile)}
	}

	return nil
}

// MergeEnv sets values in the site's environment file as the site user, keeping everything else. summary is the
// activity line; it must not contain the values.
func (m *Manager) MergeEnv(ctx context.Context, id string, values [][2]string, summary, actor string) error {
	defer m.Locks.Lock(id)()

	s, user, err := m.siteAndUser(id)
	if err != nil {
		return err
	}
	if s.EnvironmentFile == "" {
		return &site.InvalidError{Field: "environmentFile", Reason: "This site has no environment file to write to."}
	}

	files := m.files(user)
	file := m.environmentPath(s)

	content, _, err := files.ReadFile(ctx, file)
	if err != nil {
		return err
	}

	for _, value := range values {
		content = dotenv.Set(content, value[0], value[1])
	}

	if err := files.WriteFile(ctx, file, content, "0600"); err != nil {
		return err
	}

	m.Store.AddActivity(id, state.Activity{At: m.Now(), Kind: "env.changed", Actor: actor, Summary: summary})

	return nil
}
