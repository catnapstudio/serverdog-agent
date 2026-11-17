// Package sites creates, changes and deletes sites: users, directories, deploy keys, FPM pools, Node units and Nginx configs.
package sites

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/capabilities"
	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/nodeservice"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/phpfpm"
	"github.com/catnapstudio/serverdog-agent/internal/processes"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/userfs"
)

// ErrStaleContent is an edit made to a file that changed since it was read.
var ErrStaleContent = errors.New("the file changed since it was opened")

// ErrProcessStopped refuses to restart a process the user stopped: Start brings it back.
var ErrProcessStopped = errors.New("The process is stopped. Start it instead.")

type Manager struct {
	Store *state.Store
	Paths paths.Paths
	// System runs root commands (useradd, systemctl, nginx); Exec runs file operations as site users.
	System       system.Runner
	Exec         system.Runner
	Applier      apply.Applier
	Keys         gitsource.Keys
	Capabilities func(context.Context) capabilities.Capabilities
	LookupUser   func(name string) (system.User, error)
	// AsUser runs Exec commands with the site user's ids. Tests leave it false.
	AsUser bool
	Now    func() time.Time
	Locks  *lock.Keyed
	// ActiveCertificates returns each domain's active certificate (plan 2's certificate manager). Nil means HTTP only.
	ActiveCertificates func(siteID string) (map[string]nginx.Certificate, error)
	// AfterPut runs after a Put saved the site, while the site's lock is still held (it must not take it).
	// previous is nil when the site was created.
	AfterPut func(ctx context.Context, saved site.Site, previous *site.Site)
	// SyncPorts brings the Node port guard in step with the store (portguard.Syncer.Sync), after a Node site is saved
	// or deleted. Nil skips it.
	SyncPorts func(ctx context.Context) error
}

// Sum is the hex sha256 the editors use to detect concurrent edits.
func Sum(content []byte) string {
	sum := sha256.Sum256(content)

	return hex.EncodeToString(sum[:])
}

// Put creates the site (expectedRevision 0) or changes it. Nothing is stored unless the server accepted the new configuration.
// A Put that changes no setting changes nothing: no files, no new revision, no activity.
func (m *Manager) Put(ctx context.Context, spec site.Site, expectedRevision uint64, actor string) (site.Site, bool, error) {
	defer m.Locks.Lock(spec.ID)()

	spec = spec.WithDefaults()
	caps := m.Capabilities(ctx)
	if err := site.Validate(spec, caps.Host()); err != nil {
		return site.Site{}, false, err
	}

	existing, err := m.Store.GetSite(spec.ID)
	creating := errors.Is(err, state.ErrNotFound)
	var previous *site.Site

	switch {
	case creating:
		if expectedRevision != 0 {
			return site.Site{}, false, state.ErrNotFound
		}
		spec.Directory = paths.SiteDirectory(spec.User, spec.DirectoryName())
		spec.NginxCustomised = false
		if err := m.checkName(spec); err != nil {
			return site.Site{}, false, err
		}
	case err != nil:
		return site.Site{}, false, err
	default:
		if existing.Revision != expectedRevision {
			return site.Site{}, false, state.ErrStaleRevision
		}
		if err := site.ValidateChange(existing, spec); err != nil {
			return site.Site{}, false, err
		}
		spec.Directory, spec.NginxCustomised = existing.Directory, existing.NginxCustomised
		keepPassword(&spec, existing)
		// These change what Nginx forwards to. A customised file isn't rewritten, so the site would stop answering.
		if _, served := existing.ReverbDomain(); existing.NginxCustomised && (spec.Octane != existing.Octane || served != hasReverb(spec)) {
			return site.Site{}, false, &site.InvalidError{Field: "nginx", Reason: "This site's Nginx configuration is customised, so ServerDog can't change what it forwards to. Reset it to the generated configuration first."}
		}
		if sameSettings(spec, existing) {
			return existing, false, nil
		}
		previous = &existing
	}

	if err := m.checkDomains(spec); err != nil {
		return site.Site{}, false, err
	}

	spec.ReverbPort, spec.OctanePort = 0, 0
	if hasReverb(spec) {
		// Without the guard any local user could take the port first and receive the domain's traffic.
		if m.SyncPorts != nil {
			if err := m.SyncPorts(ctx); err != nil {
				return site.Site{}, false, &site.InvalidError{Field: "domains", Reason: "This server's port guard isn't active, so Reverb can't get a port only this site may use. Update the agent, or check the serverdog-port-guard service."}
			}
		}
		if spec.ReverbPort, err = m.Store.SitePort(spec.ID, state.PortReverb); err != nil {
			return site.Site{}, false, err
		}
	}
	// The live port is the deploy's to set; turning Octane off forgets it.
	if spec.Octane && previous != nil && previous.Octane {
		spec.OctanePort = previous.OctanePort
	}

	if err := hashPassword(&spec); err != nil {
		return site.Site{}, false, err
	}

	user, err := m.ensureUser(ctx, spec, creating)
	if err != nil {
		return site.Site{}, false, err
	}

	if err := m.prepareFiles(ctx, spec, user, creating); err != nil {
		return site.Site{}, false, err
	}

	if err := m.refuseSlowRemovals(ctx, spec, previous); err != nil {
		return site.Site{}, false, err
	}

	// Before their units change. A Put that fails after this leaves those copies stopped, as the user asked.
	if err := m.stopProcesses(ctx, processes.Retired(spec, previous)); err != nil {
		return site.Site{}, false, err
	}

	// Rendered, applied and saved under the apply lock, like the deploy that leaves the placeholder page (renderNginx).
	var saved site.Site
	err = m.Applier.Hold(ctx, func(applier apply.Applier) error {
		// Again under the lock: another site may have taken a domain since the check above, and Nginx must never
		// see a second server block for it.
		if err := m.checkDomains(spec); err != nil {
			return err
		}

		plan, err := m.configPlan(spec, previous, caps)
		if err != nil {
			return err
		}
		if _, err := applier.Apply(ctx, plan); err != nil {
			return err
		}
		// Before saving: if this fails, the Put fails and doing it again retries the start.
		if err := m.startProcesses(ctx, spec, processes.Changed(spec, previous)); err != nil {
			return err
		}

		saved, err = m.Store.PutSite(spec, expectedRevision, m.Now())

		return err
	})
	if err != nil {
		return site.Site{}, false, err
	}

	if err := os.RemoveAll(m.Paths.File(paths.PendingKeyDir(spec.ID))); err != nil {
		slog.Warn("could not remove the pending deploy key", "site", spec.ID, "error", err)
	}

	kind, summary := "site.updated", "Changed the site's settings."
	if creating {
		kind, summary = "site.created", "Created the site."
	}
	m.Store.AddActivity(spec.ID, state.Activity{At: m.Now(), Kind: kind, Actor: actor, Summary: summary})

	if saved.RunsOwnServer() || saved.ReverbPort != 0 {
		m.syncPorts(ctx)
	}

	// Nginx is back on PHP-FPM, so the Octane servers can go.
	if previous != nil && previous.Octane && !saved.Octane {
		if err := m.retireOwnServer(ctx, saved); err != nil {
			slog.Warn("could not remove the site's Octane servers", "site", saved.ID, "error", err)
		}
	}

	if m.AfterPut != nil {
		m.AfterPut(ctx, saved, previous)
	}

	return saved, creating, nil
}

// checkDomains refuses a domain another site uses.
func (m *Manager) checkDomains(spec site.Site) error {
	for _, domain := range spec.Domains {
		owner, taken, err := m.Store.DomainOwner(domain.Name)
		if err != nil {
			return err
		}
		if taken && owner != spec.ID {
			return &state.DomainTakenError{Name: domain.Name, SiteID: owner}
		}
	}

	return nil
}

// checkName refuses a new site without a website whose directory another site has, such as a second one named worker
// for the same user. Websites can't collide (checkDomains), and a name has no dot, so it can't be a domain.
func (m *Manager) checkName(spec site.Site) error {
	if spec.HasWebsite() {
		return nil
	}

	existing, err := m.Store.ListSites()
	if err != nil {
		return err
	}

	for _, other := range existing {
		if other.Directory == spec.Directory {
			return &site.InvalidError{Field: "name", Reason: fmt.Sprintf("Another site of %s is named %s already.", spec.User, spec.Name)}
		}
	}

	return nil
}

// sameSettings reports whether a Put of spec would store what is stored already. Agent-owned fields are ignored,
// and an empty list equals a missing one.
func sameSettings(spec, stored site.Site) bool {
	spec.Revision, spec.CreatedAt = stored.Revision, stored.CreatedAt
	spec.ReverbPort, spec.OctanePort = stored.ReverbPort, stored.OctanePort

	for _, s := range []*site.Site{&spec, &stored} {
		if len(s.Domains) == 0 {
			s.Domains = nil
		}
		if len(s.Processes) == 0 {
			s.Processes = nil
		}
		if len(s.SharedPaths) == 0 {
			s.SharedPaths = nil
		}
	}

	return reflect.DeepEqual(spec, stored)
}

// Delete removes the site's configuration and records. removeFiles also deletes its directory, and its user when isolated.
//
// Order matters: Nginx stops serving the site first, and a rejected change leaves everything running. Only then are
// Node instances stopped and the unit removed. Leftover files (keys, directory, user) are removed last; any failure
// is returned and keeps the site's record, so deleting again retries the remaining work.
func (m *Manager) Delete(ctx context.Context, id string, removeFiles bool, actor string) error {
	defer m.Locks.Lock(id)()

	s, err := m.Store.GetSite(id)
	if err != nil {
		return err
	}

	if _, running, err := m.Store.RunningDeployment(id); err != nil {
		return err
	} else if running {
		return state.ErrDeployRunning
	}

	var ports [2]int
	if s.RunsOwnServer() {
		if ports, err = m.Store.NodePorts(id); err != nil {
			return err
		}
	}

	var servingPlan apply.Plan
	if s.HasWebsite() {
		servingPlan = apply.Plan{
			Files: []apply.File{
				{Path: m.Paths.File(paths.NginxSiteEnabled(id)), Remove: true},
				{Path: m.Paths.File(paths.NginxSiteAvailable(id)), Remove: true},
				{Path: m.Paths.File(paths.NginxPasswords(id)), Remove: true},
			},
			Checks:  []system.Command{nginx.Check},
			Reloads: []system.Command{nginx.Reload},
		}
	}

	if s.Scheduler {
		servingPlan.Files = append(servingPlan.Files, apply.File{Path: m.Paths.File(paths.SchedulerCron(id)), Remove: true})
	}

	switch {
	case s.Runtime == site.PHP && s.HasWebsite():
		servingPlan.Files = append(servingPlan.Files, apply.File{Path: m.Paths.File(paths.FPMPool(s.PHPVersion, id)), Remove: true})
		if phpfpm.Installed(m.Paths, s.PHPVersion) {
			servingPlan.Checks = append(servingPlan.Checks, phpfpm.Check(s.PHPVersion))
			servingPlan.Reloads = append([]system.Command{phpfpm.Reload(s.PHPVersion)}, servingPlan.Reloads...)
		}
	}
	if s.RunsOwnServer() {
		servingPlan.Files = append(servingPlan.Files, apply.File{Path: m.Paths.File(paths.NginxUpstream(id)), Remove: true})
	}

	if _, err := m.Applier.Apply(ctx, servingPlan); err != nil {
		return err
	}

	if s.RunsOwnServer() {
		if err := m.removeNodeService(ctx, s, ports); err != nil {
			return err
		}
	}

	if err := m.removeProcesses(ctx, s); err != nil {
		return err
	}

	var failures []error

	for _, logical := range []string{paths.SiteEtcDir(id), paths.DeployLogDir(id), paths.PendingKeyDir(id)} {
		if err := os.RemoveAll(m.Paths.File(logical)); err != nil {
			failures = append(failures, err)
		}
	}

	if user, err := m.LookupUser(s.User); err == nil {
		files := m.files(user)
		key := m.Paths.File(paths.DeployKey(s.User, id))

		if err := files.Remove(ctx, key, key+".pub", m.Paths.File(paths.SiteKnownHosts(s.User, id))); err != nil {
			failures = append(failures, fmt.Errorf("remove deploy key: %w", err))
		}

		if removeFiles {
			if err := files.Remove(ctx, m.Paths.File(s.Directory)); err != nil {
				failures = append(failures, fmt.Errorf("remove site directory: %w", err))
			}
		}

		if removeFiles && s.Isolated {
			if _, err := m.System.Run(ctx, system.Command{Name: "userdel", Args: []string{"--remove", s.User}}); err != nil {
				failures = append(failures, fmt.Errorf("remove user %s: %w", s.User, err))
			}
		}
	}

	if err := errors.Join(failures...); err != nil {
		return err
	}

	held, _ := m.Store.NodePortUsers()

	if err := m.Store.DeleteSiteData(id); err != nil {
		return err
	}

	// A site that held a port (Node, Reverb, Octane, even one it no longer used) gives up the right to bind it.
	if left, _ := m.Store.NodePortUsers(); len(left) != len(held) {
		m.syncPorts(ctx)
	}

	// Last, so that a failure above can't leave certificate rows without their files.
	return os.RemoveAll(m.Paths.File(paths.SiteCertificates(id)))
}

// syncPorts lets the site users bind their Node sites' ports. A failure is only logged: running sites keep their
// sockets, and the next Node deploy syncs again and refuses to start a release while the guard is out of step.
func (m *Manager) syncPorts(ctx context.Context) {
	if m.SyncPorts == nil {
		return
	}

	if err := m.SyncPorts(ctx); err != nil {
		slog.Warn("could not sync the Node port guard", "error", err)
	}
}

// refuseSlowRemovals refuses to remove copies that still run and may take longer to stop than a save waits. Their
// unit must stay until they stopped, or systemd forgets how long they were given and kills them early.
func (m *Manager) refuseSlowRemovals(ctx context.Context, s site.Site, previous *site.Site) error {
	if previous == nil {
		return nil
	}

	for _, old := range previous.Processes {
		if site.StopTimeout(old.StopSeconds) <= site.StopPatience {
			continue
		}

		names := processes.Instances(previous.ID, old)
		if index := slices.IndexFunc(s.Processes, func(p site.Process) bool { return p.ID == old.ID }); index >= 0 {
			names = processes.Extra(previous.ID, old, s.Processes[index].Count)
		}
		if system.AnyActive(ctx, m.System, names) {
			return site.TooSlowToRemove(old.Name, site.StopTimeout(old.StopSeconds))
		}
	}

	return nil
}

func hasReverb(s site.Site) bool {
	_, serves := s.ReverbDomain()

	return serves
}

// retireOwnServer stops a site's release servers and removes their unit, once Nginx no longer sends them anything.
func (m *Manager) retireOwnServer(ctx context.Context, s site.Site) error {
	ports, err := m.Store.NodePorts(s.ID)
	if err != nil {
		return err
	}
	if err := m.Store.SetLivePort(s.ID, 0); err != nil {
		return err
	}

	return m.removeNodeService(ctx, s, ports)
}

func (m *Manager) removeNodeService(ctx context.Context, s site.Site, ports [2]int) error {
	var failures []error

	if _, err := os.Lstat(m.Paths.File(paths.SystemdUnit(nodeservice.Template(s.ID)))); errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	for _, port := range ports {
		if _, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: []string{"disable", "--now", nodeservice.Instance(s.ID, port)}}); err != nil {
			failures = append(failures, fmt.Errorf("stop %s: %w", nodeservice.Instance(s.ID, port), err))
		}
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}

	_, err := m.Applier.Apply(ctx, apply.Plan{
		Files: []apply.File{
			{Path: m.Paths.File(paths.SystemdUnit(nodeservice.Template(s.ID))), Remove: true},
			{Path: m.Paths.File(nodeservice.StartScript(s.ID)), Remove: true},
		},
		Reloads: []system.Command{{Name: "systemctl", Args: []string{"daemon-reload"}}},
	})

	return err
}

// stopProcesses stops and disables the given process copies, waiting for each to finish (up to its unit's stop timeout).
func (m *Manager) stopProcesses(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}

	result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: append([]string{"disable", "--now"}, names...)})
	if err != nil {
		return fmt.Errorf("Couldn't stop the site's removed processes.\n\n%s", system.Tail(result.Output, 5))
	}

	return nil
}

// startProcesses enables every copy of the given processes and restarts them without waiting. Units wait for the
// site's live release (ConditionPathExists), so before the first deploy this only enables them. Stopped processes are
// disabled instead, and stop without waiting for their stop timeout.
func (m *Manager) startProcesses(ctx context.Context, s site.Site, changed []site.Process) error {
	var started, stopped []string
	for _, p := range changed {
		if p.Stopped {
			stopped = append(stopped, processes.Instances(s.ID, p)...)
		} else {
			started = append(started, processes.Instances(s.ID, p)...)
		}
	}

	var commands [][]string
	if len(stopped) > 0 {
		commands = append(commands, append([]string{"disable", "--now", "--no-block"}, stopped...))
	}
	if len(started) > 0 {
		commands = append(commands, append([]string{"enable"}, started...), append([]string{"restart", "--no-block"}, started...))
	}

	for _, args := range commands {
		if result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: args}); err != nil {
			return fmt.Errorf("Couldn't start or stop the site's processes.\n\n%s", system.Tail(result.Output, 5))
		}
	}

	return nil
}

// RestartProcess restarts every copy of one of the site's processes without waiting, as a deploy does.
func (m *Manager) RestartProcess(ctx context.Context, siteID, processID, actor string) error {
	s, err := m.Store.GetSite(siteID)
	if err != nil {
		return err
	}

	for _, p := range s.Processes {
		if p.ID != processID {
			continue
		}
		if p.Stopped {
			return ErrProcessStopped
		}

		args := append([]string{"restart", "--no-block"}, processes.Instances(s.ID, p)...)
		if result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: args}); err != nil {
			return fmt.Errorf("Couldn't restart %s.\n\n%s", p.Name, system.Tail(result.Output, 5))
		}

		m.Store.AddActivity(s.ID, state.Activity{At: m.Now(), Kind: "process.restarted", Actor: actor, Summary: "Restarted " + p.Name + "."})

		return nil
	}

	return state.ErrNotFound
}

// removeProcesses stops every process of s and removes their units and start scripts.
func (m *Manager) removeProcesses(ctx context.Context, s site.Site) error {
	if len(s.Processes) == 0 {
		return nil
	}

	if err := m.stopProcesses(ctx, processes.AllInstances(s)); err != nil {
		return err
	}

	_, err := m.Applier.Apply(ctx, apply.Plan{
		Files:   m.processFiles(s, s.Processes, true),
		Reloads: []system.Command{daemonReload},
	})

	return err
}

// processFiles returns the unit and start script of each process, or their removal.
func (m *Manager) processFiles(s site.Site, list []site.Process, remove bool) []apply.File {
	var files []apply.File
	for _, p := range list {
		unit := apply.File{Path: m.Paths.File(paths.SystemdUnit(processes.Template(s.ID, p.ID))), Remove: remove}
		script := apply.File{Path: m.Paths.File(processes.StartScript(s.ID, p.ID)), Remove: remove, Mode: 0o755}
		if !remove {
			unit.Content, script.Content = processes.RenderUnit(s, p), processes.RenderStartScript(p.Command)
		}
		files = append(files, unit, script)
	}

	return files
}

var daemonReload = system.Command{Name: "systemctl", Args: []string{"daemon-reload"}}

// Env returns the site's environment file and its sum.
func (m *Manager) Env(ctx context.Context, id string) ([]byte, string, error) {
	s, user, err := m.siteAndUser(id)
	if err != nil {
		return nil, "", err
	}
	if s.EnvironmentFile == "" {
		return nil, "", &site.InvalidError{Field: "environmentFile", Reason: "This site has no environment file."}
	}

	content, _, err := m.files(user).ReadFile(ctx, m.environmentPath(s))
	if err != nil {
		return nil, "", err
	}

	return content, Sum(content), nil
}

// EnvHead returns at most limit bytes of the site's environment file, for a look that must stay cheap whatever the
// site's user put there; nothing when the site has no such file.
func (m *Manager) EnvHead(ctx context.Context, id string, limit int) ([]byte, error) {
	s, user, err := m.siteAndUser(id)
	if err != nil || s.EnvironmentFile == "" {
		return nil, err
	}

	return m.files(user).ReadHead(ctx, m.environmentPath(s), limit)
}

// PutEnv replaces the environment file when it still has expectedSum.
func (m *Manager) PutEnv(ctx context.Context, id string, content []byte, expectedSum, actor string) (string, error) {
	defer m.Locks.Lock(id)()

	_, sum, err := m.Env(ctx, id)
	if err != nil {
		return "", err
	}
	if sum != expectedSum {
		return "", ErrStaleContent
	}

	s, user, err := m.siteAndUser(id)
	if err != nil {
		return "", err
	}

	if err := m.files(user).WriteFile(ctx, m.environmentPath(s), content, "0600"); err != nil {
		return "", err
	}

	m.Store.AddActivity(id, state.Activity{At: m.Now(), Kind: "env.changed", Actor: actor, Summary: "Changed " + s.EnvironmentFile + "."})

	return Sum(content), nil
}

// NginxConfig returns the site's Nginx config, its sum, and whether it was customised.
func (m *Manager) NginxConfig(ctx context.Context, id string) ([]byte, string, bool, error) {
	s, err := m.Store.GetSite(id)
	if err != nil {
		return nil, "", false, err
	}

	if !s.HasWebsite() {
		return nil, "", false, &site.InvalidError{Field: "nginx", Reason: "This site has no website, so it has no Nginx config."}
	}

	content, err := os.ReadFile(m.Paths.File(paths.NginxSiteAvailable(id)))
	if err != nil {
		return nil, "", false, fmt.Errorf("read nginx config: %w", err)
	}

	return content, Sum(content), s.NginxCustomised, nil
}

// PutNginxConfig saves a hand-edited config. Nginx must accept it; from then on ServerDog stops regenerating the file.
func (m *Manager) PutNginxConfig(ctx context.Context, id string, content []byte, expectedSum, actor string) (string, error) {
	defer m.Locks.Lock(id)()

	// Compared under the apply lock, so an edit of the placeholder config can't overwrite the config a deploy switched
	// to meanwhile. Saved before the lock goes, so a deploy leaving the placeholder page sees the config is customised.
	err := m.Applier.Hold(ctx, func(applier apply.Applier) error {
		_, sum, _, err := m.NginxConfig(ctx, id)
		if err != nil {
			return err
		}
		if sum != expectedSum {
			return ErrStaleContent
		}

		if _, err := applier.Apply(ctx, apply.Plan{
			Files:   []apply.File{{Path: m.Paths.File(paths.NginxSiteAvailable(id)), Content: content}},
			Checks:  []system.Command{nginx.Check},
			Reloads: []system.Command{nginx.Reload},
		}); err != nil {
			return err
		}

		_, err = m.Store.UpdateSite(id, func(s *site.Site) { s.NginxCustomised = true }, m.Now())

		return err
	})
	if err != nil {
		return "", err
	}
	m.Store.AddActivity(id, state.Activity{At: m.Now(), Kind: "nginx.customised", Actor: actor, Summary: "Saved a customised Nginx configuration."})

	return Sum(content), nil
}

// ResetNginxConfig regenerates the config and hands it back to ServerDog.
func (m *Manager) ResetNginxConfig(ctx context.Context, id, actor string) ([]byte, string, error) {
	defer m.Locks.Lock(id)()

	s, err := m.Store.GetSite(id)
	if err != nil {
		return nil, "", err
	}

	s.NginxCustomised = false
	caps := m.Capabilities(ctx)

	var content []byte
	err = m.Applier.Hold(ctx, func(applier apply.Applier) error {
		rendered, err := m.renderNginx(s, caps)
		if err != nil {
			return err
		}
		content = rendered

		if _, err := applier.Apply(ctx, apply.Plan{
			Files:   []apply.File{{Path: m.Paths.File(paths.NginxSiteAvailable(id)), Content: content}},
			Checks:  []system.Command{nginx.Check},
			Reloads: []system.Command{nginx.Reload},
		}); err != nil {
			return err
		}

		_, err = m.Store.UpdateSite(id, func(s *site.Site) { s.NginxCustomised = false }, m.Now())

		return err
	})
	if err != nil {
		return nil, "", err
	}
	m.Store.AddActivity(id, state.Activity{At: m.Now(), Kind: "nginx.reset", Actor: actor, Summary: "Reset the Nginx configuration to the generated one."})

	return content, Sum(content), nil
}

func (m *Manager) configPlan(s site.Site, previous *site.Site, caps capabilities.Capabilities) (apply.Plan, error) {
	var plan apply.Plan

	switch {
	case s.Runtime == site.PHP && s.HasWebsite():
		plan.Files = append(plan.Files, phpfpm.Helpers(m.Paths, s.PHPVersion)...)
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.FPMPool(s.PHPVersion, s.ID)), Content: phpfpm.RenderPool(s.ID, s.User, s.PHPWorkerLimit())})
		plan.Checks = append(plan.Checks, phpfpm.Check(s.PHPVersion))
		plan.Reloads = append(plan.Reloads, phpfpm.Reload(s.PHPVersion))

		if previous != nil && previous.PHPVersion != "" && previous.PHPVersion != s.PHPVersion {
			plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.FPMPool(previous.PHPVersion, s.ID)), Remove: true})
			// A version uninstalled since can't check or reload; its pool file goes all the same.
			if phpfpm.Installed(m.Paths, previous.PHPVersion) {
				plan.Checks = append(plan.Checks, phpfpm.Check(previous.PHPVersion))
				plan.Reloads = append(plan.Reloads, phpfpm.Reload(previous.PHPVersion))
			}
		}

	}

	if s.RunsOwnServer() {
		// Laravel reads its own .env; a Node site's is exported by the script.
		script := nodeservice.RenderOctaneStartScript(phpfpm.Binary(s.PHPVersion), s.AppDirectory, s.ForceHTTPS)
		if s.Runtime == site.Node {
			environment := ""
			if s.EnvironmentFile != "" {
				environment = path.Join(s.Directory, "shared", s.EnvironmentFile)
			}
			script = nodeservice.RenderStartScript(s.NodeStartCommand, environment)
		}

		plan.Files = append(plan.Files,
			apply.File{Path: m.Paths.File(paths.SystemdUnit(nodeservice.Template(s.ID))), Content: nodeservice.RenderUnit(s.ID, s.User)},
			apply.File{Path: m.Paths.File(nodeservice.StartScript(s.ID)), Content: script, Mode: 0o755},
		)

		upstream, err := m.firstUpstream(s.ID)
		if err != nil {
			return apply.Plan{}, err
		}
		if upstream != nil {
			plan.Files = append(plan.Files, *upstream)
		}
		plan.Reloads = append(plan.Reloads, system.Command{Name: "systemctl", Args: []string{"daemon-reload"}})
	}

	removed := processes.Removed(s, previous)
	plan.Files = append(plan.Files, m.processFiles(s, s.Processes, false)...)
	plan.Files = append(plan.Files, m.processFiles(s, removed, true)...)
	if (len(s.Processes) > 0 || len(removed) > 0) && !s.RunsOwnServer() {
		plan.Reloads = append(plan.Reloads, daemonReload)
	}
	// With Octane off, Nginx no longer includes the upstream; it goes in the same checked change.
	if previous != nil && previous.Octane && !s.Octane {
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.NginxUpstream(s.ID)), Remove: true})
	}

	switch {
	case s.Scheduler:
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.SchedulerCron(s.ID)), Content: processes.RenderSchedulerCron(s, phpfpm.Binary(s.PHPVersion))})
	case previous != nil && previous.Scheduler:
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.SchedulerCron(s.ID)), Remove: true})
	}

	if !s.HasWebsite() {
		return plan, nil
	}

	passwords := m.Paths.File(paths.NginxPasswords(s.ID))
	switch {
	case s.BasicAuth != nil:
		plan.Files = append(plan.Files, apply.File{Path: passwords, Content: []byte(s.BasicAuth.Username + ":" + s.BasicAuth.Hash + "\n"), Mode: 0o400})
		// Nginx's workers read it per request. Theirs alone: the shared site user is in the www-data group.
		plan.Checks = append(plan.Checks, system.Command{Name: "chown", Args: []string{"www-data:www-data", passwords}})
	case previous != nil && previous.BasicAuth != nil:
		plan.Files = append(plan.Files, apply.File{Path: passwords, Remove: true})
	}

	if !s.NginxCustomised {
		content, err := m.renderNginx(s, caps)
		if err != nil {
			return apply.Plan{}, err
		}
		plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.NginxSiteAvailable(s.ID)), Content: content})
	}
	plan.Files = append(plan.Files, apply.File{Path: m.Paths.File(paths.NginxSiteEnabled(s.ID)), Link: m.Paths.File(paths.NginxSiteAvailable(s.ID))})
	plan.Checks = append(plan.Checks, nginx.Check)
	plan.Reloads = append(plan.Reloads, nginx.Reload)

	return plan, nil
}

// firstUpstream is the upstream file a new Node site starts with, or nil once it exists: from then on deploys own it,
// and a Put racing a deploy's switch must not write the previous port back.
func (m *Manager) firstUpstream(siteID string) (*apply.File, error) {
	file := m.Paths.File(paths.NginxUpstream(siteID))
	if _, err := os.Lstat(file); err == nil {
		return nil, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("check nginx upstream: %w", err)
	}

	ports, err := m.Store.NodePorts(siteID)
	if err != nil {
		return nil, err
	}
	live, err := m.Store.LivePort(siteID)
	if err != nil {
		return nil, err
	}
	if live == 0 {
		live = ports[0]
	}

	return &apply.File{Path: file, Content: nodeservice.RenderUpstream(siteID, live)}, nil
}

// renderNginx generates the site's config: its placeholder page while it has one, its releases otherwise.
// The caller holds the apply lock (Applier.Hold) until it applied the config and saved what it rendered from: the
// deploy that leaves the placeholder page holds it to render, switch and remove the page.
func (m *Manager) renderNginx(s site.Site, caps capabilities.Capabilities) ([]byte, error) {
	return m.render(s, caps, m.showsPlaceholder(s), s.OctanePort != 0)
}

// render generates the config. octaneLive sends an Octane site's requests to its Octane server; until its first
// Octane deploy, PHP-FPM keeps serving it.
func (m *Manager) render(s site.Site, caps capabilities.Capabilities, placeholder, octaneLive bool) ([]byte, error) {
	var certificates map[string]nginx.Certificate
	if m.ActiveCertificates != nil {
		var err error
		if certificates, err = m.ActiveCertificates(s.ID); err != nil {
			return nil, fmt.Errorf("read the site's certificates: %w", err)
		}
	}

	return nginx.Render(nginx.Input{Site: s, HTTP2Directive: caps.NginxHTTP2Directive(), Certificates: certificates, Placeholder: placeholder, OctaneLive: octaneLive && s.Octane}), nil
}

func (m *Manager) siteAndUser(id string) (site.Site, system.User, error) {
	s, err := m.Store.GetSite(id)
	if err != nil {
		return site.Site{}, system.User{}, err
	}

	user, err := m.LookupUser(s.User)
	if err != nil {
		return site.Site{}, system.User{}, fmt.Errorf("The site's user %s is missing.", s.User)
	}

	return s, user, nil
}

func (m *Manager) environmentPath(s site.Site) string {
	if s.ZeroDowntime {
		return m.Paths.File(path.Join(s.Directory, "shared", s.EnvironmentFile))
	}

	return m.Paths.File(path.Join(s.Directory, "current", s.EnvironmentFile))
}

func (m *Manager) files(user system.User) userfs.FS {
	if !m.AsUser {
		return userfs.FS{Runner: m.Exec}
	}

	return userfs.FS{Runner: m.Exec, User: &user}
}

// ProcessStatus is whether one of a site's processes runs, with its recent output.
type ProcessStatus struct {
	ID                string
	Running           int
	WaitingForRelease bool
	Log               string
}

// Processes reports each process of the site: how many copies run, and the last lines of their journal.
func (m *Manager) Processes(ctx context.Context, id string, lines int) ([]ProcessStatus, error) {
	s, err := m.Store.GetSite(id)
	if err != nil {
		return nil, err
	}

	_, err = os.Stat(m.Paths.File(path.Join(s.Directory, "current")))
	waiting := errors.Is(err, fs.ErrNotExist)

	var statuses []ProcessStatus
	for _, p := range s.Processes {
		status := ProcessStatus{ID: p.ID, WaitingForRelease: waiting}

		names := processes.Instances(s.ID, p)
		result, err := m.System.Run(ctx, system.Command{Name: "systemctl", Args: append([]string{"show", "--property=ActiveState", "--value"}, names...)})
		if err != nil {
			return nil, fmt.Errorf("Couldn't read the state of %s.\n\n%s", p.Name, system.Tail(result.Output, 5))
		}
		for _, state := range strings.Fields(string(result.Output)) {
			if state == "active" {
				status.Running++
			}
		}

		// The journal may be empty or unreadable; the state above is what matters.
		pattern := strings.TrimSuffix(processes.Template(s.ID, p.ID), ".service") + "*"
		if lines == 0 {
			statuses = append(statuses, status)

			continue
		}
		if result, err := m.System.Run(ctx, system.Command{Name: "journalctl", Args: []string{"--no-pager", "--quiet", "--output=short-iso", "--lines=" + strconv.Itoa(lines), "--unit=" + pattern}}); err == nil {
			status.Log = string(result.Output)
		}

		statuses = append(statuses, status)
	}

	return statuses, nil
}

// keepPassword carries the stored hash into a change that sends no new password.
func keepPassword(spec *site.Site, existing site.Site) {
	if spec.BasicAuth == nil || spec.BasicAuth.Password != "" || existing.BasicAuth == nil {
		return
	}

	spec.BasicAuth.Hash = existing.BasicAuth.Hash
}

// hashPassword replaces a new password with its bcrypt hash, which is all that is stored.
func hashPassword(spec *site.Site) error {
	if spec.BasicAuth == nil || spec.BasicAuth.Password == "" && spec.BasicAuth.Hash != "" {
		return nil
	}
	// Checked here, not in Validate: only after keepPassword is it known whether a hash is stored.
	if spec.BasicAuth.Password == "" {
		return &site.InvalidError{Field: "basicAuth", Reason: "Enter a password to protect the site."}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(spec.BasicAuth.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash the site's password: %w", err)
	}

	spec.BasicAuth.Hash, spec.BasicAuth.Password = string(hash), ""

	return nil
}
