package server

import (
	"strings"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/nginx"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

var runtimes = map[site.Runtime]agentv1.Runtime{
	site.PHP:      agentv1.Runtime_RUNTIME_PHP,
	site.Node:     agentv1.Runtime_RUNTIME_NODE,
	site.Python:   agentv1.Runtime_RUNTIME_PYTHON,
	site.Static:   agentv1.Runtime_RUNTIME_STATIC,
	site.Balancer: agentv1.Runtime_RUNTIME_BALANCER,
}

var balancings = map[site.Balancing]agentv1.Balancing{
	site.RoundRobin:       agentv1.Balancing_BALANCING_ROUND_ROBIN,
	site.LeastConnections: agentv1.Balancing_BALANCING_LEAST_CONNECTIONS,
	site.IPHash:           agentv1.Balancing_BALANCING_IP_HASH,
}

var redirects = map[site.Redirect]agentv1.Redirect{
	site.FromWWW:    agentv1.Redirect_REDIRECT_FROM_WWW,
	site.ToWWW:      agentv1.Redirect_REDIRECT_TO_WWW,
	site.NoRedirect: agentv1.Redirect_REDIRECT_NONE,
}

var kinds = map[string]agentv1.DeploymentKind{
	state.KindDeploy:   agentv1.DeploymentKind_DEPLOYMENT_KIND_DEPLOY,
	state.KindRollback: agentv1.DeploymentKind_DEPLOYMENT_KIND_ROLLBACK,
}

var deploymentStates = map[string]agentv1.DeploymentState{
	state.Running:     agentv1.DeploymentState_DEPLOYMENT_STATE_RUNNING,
	state.Succeeded:   agentv1.DeploymentState_DEPLOYMENT_STATE_SUCCEEDED,
	state.Failed:      agentv1.DeploymentState_DEPLOYMENT_STATE_FAILED,
	state.Cancelled:   agentv1.DeploymentState_DEPLOYMENT_STATE_CANCELLED,
	state.TimedOut:    agentv1.DeploymentState_DEPLOYMENT_STATE_TIMED_OUT,
	state.Interrupted: agentv1.DeploymentState_DEPLOYMENT_STATE_INTERRUPTED,
}

var phases = map[string]agentv1.Phase{
	state.PhasePrepare:         agentv1.Phase_PHASE_PREPARE,
	state.PhaseFetch:           agentv1.Phase_PHASE_FETCH,
	state.PhaseCheckOut:        agentv1.Phase_PHASE_CHECK_OUT,
	state.PhaseLinkShared:      agentv1.Phase_PHASE_LINK_SHARED,
	state.PhaseBuild:           agentv1.Phase_PHASE_BUILD,
	state.PhaseActivate:        agentv1.Phase_PHASE_ACTIVATE,
	state.PhaseAfterActivation: agentv1.Phase_PHASE_AFTER_ACTIVATION,
	state.PhaseCleanUp:         agentv1.Phase_PHASE_CLEAN_UP,
}

var phaseStates = map[string]agentv1.PhaseState{
	state.PhasePending: agentv1.PhaseState_PHASE_STATE_PENDING,
	state.PhaseRunning: agentv1.PhaseState_PHASE_STATE_RUNNING,
	state.PhaseDone:    agentv1.PhaseState_PHASE_STATE_DONE,
	state.PhaseFailed:  agentv1.PhaseState_PHASE_STATE_FAILED,
	state.PhaseSkipped: agentv1.PhaseState_PHASE_STATE_SKIPPED,
}

func invert[K comparable, V comparable](m map[K]V) map[V]K {
	inverted := make(map[V]K, len(m))
	for k, v := range m {
		inverted[v] = k
	}

	return inverted
}

var (
	runtimesBack  = invert(runtimes)
	balancingBack = invert(balancings)
	redirectsBack = invert(redirects)
)

// siteFromProto reads what the app may set. Agent-owned fields (revision, directory, customised, created) are ignored.
func siteFromProto(p *agentv1.Site) site.Site {
	s := site.Site{
		ID:                   p.Id,
		Preset:               p.Preset,
		Runtime:              runtimesBack[p.Runtime],
		RepositoryURL:        p.RepositoryUrl,
		Branch:               p.Branch,
		PHPVersion:           p.PhpVersion,
		PHPWorkers:           int(p.PhpWorkers),
		WebDirectory:         p.WebDirectory,
		EnvironmentFile:      p.EnvironmentFile,
		SharedPaths:          p.SharedPaths,
		DeployScript:         p.DeployScript,
		ZeroDowntime:         p.ZeroDowntime,
		EnvironmentInScript:  p.EnvironmentInScript,
		ReleasesToKeep:       int(p.ReleasesToKeep),
		DeployTimeoutMinutes: int(p.DeployTimeoutMinutes),
		NodeStartCommand:     p.NodeStartCommand,
		Isolated:             p.Isolated,
		User:                 p.User,
		ForceHTTPS:           p.ForceHttps,
		HSTS:                 p.Hsts,
		Scheduler:            p.Scheduler,
		DeployOnPush:         p.DeployOnPush,
		NginxRules:           normalizeRules(p.NginxRules),
		DeployNotifications: site.DeployNotifications{
			SlackURL:   strings.TrimSpace(p.GetDeployNotifications().GetSlackUrl()),
			DiscordURL: strings.TrimSpace(p.GetDeployNotifications().GetDiscordUrl()),
			HookURL:    strings.TrimSpace(p.GetDeployNotifications().GetHookUrl()),
		},
		AppDirectory:    p.AppDirectory,
		Name:            p.Name,
		HealthCheckPath: p.HealthCheckPath,
		Octane:          p.Octane,
	}

	if p.BasicAuthUsername != "" {
		s.BasicAuth = &site.BasicAuth{Username: p.BasicAuthUsername, Password: p.BasicAuthPassword}
	}
	for _, r := range p.Redirects {
		s.Redirects = append(s.Redirects, site.PathRedirect{From: r.From, To: r.To, Permanent: r.Permanent})
	}
	for _, b := range p.Backends {
		s.Backends = append(s.Backends, site.Backend{Address: b.Address, Port: int(b.Port), Weight: int(b.Weight), Backup: b.Backup})
	}
	s.Balancing = balancingBack[p.Balancing]
	s.BackendTLS = p.BackendTls
	for _, domain := range p.Domains {
		s.Domains = append(s.Domains, site.Domain{Name: domain.Name, Wildcards: domain.Wildcards, Redirect: redirectsBack[domain.Redirect], Primary: domain.Primary, Reverb: domain.Reverb})
	}
	for _, process := range p.Processes {
		s.Processes = append(s.Processes, site.Process{ID: process.Id, Name: process.Name, Command: process.Command, Count: int(process.Count), Directory: process.Directory, Stopped: process.Stopped, StopSeconds: int(process.StopSeconds)})
	}

	return s
}

func siteToProto(s site.Site) *agentv1.Site {
	p := &agentv1.Site{
		Id:                   s.ID,
		Preset:               s.Preset,
		Runtime:              runtimes[s.Runtime],
		RepositoryUrl:        s.RepositoryURL,
		Branch:               s.Branch,
		PhpVersion:           s.PHPVersion,
		PhpWorkers:           uint32(s.PHPWorkers),
		WebDirectory:         s.WebDirectory,
		EnvironmentFile:      s.EnvironmentFile,
		SharedPaths:          s.SharedPaths,
		DeployScript:         s.DeployScript,
		ZeroDowntime:         s.ZeroDowntime,
		EnvironmentInScript:  s.EnvironmentInScript,
		ReleasesToKeep:       uint32(s.ReleasesToKeep),
		DeployTimeoutMinutes: uint32(s.DeployTimeoutMinutes),
		NodeStartCommand:     s.NodeStartCommand,
		Isolated:             s.Isolated,
		User:                 s.User,
		ForceHttps:           s.ForceHTTPS,
		Hsts:                 s.HSTS,
		NginxCustomised:      s.NginxCustomised,
		Revision:             s.Revision,
		Directory:            s.Directory,
		CreatedAt:            timestamp(s.CreatedAt),
		Scheduler:            s.Scheduler,
		DeployOnPush:         s.DeployOnPush,
		NginxRules:           s.NginxRules,
		NginxDefaultRules:    defaultRules(s),
		DeployNotifications:  deployNotifications(s.DeployNotifications),
		AppDirectory:         s.AppDirectory,
		Name:                 s.Name,
		HealthCheckPath:      s.HealthCheckPath,
		ReverbPort:           uint32(s.ReverbPort),
		Octane:               s.Octane,
		OctanePort:           uint32(s.OctanePort),
	}

	// The hash stays on the server; the app only learns the site is protected and by which username.
	if s.BasicAuth != nil {
		p.BasicAuthUsername = s.BasicAuth.Username
	}
	for _, r := range s.Redirects {
		p.Redirects = append(p.Redirects, &agentv1.PathRedirect{From: r.From, To: r.To, Permanent: r.Permanent})
	}
	for _, b := range s.Backends {
		p.Backends = append(p.Backends, &agentv1.Backend{Address: b.Address, Port: uint32(b.Port), Weight: uint32(b.Weight), Backup: b.Backup})
	}
	p.Balancing = balancings[s.Balancing]
	p.BackendTls = s.BackendTLS
	for _, domain := range s.Domains {
		p.Domains = append(p.Domains, &agentv1.Domain{Name: domain.Name, Wildcards: domain.Wildcards, Redirect: redirects[domain.Redirect], Primary: domain.Primary, Reverb: domain.Reverb})
	}
	for _, process := range s.Processes {
		p.Processes = append(p.Processes, &agentv1.Process{Id: process.ID, Name: process.Name, Command: process.Command, Count: uint32(process.Count), Directory: process.Directory, Stopped: process.Stopped, StopSeconds: uint32(process.StopSeconds)})
	}

	return p
}

func deploymentToProto(d state.Deployment) *agentv1.Deployment {
	p := &agentv1.Deployment{
		Id:            d.ID,
		SiteId:        d.SiteID,
		Kind:          kinds[d.Kind],
		State:         deploymentStates[d.State],
		WentLive:      d.WentLive,
		Actor:         d.Actor,
		Branch:        d.Branch,
		Commit:        d.Commit,
		CommitAuthor:  text(d.CommitAuthor),
		CommitMessage: text(d.CommitMessage),
		Release:       d.Release,
		Error:         text(d.Error),
		StartedAt:     timestamp(d.StartedAt),
		FinishedAt:    timestamp(d.FinishedAt),
	}

	for _, phase := range d.Phases {
		p.Phases = append(p.Phases, &agentv1.PhaseStatus{
			Phase:      phases[phase.Name],
			State:      phaseStates[phase.State],
			StartedAt:  timestamp(phase.StartedAt),
			FinishedAt: timestamp(phase.FinishedAt),
			Note:       text(phase.Note),
		})
	}

	return p
}

func timestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	return t.UTC().Format(time.RFC3339)
}

// text makes s valid UTF-8, which protobuf requires of strings. Deploy logs, commit messages and command lines can
// hold any bytes; each invalid one becomes U+FFFD. Offsets stay those of the bytes on disk.
func text(s string) string {
	return strings.ToValidUTF8(s, "\uFFFD")
}

// deployNotifications leaves the message out when nothing is set, as a site without any reads.
func deployNotifications(n site.DeployNotifications) *agentv1.DeployNotifications {
	if !n.Any() {
		return nil
	}

	return &agentv1.DeployNotifications{SlackUrl: n.SlackURL, DiscordUrl: n.DiscordURL, HookUrl: n.HookURL}
}

// normalizeRules stores rules with Unix line endings and one final newline, or nothing when they are blank.
func normalizeRules(rules string) string {
	rules = strings.TrimSpace(strings.ReplaceAll(rules, "\r\n", "\n"))
	if rules == "" {
		return ""
	}

	return rules + "\n"
}

// defaultRules are the generated rules shown for a site with a website; an Octane site's are the live ones once a
// deploy brought its server up.
func defaultRules(s site.Site) string {
	if !s.HasWebsite() {
		return ""
	}

	return nginx.DefaultRules(s, s.Octane && s.OctanePort != 0)
}
