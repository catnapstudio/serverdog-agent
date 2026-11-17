// Package pushdeploy deploys a site when its branch gets a new commit. It asks each repository for the branch's head
// once a minute rather than taking webhooks, so nothing reaches the agent from outside and any git host works.
package pushdeploy

import (
	"context"
	"log/slog"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/gitsource"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Actor is who push deploys are recorded as.
const Actor = "push"

// Interval is how often each repository is asked for its branch's head.
const Interval = time.Minute

// headTimeout bounds asking one repository.
const headTimeout = 30 * time.Second

type Poller struct {
	Store       *state.Store
	Credentials func(ctx context.Context, siteID string) (gitsource.Credentials, error)
	Head        func(ctx context.Context, rawURL, branch string, c gitsource.Credentials) (string, error)
	Deploy      func(ctx context.Context, siteID, actor string) (state.Deployment, bool, error)
	Logger      *slog.Logger

	// tried is the head each site was last deployed for by this poller, so a failed deploy isn't retried every minute.
	tried map[string]string
	// problems is each site's last logged problem, so a broken repository is logged once rather than every minute.
	problems map[string]string
}

// Run checks every Interval until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.Check(ctx)
		}
	}
}

// Check deploys every site with deploy on push whose branch head isn't the commit its last deploy was for.
func (p *Poller) Check(ctx context.Context) {
	if p.tried == nil {
		p.tried, p.problems = map[string]string{}, map[string]string{}
	}

	sites, err := p.Store.ListSites()
	if err != nil {
		p.Logger.Warn("push deploy: could not list sites", "error", err)
		return
	}

	for _, s := range sites {
		if !s.DeployOnPush || !s.HasRepository() {
			continue
		}

		if err := p.check(ctx, s.ID, s.RepositoryURL, s.Branch); err != nil {
			p.problem(s.ID, err.Error())
			continue
		}
		p.problem(s.ID, "")
	}
}

func (p *Poller) check(ctx context.Context, siteID, url, branch string) error {
	credentials, err := p.Credentials(ctx, siteID)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, headTimeout)
	head, err := p.Head(ctx, url, branch, credentials)
	cancel()
	if err != nil {
		return err
	}

	if head == p.tried[siteID] {
		return nil
	}

	last, err := p.lastDeployed(siteID)
	if err != nil {
		return err
	}
	if head == last {
		p.tried[siteID] = head
		return nil
	}

	d, running, err := p.Deploy(ctx, siteID, Actor)
	if err != nil {
		return err
	}
	if running {
		// A deploy started before the push may predate the commit: look again next time.
		return nil
	}

	p.tried[siteID] = head
	p.Logger.Info("push deploy started", "site", siteID, "branch", branch, "commit", head, "deployment", d.ID)

	return nil
}

// lastDeployed is the commit of the site's newest deploy, whatever its outcome. Rollbacks don't count: a site rolled
// back stays on that release until the branch moves.
func (p *Poller) lastDeployed(siteID string) (string, error) {
	deployments, err := p.Store.ListDeployments(siteID, 50)
	if err != nil {
		return "", err
	}

	for _, d := range deployments {
		if d.Kind == state.KindDeploy {
			return d.Commit, nil
		}
	}

	return "", nil
}

func (p *Poller) problem(siteID, message string) {
	if p.problems[siteID] == message {
		return
	}
	p.problems[siteID] = message

	if message != "" {
		p.Logger.Warn("push deploy: could not check the repository", "site", siteID, "error", message)
	}
}
