//go:build vmtest

package integration

import (
	"strings"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
)

func TestAHealthCheckThatFailsFailsTheDeployButKeepsItLive(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "healthy\n"})
	spec := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "health.test", r.URL)
	spec.HealthCheckPath = "/missing.html"
	s := createSite(t, spec)

	d, log := deploy(t, s.Id)
	if d.State != agentv1.DeploymentState_DEPLOYMENT_STATE_FAILED || !d.WentLive || !strings.Contains(d.Error, "answered 404") {
		t.Fatalf("deployment = %s live %v %q\n%s", d.State, d.WentLive, d.Error, log)
	}

	s.HealthCheckPath = "/index.html"
	updated, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, ExpectedRevision: s.Revision, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}

	mustDeploy(t, updated.Site.Id)
}
