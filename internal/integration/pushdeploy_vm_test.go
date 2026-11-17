//go:build vmtest

package integration

import (
	"strings"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
)

func TestAPushIsDeployedWithinTwoMinutes(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "v1"})

	s := newSite(agentv1.Runtime_RUNTIME_STATIC, "static", "push.test", r.URL)
	s.DeployOnPush = true
	s = createSite(t, s)
	t.Cleanup(func() {
		sitesClient().DeleteSite(timeout(t), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor})
	})
	mustDeploy(t, s.Id)

	r.push(map[string]string{"index.html": "v2"}, "Second")
	head := sh(t, r.work, "git", "rev-parse", "HEAD")

	// The agent asks the repository every minute, so a push lands within two checks.
	var pushed *agentv1.Deployment
	for deadline := time.Now().Add(150 * time.Second); pushed == nil && time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		response, err := deploysClient().ListDeployments(timeout(t), &agentv1.ListDeploymentsRequest{SiteId: s.Id, Limit: 5})
		if err != nil {
			t.Fatal(err)
		}
		if newest := response.Deployments[0]; newest.Actor == "push" {
			pushed = newest
		}
	}
	if pushed == nil {
		t.Fatal("the push wasn't deployed within two and a half minutes")
	}

	d := mustWatch(t, pushed.Id)
	if !strings.HasPrefix(head, d.Commit) {
		t.Errorf("deployed %s, want the pushed %s", d.Commit, head)
	}
}
