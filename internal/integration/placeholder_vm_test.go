//go:build vmtest

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// placeholderText is in the page a site serves until its first release is live.
const placeholderText = "This site is set up on ServerDog."

func TestASiteWithoutARepositoryShowsAPlaceholderUntilItsFirstDeploy(t *testing.T) {
	resolveHere(t, "later.test", "www.later.test")

	spec := newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "later.test", "")
	spec.Branch = ""
	put, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: spec, Actor: actor})
	if err != nil {
		t.Fatalf("PutSite without a repository: %v", err)
	}
	t.Cleanup(func() {
		sitesClient().DeleteSite(context.Background(), &agentv1.DeleteSiteRequest{Id: spec.Id, RemoveFiles: true, Actor: actor})
	})
	s := put.Site

	if code, body, _, err := get("later.test"); err != nil || code != 200 || !strings.Contains(body, placeholderText) {
		t.Errorf("http://later.test = %d %q %v, want the placeholder page", code, body, err)
	}
	page, err := os.Stat(filepath.Join(s.Directory, "placeholder", "index.html"))
	if err != nil || page.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Errorf("placeholder page = %v %v, want one the site user owns", page, err)
	}
	if _, err := os.Stat("/home/serverdog/.ssh/serverdog-" + s.Id + ".known_hosts"); !os.IsNotExist(err) {
		t.Errorf("a site without a repository has known_hosts: %v", err)
	}

	waitForCertificate(t, s.Id, "later.test")
	if code, body, _, _, err := getTLS("later.test"); err != nil || code != 200 || !strings.Contains(body, placeholderText) {
		t.Errorf("https://later.test = %d %q %v, want the placeholder page", code, body, err)
	}

	_, err = deploysClient().Deploy(timeout(t), &agentv1.DeployRequest{SiteId: s.Id, Actor: actor})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "This site has no repository yet. Add one in its settings, then deploy." {
		t.Errorf("Deploy without a repository = %v", err)
	}

	r := newRepo(t, map[string]string{"index.html": "later v1\n"})
	s.RepositoryUrl, s.Branch = r.URL, "main"
	grantAccess(t, s)
	updated, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, ExpectedRevision: s.Revision, Actor: actor})
	if err != nil {
		t.Fatalf("PutSite adding the repository: %v", err)
	}
	s = updated.Site

	mustDeploy(t, s.Id)
	expect(t, "later.test", 200, "later v1")
	if code, body, _, _, err := getTLS("later.test"); err != nil || code != 200 || body != "later v1" {
		t.Errorf("https://later.test after the deploy = %d %q %v", code, body, err)
	}
	if _, err := os.Stat(filepath.Join(s.Directory, "placeholder")); !os.IsNotExist(err) {
		t.Errorf("the placeholder folder is still there: %v", err)
	}
	if moved, err := filepath.Glob(filepath.Join(s.Directory, ".placeholder-removed-*")); err != nil || len(moved) != 0 {
		t.Errorf("the moved placeholder folder is still there: %v %v", moved, err)
	}
}
