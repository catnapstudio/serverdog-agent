//go:build vmtest

package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
)

func TestTheServerAndSiteLogsCanBeRead(t *testing.T) {
	r := newRepo(t, map[string]string{"index.html": "logs\n"})
	s := createSite(t, newSite(agentv1.Runtime_RUNTIME_STATIC, "html", "logs.test", r.URL))
	mustDeploy(t, s.Id)
	expect(t, "logs.test", 200, "logs")

	// A Laravel log the site user owns, and one it can't read through a symlink.
	logs := filepath.Join(s.Directory, "current", "storage", "logs")
	sh(t, "/", "runuser", "-u", s.User, "--", "mkdir", "-p", logs)
	sh(t, "/", "runuser", "-u", s.User, "--", "sh", "-c", "echo 'production.ERROR: boom' > "+filepath.Join(logs, "laravel.log"))

	server := agentv1.NewServerServiceClient(conn)
	list, err := server.ListLogs(timeout(t), &agentv1.ListLogsRequest{})
	if err != nil {
		t.Fatal(err)
	}

	ids := map[string]bool{}
	for _, source := range list.Sources {
		ids[source.Id] = true
	}
	for _, id := range []string{"journal", "agent", "nginx-error", "site:" + s.Id + ":access", "site:" + s.Id + ":laravel"} {
		if !ids[id] {
			t.Errorf("ListLogs has no %s: %v", id, ids)
		}
	}

	read := func(id string) (string, error) {
		response, err := server.ReadLog(timeout(t), &agentv1.ReadLogRequest{Id: id, Lines: 20})
		return response.GetText(), err
	}

	if text, err := read("site:" + s.Id + ":access"); err != nil || !strings.Contains(text, "GET / ") {
		t.Errorf("access log = %q %v", text, err)
	}
	if text, err := read("site:" + s.Id + ":laravel"); err != nil || !strings.Contains(text, "boom") {
		t.Errorf("laravel log = %q %v", text, err)
	}
	if text, err := read("agent"); err != nil || text == "" {
		t.Errorf("agent log = %q %v", text, err)
	}

	// The site user swaps its log for a link to a root-only file: it is read as the site user, so it fails.
	if err := os.Remove(filepath.Join(logs, "laravel.log")); err != nil {
		t.Fatal(err)
	}
	sh(t, "/", "runuser", "-u", s.User, "--", "ln", "-s", "/etc/shadow", filepath.Join(logs, "laravel.log"))
	if text, err := read("site:" + s.Id + ":laravel"); err == nil || strings.Contains(text, "root:") {
		t.Errorf("a link to /etc/shadow was read: %q %v", text, err)
	}
}
