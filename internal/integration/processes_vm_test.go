//go:build vmtest

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

// processesUntil polls ListProcesses until ok accepts the site's first process, and fails the test after a minute.
func processesUntil(t *testing.T, siteID, want string, ok func(*agentv1.ProcessStatus) bool) *agentv1.ProcessStatus {
	t.Helper()

	var last *agentv1.ProcessStatus
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		response, err := sitesClient().ListProcesses(timeout(t), &agentv1.ListProcessesRequest{SiteId: siteID})
		if err != nil {
			t.Fatal(err)
		}
		if len(response.Processes) > 0 {
			last = response.Processes[0]
			if ok(last) {
				return last
			}
		}
	}

	t.Fatalf("processes never showed %s; last = %v", want, last)
	return nil
}

// unitState asks systemctl about a unit; it exits non-zero for the stopped and disabled states the tests look for.
func unitState(verb, unit string) string {
	output, _ := exec.Command("systemctl", verb, unit).CombinedOutput()
	return strings.TrimSpace(string(output))
}

func TestProcessesFollowTheLiveReleaseAndTheSchedulerRuns(t *testing.T) {
	version := phpVersion(t)
	r := newRepo(t, map[string]string{
		"VERSION": "v1",
		// Laravel's scheduler, as far as cron can tell: the agent's entry runs `php artisan schedule:run` in current.
		"artisan":          "<?php file_put_contents(__DIR__ . '/../../shared/scheduled', implode(' ', array_slice($argv, 1)) . \"\\n\", FILE_APPEND);\n",
		"public/index.php": "<?php echo 'ok';\n",
	})

	s := newSite(agentv1.Runtime_RUNTIME_PHP, "laravel", "processes.test", r.URL)
	s.PhpVersion, s.WebDirectory = version, "public"
	s.Scheduler = true
	s.Processes = []*agentv1.Process{{Id: ids.New(), Name: "Worker", Command: "sh -c 'echo started $(cat VERSION); exec sleep 600'", Count: 2}}
	s = createSite(t, s)
	unit := "serverdog-process-" + s.Id + "-" + s.Processes[0].Id

	processesUntil(t, s.Id, "waiting for the first release", func(p *agentv1.ProcessStatus) bool {
		return p.WaitingForRelease && p.Running == 0
	})

	mustDeploy(t, s.Id)
	processesUntil(t, s.Id, "two copies of v1", func(p *agentv1.ProcessStatus) bool {
		return !p.WaitingForRelease && p.Running == 2 && strings.Contains(p.Log, "started v1")
	})

	r.push(map[string]string{"VERSION": "v2"}, "Second")
	mustDeploy(t, s.Id)
	processesUntil(t, s.Id, "two copies of v2", func(p *agentv1.ProcessStatus) bool {
		return p.Running == 2 && strings.Count(p.Log, "started v2") == 2
	})

	scheduled := filepath.Join(s.Directory, "shared", "scheduled")
	for deadline := time.Now().Add(75 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if _, err := os.Stat(scheduled); err == nil {
			break
		}
	}
	content, err := os.ReadFile(scheduled)
	if err != nil || !strings.HasPrefix(string(content), "schedule:run\n") {
		t.Fatalf("the scheduler didn't run within a minute: %q %v", content, err)
	}
	if info, _ := os.Stat(scheduled); info.Sys().(*syscall.Stat_t).Uid == 0 {
		t.Error("the scheduler ran as root")
	}

	s.Processes[0].Count = 1
	put, err := sitesClient().PutSite(timeout(t), &agentv1.PutSiteRequest{Site: s, ExpectedRevision: s.Revision, Actor: actor})
	if err != nil {
		t.Fatal(err)
	}
	s = put.Site
	processesUntil(t, s.Id, "one copy", func(p *agentv1.ProcessStatus) bool { return p.Running == 1 })
	if state := unitState("is-enabled", unit+"@2.service"); !strings.Contains(state, "disabled") {
		t.Errorf("the second copy is still %s", state)
	}

	if _, err := sitesClient().DeleteSite(timeout(t), &agentv1.DeleteSiteRequest{Id: s.Id, RemoveFiles: true, Actor: actor}); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"/etc/systemd/system/" + unit + "@.service", "/etc/cron.d/serverdog-" + s.Id} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("%s survived the site: %v", file, err)
		}
	}
	if state := unitState("is-active", unit+"@1.service"); !strings.Contains(state, "inactive") {
		t.Errorf("the process still runs after the site was deleted: %s", state)
	}
}
