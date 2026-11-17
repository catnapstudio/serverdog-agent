//go:build vmtest

package integration

import (
	"os"
	"strings"
	"testing"

	agentv1 "github.com/catnapstudio/serverdog-agent/gen/serverdog/agent/v1"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
)

func TestASiteWithoutAWebsiteDeploysAndRunsItsProcess(t *testing.T) {
	r := newRepo(t, map[string]string{"VERSION": "v1"})

	s := newSite(agentv1.Runtime_RUNTIME_PHP, "laravel", "", r.URL)
	s.Domains, s.Name, s.PhpVersion = nil, "worker-"+strings.ToLower(ids.New()[:6]), phpVersion(t)
	s.Processes = []*agentv1.Process{{Id: ids.New(), Name: "Worker", Command: "sh -c 'echo started $(cat VERSION); exec sleep 600'", Count: 1}}
	s = createSite(t, s)

	if !strings.HasSuffix(s.Directory, "/"+s.Name) {
		t.Errorf("directory = %s", s.Directory)
	}
	for _, file := range []string{"/etc/nginx/sites-enabled/serverdog-" + s.Id + ".conf", s.Directory + "/placeholder"} {
		if _, err := os.Stat(file); !os.IsNotExist(err) {
			t.Errorf("%s exists: %v", file, err)
		}
	}

	mustDeploy(t, s.Id)
	processesUntil(t, s.Id, "the worker running v1", func(p *agentv1.ProcessStatus) bool {
		return p.Running == 1 && strings.Contains(p.Log, "started v1")
	})
}
