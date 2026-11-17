package processes

import (
	"slices"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/site"
)

func TestADescriptionCannotBreakTheUnit(t *testing.T) {
	s := site.Site{ID: "abcdefghijkl", User: "serverdog", Directory: "/home/serverdog/a.com"}
	unit := string(RenderUnit(s, site.Process{ID: "workerid2345", Name: `50% \`, Command: "x", Count: 1}))

	if !strings.Contains(unit, "Description=ServerDog process 50%%   of site abcdefghijkl (copy %i)\nAfter=network.target\n") {
		t.Errorf("unit =\n%s", unit)
	}
}

func TestRetiredAndChanged(t *testing.T) {
	a := site.Process{ID: "aaaaaaaaaaaa", Name: "A", Command: "a", Count: 3}
	b := site.Process{ID: "bbbbbbbbbbbb", Name: "B", Command: "b", Count: 1}
	previous := site.Site{ID: "abcdefghijkl", Processes: []site.Process{a, b}}

	shrunk := a
	shrunk.Count = 1
	c := site.Process{ID: "cccccccccccc", Name: "C", Command: "c", Count: 1}
	next := site.Site{ID: "abcdefghijkl", Processes: []site.Process{shrunk, c}}

	wantRetired := []string{
		"serverdog-process-abcdefghijkl-aaaaaaaaaaaa@2.service",
		"serverdog-process-abcdefghijkl-aaaaaaaaaaaa@3.service",
		"serverdog-process-abcdefghijkl-bbbbbbbbbbbb@1.service",
	}
	if got := Retired(next, &previous); !slices.Equal(got, wantRetired) {
		t.Errorf("Retired = %v", got)
	}
	if got := Removed(next, &previous); len(got) != 1 || got[0].ID != b.ID {
		t.Errorf("Removed = %v", got)
	}
	if got := Changed(next, &previous); len(got) != 2 {
		t.Errorf("Changed = %v", got)
	}
	if got := Changed(previous, &previous); len(got) != 0 {
		t.Errorf("unchanged processes changed: %v", got)
	}
}

func TestProcessesAndTheSchedulerRunInTheirDirectories(t *testing.T) {
	s := site.Site{ID: "abcdefghijkl", User: "serverdog", Directory: "/home/serverdog/a.com", AppDirectory: "app"}

	unit := string(RenderUnit(s, site.Process{ID: "workerid2345", Name: "Worker", Command: "x", Count: 1, Directory: "app/worker"}))
	if !strings.Contains(unit, "ConditionPathExists=/home/serverdog/a.com/current\n") || !strings.Contains(unit, "WorkingDirectory=/home/serverdog/a.com/current/app/worker\n") {
		t.Errorf("unit =\n%s", unit)
	}

	cron := string(RenderSchedulerCron(s, "/usr/bin/php8.4"))
	if !strings.Contains(cron, "cd '/home/serverdog/a.com/current/app' && /usr/bin/php8.4 artisan schedule:run") {
		t.Errorf("cron = %s", cron)
	}
}

func TestRunningSkipsStoppedProcesses(t *testing.T) {
	s := site.Site{ID: "abcdefghijkl", Processes: []site.Process{
		{ID: "workerid2345", Count: 2},
		{ID: "stoppedid234", Count: 1, Stopped: true},
	}}

	got := Running(s)
	want := []string{"serverdog-process-abcdefghijkl-workerid2345@1.service", "serverdog-process-abcdefghijkl-workerid2345@2.service"}
	if !slices.Equal(got, want) {
		t.Errorf("Running = %v", got)
	}
}
