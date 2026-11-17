package jobs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

func newManager(t *testing.T) (*Manager, string) {
	t.Helper()

	root := t.TempDir()
	store, err := state.Open(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	fake := &systemtest.Fake{}
	m := &Manager{
		Store: store, Paths: paths.Paths{Root: root}, System: fake,
		Applier: apply.Applier{Runner: fake, LockPath: filepath.Join(root, "apply.lock")},
		LookupUser: func(name string) (system.User, error) {
			if name == "root" || name == "serverdog" {
				return system.User{Name: name}, nil
			}
			return system.User{}, errors.New("unknown user")
		},
	}

	return m, filepath.Join(root, paths.JobsCron)
}

var backup = Job{ID: "backupbackup", Name: "Backup", Command: `tar czf "backup-$(date +%F).tgz" ~/files`, User: "serverdog", Schedule: "0 3 * * *"}

func TestJobsAreSavedAndWrittenForCron(t *testing.T) {
	m, cron := newManager(t)

	revision, err := m.Put(context.Background(), []Job{backup}, 0)
	if err != nil || revision != 1 {
		t.Fatalf("Put = %d, %v", revision, err)
	}

	content, _ := os.ReadFile(cron)
	want := `0 3 * * * serverdog /usr/bin/systemd-cat --identifier=serverdog-job-backupbackup /bin/sh -c 'echo "serverdog-job: started"; /bin/sh -c "$1"; code=$?; echo "serverdog-job: exited $code"; exit $code' serverdog-job 'tar czf "backup-$(date +\%F).tgz" ~/files'`
	if !strings.Contains(string(content), want+"\n") {
		t.Errorf("cron file =\n%s\nwant a line\n%s", content, want)
	}

	jobs, listed, err := m.List()
	if err != nil || listed != 1 || len(jobs) != 1 || jobs[0] != backup {
		t.Errorf("List = %v, %d, %v", jobs, listed, err)
	}

	if _, err := m.Put(context.Background(), nil, 0); !errors.Is(err, state.ErrStaleDocument) {
		t.Errorf("stale Put err = %v", err)
	}

	if _, err := m.Put(context.Background(), nil, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cron); !os.IsNotExist(err) {
		t.Errorf("the cron file survived the last job: %v", err)
	}
}

func TestInvalidJobsAreRefusedBeforeAnythingIsWritten(t *testing.T) {
	cases := map[string]func(*Job){
		"bad id":        func(j *Job) { j.ID = "x" },
		"no name":       func(j *Job) { j.Name = " " },
		"two lines":     func(j *Job) { j.Command = "a\nb" },
		"four fields":   func(j *Job) { j.Schedule = "* * * *" },
		"unsafe field":  func(j *Job) { j.Schedule = "* * * * * root" },
		"shell in time": func(j *Job) { j.Schedule = "* * * * $(id)" },
		"unknown macro": func(j *Job) { j.Schedule = "@often" },
		"unknown user":  func(j *Job) { j.User = "nobody2" },
		"bad user":      func(j *Job) { j.User = "Root" },
	}

	for name, change := range cases {
		m, cron := newManager(t)
		job := backup
		change(&job)

		if _, err := m.Put(context.Background(), []Job{job}, 0); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if _, err := os.Stat(cron); !os.IsNotExist(err) {
			t.Errorf("%s: wrote the cron file", name)
		}
	}

	m, _ := newManager(t)
	daily := backup
	daily.Schedule = "@daily"
	if _, err := m.Put(context.Background(), []Job{daily, {ID: "secondsecond", Name: "Prune", Command: "docker system prune -f", User: "root", Schedule: "*/15 1-5 * * mon-fri"}}, 0); err != nil {
		t.Errorf("valid jobs refused: %v", err)
	}
	if _, err := m.Put(context.Background(), []Job{backup, backup}, 1); err == nil {
		t.Error("a repeated id was accepted")
	}
}

func TestRewriteAddsRunMarkersToOldLines(t *testing.T) {
	m, cron := newManager(t)
	job := Job{ID: "oldjoboldjob", Name: "Old", Command: "true", User: "serverdog", Schedule: "@daily"}
	if _, err := m.Put(context.Background(), []Job{job}, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cron, []byte("@daily serverdog /usr/bin/systemd-cat --identifier=serverdog-job-oldjoboldjob /bin/sh -c 'true'\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := m.Rewrite(context.Background()); err != nil {
		t.Fatal(err)
	}

	content, _ := os.ReadFile(cron)
	if !strings.Contains(string(content), startMarker) {
		t.Errorf("cron file =\n%s", content)
	}
}
