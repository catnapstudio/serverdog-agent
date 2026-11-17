// Package jobs keeps the server's scheduled jobs: commands cron runs as a user on a schedule, apart from any site.
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/apply"
	"github.com/catnapstudio/serverdog-agent/internal/ids"
	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/state"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

type Job struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Command  string `json:"command"`
	User     string `json:"user"`
	Schedule string `json:"schedule"`
}

// MaxJobs bounds the list.
const MaxJobs = 50

// document is where the store keeps the list.
const document = "scheduled_jobs"

var (
	field       = regexp.MustCompile(`^[0-9A-Za-z*,/-]+$`)
	macros      = []string{"@reboot", "@hourly", "@daily", "@midnight", "@weekly", "@monthly", "@yearly", "@annually"}
	userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// Manager validates, saves and applies the jobs. The cron file is rewritten from the whole list on each change.
type Manager struct {
	Store      *state.Store
	Paths      paths.Paths
	Applier    apply.Applier
	System     system.Runner
	LookupUser func(string) (system.User, error)

	mu sync.Mutex
}

// List returns the jobs and their revision, the one Put expects.
func (m *Manager) List() ([]Job, uint64, error) {
	encoded, revision, err := m.Store.Document(document)
	if err != nil || encoded == nil {
		return nil, revision, err
	}

	var jobs []Job

	return jobs, revision, json.Unmarshal(encoded, &jobs)
}

// Put replaces the jobs. Nothing is saved unless the cron file was written.
func (m *Manager) Put(ctx context.Context, jobs []Job, expectedRevision uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.validate(jobs); err != nil {
		return 0, err
	}

	if _, current, err := m.Store.Document(document); err != nil {
		return 0, err
	} else if current != expectedRevision {
		return 0, state.ErrStaleDocument
	}

	file := apply.File{Path: m.Paths.File(paths.JobsCron), Content: Render(jobs)}
	if len(jobs) == 0 {
		file = apply.File{Path: m.Paths.File(paths.JobsCron), Remove: true}
	}
	if _, err := m.Applier.Apply(ctx, apply.Plan{Files: []apply.File{file}}); err != nil {
		return 0, err
	}

	encoded, err := json.Marshal(jobs)
	if err != nil {
		return 0, err
	}

	return m.Store.PutDocument(document, encoded, expectedRevision)
}

// Rewrite writes the cron file from the saved list again, so lines from an older agent get the run markers.
func (m *Manager) Rewrite(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	jobs, _, err := m.List()
	if err != nil || len(jobs) == 0 {
		return err
	}

	_, err = m.Applier.Apply(ctx, apply.Plan{Files: []apply.File{{Path: m.Paths.File(paths.JobsCron), Content: Render(jobs)}}})

	return err
}

// Log returns the last lines a job wrote, from the journal.
func (m *Manager) Log(ctx context.Context, id string, lines int) string {
	result, err := m.System.Run(ctx, system.Command{Name: "journalctl", Args: []string{"--no-pager", "--quiet", "--output=short-iso", fmt.Sprintf("--lines=%d", lines), "--identifier=" + identifier(id)}})
	if err != nil {
		return ""
	}

	var kept []string
	for _, line := range strings.Split(strings.TrimSpace(string(result.Output)), "\n") {
		if !strings.Contains(line, ": "+startMarker) && !strings.Contains(line, ": "+exitMarker) {
			kept = append(kept, line)
		}
	}

	return strings.Join(kept, "\n")
}

func identifier(id string) string { return "serverdog-job-" + id }

// wrapper marks each run's start and exit code in the job's journal, around the command it gets as $1.
const wrapper = `'echo "` + startMarker + `"; /bin/sh -c "$1"; code=$?; echo "` + exitMarker + `$code"; exit $code'`

// Render is the cron file. Each job's output goes to the journal under its own identifier, which Log and the run
// markers read.
func Render(jobs []Job) []byte {
	var b strings.Builder
	b.WriteString("# Managed by ServerDog: the server's scheduled jobs.\n")

	for _, job := range jobs {
		// cron turns an unescaped % into a newline.
		command := strings.ReplaceAll(shellQuote(job.Command), "%", `\%`)
		fmt.Fprintf(&b, "# %s\n%s %s /usr/bin/systemd-cat --identifier=%s /bin/sh -c %s serverdog-job %s\n", job.Name, job.Schedule, job.User, identifier(job.ID), wrapper, command)
	}

	return []byte(b.String())
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func (m *Manager) validate(jobs []Job) error {
	if len(jobs) > MaxJobs {
		return invalid("A server can have at most %d scheduled jobs.", MaxJobs)
	}

	seen := map[string]bool{}

	for _, job := range jobs {
		if !ids.Valid(job.ID) || seen[job.ID] {
			return invalid("The job id %q isn't valid or is listed twice.", job.ID)
		}
		seen[job.ID] = true

		if strings.TrimSpace(job.Name) == "" || strings.ContainsAny(job.Name, "\r\n") || len(job.Name) > 60 {
			return invalid("A scheduled job needs a single-line name of at most 60 characters.")
		}
		if strings.TrimSpace(job.Command) == "" || strings.ContainsAny(job.Command, "\r\n") || len(job.Command) > 1000 {
			return invalid("%s needs a command on a single line of at most 1000 characters.", job.Name)
		}
		if !ValidSchedule(job.Schedule) {
			return invalid("%s's schedule %q isn't a cron schedule, like */5 * * * * or @daily.", job.Name, job.Schedule)
		}
		if !userPattern.MatchString(job.User) {
			return invalid("%s's user %q isn't a valid user name.", job.Name, job.User)
		}
		if _, err := m.LookupUser(job.User); err != nil {
			return invalid("%s runs as %s, but this server has no such user.", job.Name, job.User)
		}
	}

	return nil
}

// ValidSchedule reports whether cron takes the schedule: five fields of digits, names, *, ",", "/" and "-", or a macro.
// Nothing else, so a schedule can't smuggle a user or a command into a cron line.
func ValidSchedule(schedule string) bool {
	if slices.Contains(macros, schedule) {
		return true
	}

	fields := strings.Fields(schedule)
	if len(fields) != 5 || strings.Join(fields, " ") != schedule {
		return false
	}

	for _, f := range fields {
		if !field.MatchString(f) {
			return false
		}
	}

	return true
}

func invalid(format string, args ...any) error {
	return &site.InvalidError{Field: "jobs", Reason: fmt.Sprintf(format, args...)}
}
