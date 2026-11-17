package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

const (
	startMarker = "serverdog-job: started"
	exitMarker  = "serverdog-job: exited "
)

// Run is a job's latest run, read from the markers its cron line writes.
type Run struct {
	Started  time.Time
	Finished time.Time
	ExitCode int
	// Started with no exit marker yet: still going, or killed with the server.
	Running bool
}

// Event is one line a job wrote to the journal: a run marker or its own output.
type Event struct {
	JobID   string
	At      time.Time
	Message string
	Cursor  string
}

// Start tells whether the line marks a run's start.
func (e Event) Start() bool { return e.Message == startMarker }

// Exit returns the exit code an exit marker carries.
func (e Event) Exit() (int, bool) {
	code, found := strings.CutPrefix(e.Message, exitMarker)
	if !found {
		return 0, false
	}

	n, err := strconv.Atoi(code)

	return n, err == nil
}

// LastRun reads the job's latest run from its last journal lines; zero when it hasn't run in them.
func (m *Manager) LastRun(ctx context.Context, id string) Run {
	events, _, err := m.events(ctx, []string{id}, "--lines=300")
	if err != nil {
		return Run{}
	}

	var run Run
	for _, e := range events {
		if e.Start() {
			run = Run{Started: e.At, Running: true}
		} else if code, ok := e.Exit(); ok && run.Running {
			run.Finished, run.ExitCode, run.Running = e.At, code, false
		}
	}

	return run
}

// Events returns what the jobs wrote after cursor, or since since when cursor is empty, oldest first, and the
// cursor to read on from.
func (m *Manager) Events(ctx context.Context, ids []string, cursor string, since time.Time) ([]Event, string, error) {
	from := fmt.Sprintf("--since=@%d", since.Unix())
	if cursor != "" {
		from = "--after-cursor=" + cursor
	}

	events, last, err := m.events(ctx, ids, from)
	if last == "" {
		last = cursor
	}

	return events, last, err
}

func (m *Manager) events(ctx context.Context, ids []string, from string) ([]Event, string, error) {
	if len(ids) == 0 {
		return nil, "", nil
	}

	args := []string{"--no-pager", "--quiet", "--output=json", "--output-fields=MESSAGE,SYSLOG_IDENTIFIER", from}
	for _, id := range ids {
		args = append(args, "--identifier="+identifier(id))
	}

	result, err := m.System.Run(ctx, system.Command{Name: "journalctl", Args: args})
	if err != nil {
		return nil, "", err
	}

	var events []Event
	cursor := ""
	for _, line := range bytes.Split(result.Output, []byte("\n")) {
		var entry struct {
			Message    any    `json:"MESSAGE"`
			Identifier string `json:"SYSLOG_IDENTIFIER"`
			Realtime   string `json:"__REALTIME_TIMESTAMP"`
			Cursor     string `json:"__CURSOR"`
		}
		if json.Unmarshal(line, &entry) != nil {
			continue
		}
		cursor = entry.Cursor

		// journald sends a message with invalid UTF-8 as an array of bytes; those are skipped.
		message, isText := entry.Message.(string)
		micros, err := strconv.ParseInt(entry.Realtime, 10, 64)
		jobID, isJob := strings.CutPrefix(entry.Identifier, "serverdog-job-")
		if !isText || err != nil || !isJob {
			continue
		}

		events = append(events, Event{JobID: jobID, At: time.UnixMicro(micros), Message: message, Cursor: entry.Cursor})
	}

	return events, cursor, nil
}
