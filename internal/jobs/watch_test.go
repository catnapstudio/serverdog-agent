package jobs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

// journal answers journalctl with the lines added since the last read, like --after-cursor would.
type journal struct {
	mu      sync.Mutex
	pending []string
	n       int
}

func (j *journal) add(id string, at time.Time, message string) {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.n++
	j.pending = append(j.pending, fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"c%d","SYSLOG_IDENTIFIER":"serverdog-job-%s","MESSAGE":%q}`, at.UnixMicro(), j.n, id, message))
}

func (j *journal) answer(c system.Command) (system.Result, error) {
	if slices.Contains(c.Args, "--lines=300") {
		return system.Result{}, nil
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	out := strings.Join(j.pending, "\n")
	j.pending = nil

	return system.Result{Output: []byte(out)}, nil
}

func TestWatcherPostsFailuresMissesAndRecoveries(t *testing.T) {
	m, _ := newManager(t)
	j := &journal{}
	m.System.(*systemtest.Fake).Handle("journalctl", j.answer)

	every5 := Job{ID: "every5every5", Name: "Sync", Command: "sync", User: "serverdog", Schedule: "*/5 * * * *"}
	nightly := Job{ID: "nightlynight", Name: "Report", Command: "report", User: "serverdog", Schedule: "@daily"}
	if _, err := m.Put(context.Background(), []Job{every5, nightly}, 0); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 11, 13, 14, 0, 30, 0, time.UTC)
	var posts []string
	w := &Watcher{
		Jobs: m, Enabled: func() bool { return true }, Host: func() string { return "web-1" },
		Post:     func(_ context.Context, text string) error { posts = append(posts, text); return nil },
		Location: func() *time.Location { return time.UTC }, Now: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx := context.Background()

	w.Check(ctx)
	if len(posts) != 0 {
		t.Fatalf("posted on start: %v", posts)
	}

	j.add(every5.ID, now.Add(-29*time.Second), startMarker)
	j.add(every5.ID, now.Add(-28*time.Second), "boom")
	j.add(every5.ID, now.Add(-27*time.Second), exitMarker+"2")
	now = now.Add(time.Minute)
	w.Check(ctx)
	if len(posts) != 1 || !strings.Contains(posts[0], `"Sync" on web-1 failed with exit code 2.`) || !strings.HasSuffix(posts[0], "\nboom") {
		t.Fatalf("failure posts = %q", posts)
	}

	// A second failure in a row stays quiet.
	j.add(every5.ID, now.Add(-20*time.Second), startMarker)
	j.add(every5.ID, now.Add(-19*time.Second), exitMarker+"2")
	w.Check(ctx)
	if len(posts) != 1 {
		t.Fatalf("repeat failure posted: %q", posts)
	}

	// 14:05 passes with no run; it's missed once the grace ends.
	now = time.Date(2026, 11, 13, 14, 9, 0, 0, time.UTC)
	w.Check(ctx)
	now = now.Add(time.Minute)
	w.Check(ctx)
	if len(posts) != 2 || posts[1] != `⚠️ Scheduled job "Sync" on web-1 didn't run at Nov 13 14:05 UTC.` {
		t.Fatalf("missed posts = %q", posts)
	}

	j.add(every5.ID, time.Date(2026, 11, 13, 14, 10, 1, 0, time.UTC), startMarker)
	j.add(every5.ID, time.Date(2026, 11, 13, 14, 10, 2, 0, time.UTC), exitMarker+"0")
	now = time.Date(2026, 11, 13, 14, 11, 0, 0, time.UTC)
	w.Check(ctx)
	if len(posts) != 4 || posts[2] != `✅ Scheduled job "Sync" on web-1 ran again.` || posts[3] != `✅ Scheduled job "Sync" on web-1 succeeded again.` {
		t.Fatalf("recovery posts = %q", posts)
	}
}

func TestLastRunReadsTheNewestMarkers(t *testing.T) {
	m, _ := newManager(t)
	at := time.Date(2026, 11, 13, 14, 0, 0, 0, time.UTC)
	lines := []string{
		fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"a","SYSLOG_IDENTIFIER":"serverdog-job-x","MESSAGE":%q}`, at.UnixMicro(), startMarker),
		fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"b","SYSLOG_IDENTIFIER":"serverdog-job-x","MESSAGE":%q}`, at.Add(3*time.Second).UnixMicro(), exitMarker+"1"),
		fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","__CURSOR":"c","SYSLOG_IDENTIFIER":"serverdog-job-x","MESSAGE":%q}`, at.Add(time.Minute).UnixMicro(), startMarker),
	}
	m.System.(*systemtest.Fake).Handle("journalctl", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(strings.Join(lines, "\n"))}, nil
	})

	run := m.LastRun(context.Background(), "x")
	if !run.Running || !run.Started.Equal(at.Add(time.Minute)) {
		t.Errorf("run = %+v", run)
	}

	lines = lines[:2]
	run = m.LastRun(context.Background(), "x")
	if run.Running || run.ExitCode != 1 || !run.Finished.Equal(at.Add(3*time.Second)) {
		t.Errorf("run = %+v", run)
	}
}
