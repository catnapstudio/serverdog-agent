package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// Grace is how long after a scheduled minute a run may start before it counts as missed.
const Grace = 3 * time.Minute

// Watcher posts when a scheduled job fails or doesn't run when its schedule says, and when a missed job runs again.
// It only judges runs from when it started watching, never earlier history.
type Watcher struct {
	Jobs *Manager
	// Enabled tells whether alerts go anywhere: the server has a webhook.
	Enabled func() bool
	Post    func(ctx context.Context, text string) error
	Host    func() string
	// Location is the zone cron reads schedules in: the server's, which the app can change while the agent runs.
	Location func() *time.Location
	Now      func() time.Time
	Logger   *slog.Logger

	// shortcut: kept in memory, so a restart forgets a missed job and doesn't post its recovery; persist if that matters.
	started time.Time
	cursor  string
	tracked map[string]*watched
}

type watched struct {
	name         string
	schedule     string
	lastStart    time.Time
	checkedUntil time.Time
	lastOutput   string
	missed       bool
	// Its last run failed and that was posted; the next failures aren't, its next success is.
	failing bool
}

// Run checks every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Check(ctx)
		}
	}
}

// Check reads what the jobs logged since the last check, then looks for scheduled minutes nobody ran.
func (w *Watcher) Check(ctx context.Context) {
	now := w.Now()
	if w.started.IsZero() {
		w.started = now
		w.tracked = map[string]*watched{}
	}

	jobs, _, err := w.Jobs.List()
	if err != nil {
		w.Logger.Warn("could not read the scheduled jobs", "error", err)
		return
	}

	ids := w.track(ctx, jobs, now)

	events, cursor, err := w.Jobs.Events(ctx, ids, w.cursor, w.started)
	if err != nil {
		w.Logger.Warn("could not read the scheduled jobs' journal", "error", err)
		return
	}
	w.cursor = cursor

	for _, event := range events {
		job := w.tracked[event.JobID]
		if job == nil {
			continue
		}

		if event.Start() {
			job.lastStart, job.lastOutput = event.At, ""
			if job.missed {
				job.missed = false
				w.post(ctx, fmt.Sprintf("✅ Scheduled job %q on %s ran again.", job.name, w.Host()))
			}
			continue
		}

		if code, ok := event.Exit(); ok {
			switch {
			case code != 0 && !job.failing:
				job.failing = true
				w.post(ctx, failedText(job, w.Host(), code))
			case code == 0 && job.failing:
				job.failing = false
				w.post(ctx, fmt.Sprintf("✅ Scheduled job %q on %s succeeded again.", job.name, w.Host()))
			}
			job.lastOutput = ""
			continue
		}

		job.lastOutput = event.Message
	}

	location := w.Location()
	for _, job := range w.tracked {
		if missedAt, ok := job.findMissed(now.Add(-Grace), location); ok {
			job.missed = true
			w.post(ctx, fmt.Sprintf("⚠️ Scheduled job %q on %s didn't run at %s.", job.name, w.Host(), missedAt.In(location).Format("Jan 2 15:04 MST")))
		}
	}
}

// track follows the current list: new jobs and changed schedules are judged from now on.
func (w *Watcher) track(ctx context.Context, jobs []Job, now time.Time) []string {
	ids := make([]string, 0, len(jobs))
	current := map[string]bool{}

	for _, job := range jobs {
		ids = append(ids, job.ID)
		current[job.ID] = true

		tracked := w.tracked[job.ID]
		if tracked != nil && tracked.schedule == job.Schedule {
			tracked.name = job.Name
			continue
		}

		w.tracked[job.ID] = &watched{name: job.Name, schedule: job.Schedule, lastStart: w.Jobs.LastRun(ctx, job.ID).Started, checkedUntil: now.Truncate(time.Minute)}
	}

	for id := range w.tracked {
		if !current[id] {
			delete(w.tracked, id)
		}
	}

	return ids
}

// findMissed returns the first scheduled minute before end that no run started in, once per miss.
func (j *watched) findMissed(end time.Time, location *time.Location) (time.Time, bool) {
	spec, ok := ParseSchedule(j.schedule)
	end = end.Truncate(time.Minute)
	if !ok || j.missed || !end.After(j.checkedUntil) {
		return time.Time{}, false
	}

	from := j.checkedUntil
	if after := j.lastStart.Truncate(time.Minute).Add(time.Minute); after.After(from) {
		from = after
	}
	j.checkedUntil = end

	for t := from; t.Before(end); t = t.Add(time.Minute) {
		if spec.Matches(t.In(location)) {
			return t, true
		}
	}

	return time.Time{}, false
}

func (w *Watcher) post(ctx context.Context, text string) {
	if !w.Enabled() {
		return
	}

	if err := w.Post(ctx, text); err != nil {
		w.Logger.Warn("could not post a scheduled job alert", "error", err)
	}
}

func failedText(job *watched, host string, code int) string {
	text := fmt.Sprintf("❌ Scheduled job %q on %s failed with exit code %d. Later failures aren't posted until it succeeds again.", job.name, host, code)
	if job.lastOutput == "" {
		return text
	}

	output := job.lastOutput
	if len(output) > 300 {
		output = output[:300] + "…"
	}

	return text + "\n" + output
}
