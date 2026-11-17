package monitor

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/notify"
	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
)

func TestAThresholdAlertsAfterFiveMinutesOnceAndAgainWhenItRecovers(t *testing.T) {
	info := sysinfo.Info{DiskTotal: 100, DiskUsed: 95, MemTotal: 100, MemUsed: 10, CPUCount: 2, Load5: 4}
	settings := notify.Settings{WebhookURL: "https://hooks.example/x", DiskPercent: 90, MemoryPercent: 90}
	var posted []string
	failing := false

	m := &Monitor{
		Collect:  func() (sysinfo.Info, error) { return info, nil },
		Settings: func() (notify.Settings, error) { return settings, nil },
		Post: func(_ context.Context, text string) error {
			if failing {
				return errors.New("down")
			}
			posted = append(posted, text)
			return nil
		},
		Host:   func() string { return "web-1" },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	for range Sustained - 1 {
		m.Check(context.Background())
	}
	if len(posted) != 0 {
		t.Fatalf("posted before %d checks: %q", Sustained, posted)
	}

	// The webhook is down for the fifth check, so the sixth posts.
	failing = true
	m.Check(context.Background())
	failing = false
	m.Check(context.Background())
	m.Check(context.Background())

	// Load is 200% but has no threshold; memory is under its own.
	if len(posted) != 1 || !strings.Contains(posted[0], "Disk use on web-1 is at 95%, at or above the 90% alert") {
		t.Fatalf("posted = %q, want one disk alert", posted)
	}

	info.DiskUsed = 50
	m.Check(context.Background())
	m.Check(context.Background())
	if len(posted) != 2 || !strings.Contains(posted[1], "Disk use on web-1 is back to 50%") {
		t.Fatalf("posted = %q, want the recovery once", posted)
	}

	// Removing the webhook forgets the counts.
	info.DiskUsed = 95
	for range Sustained - 1 {
		m.Check(context.Background())
	}
	settings.WebhookURL = ""
	m.Check(context.Background())
	settings.WebhookURL = "https://hooks.example/x"
	m.Check(context.Background())
	if len(posted) != 2 {
		t.Fatalf("posted = %q after the counts were reset", posted)
	}
}

func TestPutRefusesThresholdsOverTheirRange(t *testing.T) {
	if _, err := (&notify.Manager{}).Put(notify.Settings{DiskPercent: 101}, 0); err == nil {
		t.Fatal("Put took a disk threshold of 101%")
	}
}
