// Package monitor posts to the server's webhook when disk use, memory use or load stays at or above a threshold the
// app set, and again when it drops back below.
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/notify"
	"github.com/catnapstudio/serverdog-agent/internal/sysinfo"
)

// Sustained is how many checks in a row a value must stay at or above its threshold before the alert.
const Sustained = 5

type Monitor struct {
	Collect  func() (sysinfo.Info, error)
	Settings func() (notify.Settings, error)
	Post     func(ctx context.Context, text string) error
	Host     func() string
	Logger   *slog.Logger

	// shortcut: kept in memory, so a restart during an alert posts it again; persist it if that turns out noisy.
	checks map[string]*check
}

type check struct {
	above   int
	alerted bool
}

type metric struct {
	name      string
	value     float64
	threshold uint32
}

// Run checks every interval until ctx ends.
func (m *Monitor) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.Check(ctx)
		}
	}
}

// Check reads the machine once and posts what crossed a threshold. A post that fails is tried again next check.
func (m *Monitor) Check(ctx context.Context) {
	if m.checks == nil {
		m.checks = map[string]*check{}
	}

	settings, err := m.Settings()
	if err != nil {
		m.Logger.Warn("could not read the monitor thresholds", "error", err)
		return
	}

	if settings.WebhookURL == "" || settings.DiskPercent == 0 && settings.MemoryPercent == 0 && settings.LoadPercent == 0 {
		clear(m.checks)
		return
	}

	info, err := m.Collect()
	if err != nil {
		m.Logger.Warn("could not read the system for the monitors", "error", err)
		return
	}

	for _, metric := range metrics(info, settings) {
		state := m.checks[metric.name]
		if state == nil {
			state = &check{}
			m.checks[metric.name] = state
		}

		if metric.threshold == 0 {
			*state = check{}
			continue
		}

		text := ""
		if metric.value >= float64(metric.threshold) {
			state.above++
			if state.above >= Sustained && !state.alerted {
				text = fmt.Sprintf("⚠️ %s on %s is at %.0f%%, at or above the %d%% alert for %d minutes.", metric.name, m.Host(), metric.value, metric.threshold, Sustained)
			}
		} else {
			state.above = 0
			if state.alerted {
				text = fmt.Sprintf("✅ %s on %s is back to %.0f%%, below the %d%% alert.", metric.name, m.Host(), metric.value, metric.threshold)
			}
		}

		if text == "" {
			continue
		}

		if err := m.Post(ctx, text); err != nil {
			m.Logger.Warn("could not post a monitor alert", "error", err)
			continue
		}
		state.alerted = !state.alerted
	}
}

func metrics(info sysinfo.Info, settings notify.Settings) []metric {
	return []metric{
		{"Disk use", percent(info.DiskUsed, info.DiskTotal), settings.DiskPercent},
		{"Memory use", percent(info.MemUsed, info.MemTotal), settings.MemoryPercent},
		{"Load", info.Load5 / float64(max(info.CPUCount, 1)) * 100, settings.LoadPercent},
	}
}

func percent(part, whole uint64) float64 {
	if whole == 0 {
		return 0
	}

	return float64(part) / float64(whole) * 100
}
