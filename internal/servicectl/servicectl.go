// Package servicectl lists the system services ServerDog installs, starts, stops, restarts and reloads them, and
// reboots the server.
package servicectl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/site"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Only these units are ever controlled: the app names one, never a command.
var (
	fixed  = []string{"nginx", "mysql", "mariadb", "postgresql", "redis-server", "memcached", "supervisor", "meilisearch"}
	phpFPM = regexp.MustCompile(`^php\d+\.\d+-fpm$`)
)

type Action string

const (
	Start   Action = "start"
	Stop    Action = "stop"
	Restart Action = "restart"
	Reload  Action = "reload"
)

type Service struct {
	Unit string
	// systemd's ActiveState: active, inactive, failed, activating, deactivating or reloading.
	State string
	// Nginx and PHP-FPM reread their config without dropping connections.
	Reloadable bool
}

// Error is a service that didn't do what it was asked; Detail is the end of its journal.
type Error struct {
	Summary string
	Detail  string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Summary
	}

	return e.Summary + "\n\n" + e.Detail
}

type Manager struct {
	Runner system.Runner
	// How long Reboot waits before rebooting, so its answer reaches the app first.
	RebootDelay time.Duration
}

// List returns the installed services ServerDog knows, sorted by unit.
func (m *Manager) List(ctx context.Context) ([]Service, error) {
	result, err := m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"list-unit-files", "--type=service", "--no-legend", "--no-pager", "--plain"}})
	if err != nil {
		return nil, err
	}

	var units []string
	scanner := bufio.NewScanner(bytes.NewReader(result.Output))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 || fields[1] == "alias" {
			continue
		}

		unit := strings.TrimSuffix(fields[0], ".service")
		if Known(unit) && !slices.Contains(units, unit) {
			units = append(units, unit)
		}
	}
	if len(units) == 0 {
		return nil, nil
	}
	slices.Sort(units)

	result, err = m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: append([]string{"show", "--property=ActiveState", "--value"}, units...)})
	if err != nil {
		return nil, err
	}

	states := strings.Fields(string(result.Output))
	services := make([]Service, 0, len(units))
	for i, unit := range units {
		state := "unknown"
		if i < len(states) {
			state = states[i]
		}
		services = append(services, Service{Unit: unit, State: state, Reloadable: reloadable(unit)})
	}

	return services, nil
}

// Control runs action on unit, which must be one List returns.
func (m *Manager) Control(ctx context.Context, unit string, action Action) error {
	if !slices.Contains([]Action{Start, Stop, Restart, Reload}, action) {
		return &site.InvalidError{Field: "action", Reason: "Pick start, stop, restart or reload."}
	}
	if action == Reload && !reloadable(unit) {
		return &site.InvalidError{Field: "action", Reason: fmt.Sprintf("%s can't reload; restart it instead.", unit)}
	}

	services, err := m.List(ctx)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(services, func(s Service) bool { return s.Unit == unit }) {
		return &site.InvalidError{Field: "unit", Reason: fmt.Sprintf("%s isn't a service ServerDog manages on this server.", unit)}
	}

	// A service that gave up after exiting too often refuses a start until its count is cleared.
	if index := slices.IndexFunc(services, func(s Service) bool { return s.Unit == unit }); (action == Start || action == Restart) && services[index].State == "failed" {
		m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{"reset-failed", unit}})
	}

	// The journal from a second before, so the detail is what this action logged, not earlier history.
	since := fmt.Sprintf("@%d", time.Now().Unix()-1)
	if _, err := m.Runner.Run(ctx, system.Command{Name: "systemctl", Args: []string{string(action), unit}}); err != nil {
		journal, _ := m.Runner.Run(ctx, system.Command{Name: "journalctl", Args: []string{"--unit", unit, "--since", since, "--lines", "15", "--no-pager", "--output", "json", "--output-fields", "MESSAGE,_PID"}})
		return &Error{Summary: fmt.Sprintf("%s didn't %s.", unit, action), Detail: serviceLines(journal.Output)}
	}

	return nil
}

// Reboot reboots the server after RebootDelay, in the background: the agent goes down with it.
func (m *Manager) Reboot() {
	go func() {
		time.Sleep(m.RebootDelay)
		_, _ = m.Runner.Run(context.Background(), system.Command{Name: "systemctl", Args: []string{"reboot"}})
	}()
}

// serviceLines keeps what the service itself logged, without systemd's "Reloading…" and "Reload failed…" around it;
// all of it when the service logged nothing.
func serviceLines(journal []byte) string {
	var own, all []string
	for _, line := range bytes.Split(journal, []byte("\n")) {
		var entry struct {
			Message any    `json:"MESSAGE"`
			PID     string `json:"_PID"`
		}
		if json.Unmarshal(line, &entry) != nil {
			continue
		}

		// journald sends a message with invalid UTF-8 as an array of bytes; those are skipped.
		message, ok := entry.Message.(string)
		if !ok {
			continue
		}

		all = append(all, message)
		if entry.PID != "1" {
			own = append(own, message)
		}
	}

	if len(own) == 0 {
		own = all
	}

	return strings.TrimSpace(strings.Join(own, "\n"))
}

// Known reports whether unit is a service ServerDog lists and controls.
func Known(unit string) bool {
	return slices.Contains(fixed, unit) || phpFPM.MatchString(unit)
}

func reloadable(unit string) bool {
	return unit == "nginx" || phpFPM.MatchString(unit)
}
