// Package deployscript splits a Forge-style deploy script at its release macros.
package deployscript

import (
	"fmt"
	"strings"
)

const (
	CreateRelease   = "$CREATE_RELEASE()"
	ActivateRelease = "$ACTIVATE_RELEASE()"
	RestartQueues   = "$RESTART_QUEUES()"
)

// restartQueuesShell replaces $RESTART_QUEUES(). Sub-project 3 adds the site's managed processes.
const restartQueuesShell = `if [ -f artisan ]; then "$SERVERDOG_PHP" artisan queue:restart; if [ -d vendor/laravel/horizon ]; then "$SERVERDOG_PHP" artisan horizon:terminate; fi; fi`

// Segments are the parts of a zero-downtime script, each run by its own bash.
// Every segment keeps the script's line count: lines outside it are blank, so bash's line numbers match the editor.
type Segments struct {
	Before string // before $CREATE_RELEASE(), in the site directory
	Build  string // between the macros, in the new release
	After  string // after $ACTIVATE_RELEASE(), in current
}

// Error is a script the agent can't run.
type Error struct {
	Line   int
	Reason string
}

func (e *Error) Error() string {
	if e.Line == 0 {
		return e.Reason
	}

	return fmt.Sprintf("line %d: %s", e.Line, e.Reason)
}

// Split cuts script at $CREATE_RELEASE() and $ACTIVATE_RELEASE(), which must each appear once, alone on their line, in that order.
func Split(script string) (Segments, error) {
	lines := strings.Split(script, "\n")
	create, activate := -1, -1

	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case CreateRelease:
			if create >= 0 {
				return Segments{}, &Error{Line: i + 1, Reason: CreateRelease + " appears twice."}
			}
			create = i
		case ActivateRelease:
			if activate >= 0 {
				return Segments{}, &Error{Line: i + 1, Reason: ActivateRelease + " appears twice."}
			}
			activate = i
		}
	}

	if create < 0 {
		return Segments{}, &Error{Reason: "Zero-downtime deploys need " + CreateRelease + " on a line of its own."}
	}
	if activate < 0 {
		return Segments{}, &Error{Reason: "Zero-downtime deploys need " + ActivateRelease + " on a line of its own."}
	}
	if activate < create {
		return Segments{}, &Error{Line: activate + 1, Reason: ActivateRelease + " must come after " + CreateRelease + "."}
	}

	return Segments{
		Before: segment(lines, 0, create),
		Build:  segment(lines, create+1, activate),
		After:  segment(lines, activate+1, len(lines)),
	}, nil
}

// InPlace prepares a script for a site without zero downtime: release macros are dropped.
func InPlace(script string) string {
	lines := strings.Split(script, "\n")

	return segment(lines, 0, len(lines))
}

// segment keeps lines[from:to] (with $RESTART_QUEUES() expanded and release macros blanked) and blanks the rest.
func segment(lines []string, from, to int) string {
	out := make([]string, len(lines))

	for i, line := range lines {
		if i < from || i >= to {
			continue
		}

		switch strings.TrimSpace(line) {
		case CreateRelease, ActivateRelease:
		case RestartQueues:
			out[i] = restartQueuesShell
		default:
			out[i] = line
		}
	}

	return strings.Join(out, "\n")
}
