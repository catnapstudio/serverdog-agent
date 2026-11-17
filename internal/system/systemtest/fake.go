// Package systemtest provides a scripted system.Runner for tests.
package systemtest

import (
	"context"
	"strings"
	"sync"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// Fake records every command and answers from handlers registered by command name.
// Commands without a handler succeed with no output.
type Fake struct {
	mu       sync.Mutex
	calls    []system.Command
	handlers map[string]func(system.Command) (system.Result, error)
}

// Handle answers every later command called name with fn.
func (f *Fake) Handle(name string, fn func(system.Command) (system.Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.handlers == nil {
		f.handlers = map[string]func(system.Command) (system.Result, error){}
	}
	f.handlers[name] = fn
}

// Fail makes every later command called name exit with code and output.
func (f *Fake) Fail(name string, code int, output string) {
	f.Handle(name, func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte(output), ExitCode: code}, &system.ExitError{Command: name, ExitCode: code, Output: []byte(output)}
	})
}

func (f *Fake) Run(_ context.Context, cmd system.Command) (system.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, cmd)
	handler := f.handlers[cmd.Name]
	f.mu.Unlock()

	if handler == nil {
		return system.Result{}, nil
	}

	return handler(cmd)
}

// Calls returns every command run so far.
func (f *Fake) Calls() []system.Command {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]system.Command(nil), f.calls...)
}

// Commands returns every command run so far as "name arg arg".
func (f *Fake) Commands() []string {
	var lines []string
	for _, call := range f.Calls() {
		lines = append(lines, strings.Join(append([]string{call.Name}, call.Args...), " "))
	}

	return lines
}

// Reset forgets recorded calls but keeps handlers.
func (f *Fake) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = nil
}
