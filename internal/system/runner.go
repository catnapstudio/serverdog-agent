// Package system runs commands on the server, optionally as another user.
package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Command is one process to run.
type Command struct {
	Name string
	Args []string
	Dir  string
	// Env replaces the environment when non-nil.
	Env []string
	// User runs the process with that user's ids; nil keeps the agent's.
	User  *User
	Stdin io.Reader
	// Stdout receives stdout and stderr when set; Result.Output is then empty.
	Stdout io.Writer
	// Description names the command in messages for people when its command line wouldn't read well.
	Description string
}

// Result is what a finished command produced.
type Result struct {
	Output   []byte
	ExitCode int
}

// ExitError is a command that ran and exited non-zero (or was killed: ExitCode -1).
type ExitError struct {
	Command  string
	ExitCode int
	Output   []byte
}

func (e *ExitError) Error() string {
	tail := Tail(e.Output, 5)
	if tail == "" {
		return fmt.Sprintf("%s exited with %d", e.Command, e.ExitCode)
	}

	return fmt.Sprintf("%s exited with %d: %s", e.Command, e.ExitCode, tail)
}

// Runner runs commands. Exec is the real one; systemtest.Fake scripts results in tests.
// AnyActive reports whether any of the systemd units still runs or is stopping. No units, none active.
func AnyActive(ctx context.Context, runner Runner, units []string) bool {
	if len(units) == 0 {
		return false
	}

	// Exits non-zero unless every unit is active; the states are on stdout either way.
	result, _ := runner.Run(ctx, Command{Name: "systemctl", Args: append([]string{"is-active"}, units...)})
	for _, state := range strings.Fields(string(result.Output)) {
		if state == "active" || state == "deactivating" || state == "reloading" {
			return true
		}
	}

	return false
}

type Runner interface {
	Run(ctx context.Context, cmd Command) (Result, error)
}

// Exec runs commands with os/exec. Each command gets its own process group, which is killed when ctx ends.
type Exec struct{}

func (Exec) Run(ctx context.Context, c Command) (Result, error) {
	cmd := exec.CommandContext(ctx, c.Name, c.Args...)
	cmd.Dir = c.Dir
	cmd.Env = c.Env
	cmd.Stdin = c.Stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if c.User != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: c.User.UID, Gid: c.User.GID, Groups: c.User.Groups}
	}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	var buffer bytes.Buffer
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
		cmd.Stderr = c.Stdout
	} else {
		cmd.Stdout = &buffer
		cmd.Stderr = &buffer
	}

	err := cmd.Run()
	result := Result{Output: buffer.Bytes()}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return result, &ExitError{Command: c.Name, ExitCode: exitErr.ExitCode(), Output: result.Output}
	}
	if err != nil {
		return result, fmt.Errorf("run %s: %w", c.Name, err)
	}

	return result, nil
}

// ExitCode returns the exit code carried by err, if err is an ExitError.
func ExitCode(err error) (int, bool) {
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode, true
	}

	return 0, false
}

// Tail returns the last n non-empty lines of output, trimmed.
func Tail(output []byte, n int) string {
	var lines []string
	for line := range strings.SplitSeq(string(output), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}

	return strings.Join(lines, "\n")
}
