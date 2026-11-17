// Package userfs changes files inside a site user's home by running commands as that user.
// Root never writes there itself, so a symlink planted by the site user can't redirect a root write.
package userfs

import (
	"bytes"
	"context"
	"fmt"
	"strconv"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// FS runs file operations as User (nil in tests: the current user).
type FS struct {
	Runner system.Runner
	User   *system.User
}

// MkdirAll creates dirs (and parents) with mode, e.g. "0750".
func (f FS) MkdirAll(ctx context.Context, mode string, dirs ...string) error {
	_, err := f.run(ctx, nil, "install", append([]string{"-d", "-m", mode}, dirs...)...)

	return err
}

// WriteFile atomically replaces path with content (via stdin, never arguments) and sets mode.
// Each call writes its own temp file beside path, so concurrent writers never share one; the last rename wins.
func (f FS) WriteFile(ctx context.Context, path string, content []byte, mode string) error {
	const script = `umask 077 && tmp=$(mktemp -- "$1.serverdog-new.XXXXXX") && trap 'rm -f -- "$tmp"' EXIT && cat > "$tmp" && chmod "$2" "$tmp" && mv -f -- "$tmp" "$1"`

	_, err := f.run(ctx, bytes.NewReader(content), "sh", "-c", script, "sh", path, mode)

	return err
}

// ReadHead returns at most limit bytes of path when it is a regular file, and nothing otherwise. Unlike ReadFile it
// is safe on a path the user controls: a link to /dev/zero, a FIFO or a huge file can't fill the agent's memory or
// hold it up.
func (f FS) ReadHead(ctx context.Context, path string, limit int) ([]byte, error) {
	result, err := f.run(ctx, nil, "sh", "-c", `[ -f "$1" ] || exit 3; head -c "$2" -- "$1"`, "sh", path, strconv.Itoa(limit))
	if code, isExit := system.ExitCode(err); isExit && code == 3 {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return result.Output, nil
}

// ReadFile returns path's content; ok is false when it doesn't exist.
func (f FS) ReadFile(ctx context.Context, path string) ([]byte, bool, error) {
	result, err := f.run(ctx, nil, "sh", "-c", `[ -e "$1" ] || exit 3; cat -- "$1"`, "sh", path)
	if code, isExit := system.ExitCode(err); isExit && code == 3 {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}

	return result.Output, true, nil
}

// Remove deletes files or directories.
func (f FS) Remove(ctx context.Context, paths ...string) error {
	_, err := f.run(ctx, nil, "rm", append([]string{"-rf", "--"}, paths...)...)

	return err
}

func (f FS) run(ctx context.Context, stdin *bytes.Reader, name string, args ...string) (system.Result, error) {
	command := system.Command{Name: name, Args: args, User: f.User}
	if stdin != nil {
		command.Stdin = stdin
	}

	result, err := f.Runner.Run(ctx, command)
	if err != nil {
		return result, fmt.Errorf("%s as %s: %w", name, f.userName(), err)
	}

	return result, nil
}

func (f FS) userName() string {
	if f.User == nil {
		return "the current user"
	}

	return f.User.Name
}
