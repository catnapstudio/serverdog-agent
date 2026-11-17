// Package apply changes server configuration safely: stage, swap, validate, reload, and put everything back on failure.
package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/catnapstudio/serverdog-agent/internal/lock"
	"github.com/catnapstudio/serverdog-agent/internal/system"
)

// File is one file to create, replace, link or remove. Paths are real (root-prefixed) paths in root-owned directories.
type File struct {
	Path    string
	Content []byte
	// Mode defaults to 0644.
	Mode os.FileMode
	// Link makes Path a symlink to Link instead of a regular file.
	Link   string
	Remove bool
}

// Plan is a set of file changes plus the commands that validate and activate them.
type Plan struct {
	Files   []File
	Checks  []system.Command
	Reloads []system.Command
}

// Error is a change that was rolled back. Summary is one sentence; Output is the tool's own message.
type Error struct {
	Summary string
	Output  string
}

func (e *Error) Error() string {
	if e.Output == "" {
		return e.Summary
	}

	return e.Summary + "\n\n" + e.Output
}

// Applier applies plans one at a time across processes (the agent and deploy runners share LockPath).
type Applier struct {
	Runner   system.Runner
	LockPath string

	// held is set on the Applier Hold hands out: its caller has the lock already.
	held bool
}

// Hold runs fn while holding the lock every Apply takes, so what fn reads, applies and saves is one change to anyone
// else applying through LockPath, in this process or another. fn applies through the Applier it is given, which
// doesn't take the lock again; it must not use another Applier for the same LockPath.
func (a Applier) Hold(ctx context.Context, fn func(Applier) error) error {
	if a.held {
		return fn(a)
	}

	release, err := lock.Acquire(ctx, a.LockPath)
	if err != nil {
		return err
	}
	defer release()

	a.held = true

	return fn(a)
}

type swapped struct {
	file File
	had  bool
}

// Apply makes the plan's files current. When nothing differs it does nothing and returns false.
func (a Applier) Apply(ctx context.Context, plan Plan) (bool, error) {
	if !a.held {
		release, err := lock.Acquire(ctx, a.LockPath)
		if err != nil {
			return false, err
		}
		defer release()
	}

	var changed []File
	for _, file := range plan.Files {
		if file.Mode == 0 {
			file.Mode = 0o644
		}

		same, err := unchanged(file)
		if err != nil {
			return false, err
		}
		if !same {
			changed = append(changed, file)
		}
	}

	if len(changed) == 0 {
		return false, nil
	}

	for _, file := range changed {
		if err := stage(file); err != nil {
			discardStaged(changed)
			return false, fmt.Errorf("write %s: %w", file.Path, err)
		}
	}

	var done []swapped
	for _, file := range changed {
		had, err := swapIn(file)
		if err != nil {
			err = errors.Join(fmt.Errorf("replace %s: %w", file.Path, err), restore(done))
			discardStaged(changed)
			return false, err
		}
		done = append(done, swapped{file: file, had: had})
	}

	for _, command := range plan.Checks {
		if result, err := a.Runner.Run(ctx, command); err != nil {
			output := strings.TrimSpace(string(result.Output))

			if restoreErr := restore(done); restoreErr != nil {
				return false, &Error{
					Summary: describe(command) + " rejected the change, and restoring the previous files failed.",
					Output:  joinOutput(output, restoreErr.Error()),
				}
			}

			return false, &Error{Summary: describe(command) + " rejected the change, so nothing was changed.", Output: output}
		}
	}

	for _, command := range plan.Reloads {
		if result, err := a.Runner.Run(ctx, command); err != nil {
			output := strings.TrimSpace(string(result.Output))
			problems := []error{restore(done)}

			for _, again := range plan.Reloads {
				if againResult, againErr := a.Runner.Run(context.WithoutCancel(ctx), again); againErr != nil {
					problems = append(problems, fmt.Errorf("%s again: %w: %s", describe(again), againErr, strings.TrimSpace(string(againResult.Output))))
				}
			}

			if failure := errors.Join(problems...); failure != nil {
				return false, &Error{
					Summary: describe(command) + " failed, and restoring the previous configuration also failed.",
					Output:  joinOutput(output, failure.Error()),
				}
			}

			return false, &Error{Summary: describe(command) + " failed, so the previous configuration was restored.", Output: output}
		}
	}

	for _, item := range done {
		os.Remove(previousPath(item.file.Path))
	}

	return true, nil
}

func unchanged(file File) (bool, error) {
	info, err := os.Lstat(file.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return file.Remove, nil
	}
	if err != nil {
		return false, err
	}

	if file.Remove {
		return false, nil
	}

	if file.Link != "" {
		target, err := os.Readlink(file.Path)

		return err == nil && target == file.Link, nil
	}

	if !info.Mode().IsRegular() || info.Mode().Perm() != file.Mode {
		return false, nil
	}

	current, err := os.ReadFile(file.Path)
	if err != nil {
		return false, err
	}

	return bytes.Equal(current, file.Content), nil
}

func stage(file File) error {
	if file.Remove {
		return nil
	}

	staged := stagedPath(file.Path)
	os.Remove(staged)

	if err := os.MkdirAll(filepath.Dir(file.Path), 0o755); err != nil {
		return err
	}

	if file.Link != "" {
		return os.Symlink(file.Link, staged)
	}

	if err := os.WriteFile(staged, file.Content, file.Mode); err != nil {
		return err
	}

	return os.Chmod(staged, file.Mode)
}

func swapIn(file File) (bool, error) {
	previous := previousPath(file.Path)
	os.Remove(previous)

	_, err := os.Lstat(file.Path)
	had := err == nil

	if had {
		if err := os.Rename(file.Path, previous); err != nil {
			return false, err
		}
	}

	if !file.Remove {
		if err := os.Rename(stagedPath(file.Path), file.Path); err != nil {
			if had {
				err = errors.Join(err, os.Rename(previous, file.Path))
			}
			return false, err
		}
	}

	return had, nil
}

func restore(done []swapped) error {
	var problems []error

	for i := len(done) - 1; i >= 0; i-- {
		item := done[i]

		if err := os.Remove(item.file.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			problems = append(problems, fmt.Errorf("remove %s: %w", item.file.Path, err))
			continue
		}

		if !item.had {
			continue
		}

		if err := os.Rename(previousPath(item.file.Path), item.file.Path); err != nil {
			problems = append(problems, fmt.Errorf("restore %s: %w", item.file.Path, err))
		}
	}

	return errors.Join(problems...)
}

func discardStaged(files []File) {
	for _, file := range files {
		os.Remove(stagedPath(file.Path))
	}
}

// Temp files sit beside the live file but start with a dot, so globs such as nginx's include of sites-enabled/* skip them.
func stagedPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".serverdog-new")
}

func previousPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".serverdog-prev")
}

func joinOutput(parts ...string) string {
	var kept []string

	for _, part := range parts {
		if part != "" {
			kept = append(kept, part)
		}
	}

	return strings.Join(kept, "\n")
}

func describe(command system.Command) string {
	if command.Description != "" {
		return command.Description
	}

	return strings.Join(append([]string{command.Name}, command.Args...), " ")
}
