package apply

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/catnapstudio/serverdog-agent/internal/system"
	"github.com/catnapstudio/serverdog-agent/internal/system/systemtest"
)

var (
	check  = system.Command{Name: "nginx", Args: []string{"-t"}}
	reload = system.Command{Name: "systemctl", Args: []string{"reload", "nginx"}}
)

func setup(t *testing.T) (string, *systemtest.Fake, Applier) {
	t.Helper()

	dir := t.TempDir()
	runner := &systemtest.Fake{}

	return dir, runner, Applier{Runner: runner, LockPath: filepath.Join(dir, "apply.lock")}
}

func read(t *testing.T, path string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func TestApplyWritesValidatesAndReloads(t *testing.T) {
	dir, runner, applier := setup(t)
	site := filepath.Join(dir, "sites-available/a.conf")
	enabled := filepath.Join(dir, "sites-enabled/a.conf")

	changed, err := applier.Apply(context.Background(), Plan{
		Files:   []File{{Path: site, Content: []byte("new")}, {Path: enabled, Link: site}},
		Checks:  []system.Command{check},
		Reloads: []system.Command{reload},
	})
	if err != nil || !changed {
		t.Fatalf("Apply = %v, %v", changed, err)
	}

	if read(t, site) != "new" {
		t.Error("content not written")
	}
	if target, _ := os.Readlink(enabled); target != site {
		t.Errorf("link = %q", target)
	}
	if !reflect.DeepEqual(runner.Commands(), []string{"nginx -t", "systemctl reload nginx"}) {
		t.Errorf("commands = %v", runner.Commands())
	}

	if found := leftovers(t, dir); len(found) != 0 {
		t.Errorf("leftover files: %v", found)
	}
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()

	var found []string
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && strings.Contains(entry.Name(), ".serverdog-") {
			found = append(found, path)
		}

		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	return found
}

// globLikeNginx lists what glob(3) matches for "dir/*": everything except names starting with a dot.
func globLikeNginx(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var matched []string
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			matched = append(matched, filepath.Join(dir, entry.Name()))
		}
	}

	return matched
}

func TestTempFilesAreInvisibleToGlobs(t *testing.T) {
	dir, runner, applier := setup(t)
	enabled := filepath.Join(dir, "sites-enabled")
	kept := filepath.Join(enabled, "serverdog-kept.conf")
	removed := filepath.Join(enabled, "serverdog-removed.conf")
	os.MkdirAll(enabled, 0o755)
	os.WriteFile(kept, []byte("old"), 0o644)
	os.WriteFile(removed, []byte("gone"), 0o644)

	var seen []string
	runner.Handle("nginx", func(system.Command) (system.Result, error) {
		seen = globLikeNginx(t, enabled)

		return system.Result{}, nil
	})

	_, err := applier.Apply(context.Background(), Plan{
		Files:  []File{{Path: kept, Content: []byte("new")}, {Path: removed, Remove: true}},
		Checks: []system.Command{check},
	})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(seen, []string{kept}) {
		t.Errorf("during the check a glob of sites-enabled matched %v, want only %v", seen, kept)
	}
	if found := leftovers(t, dir); len(found) != 0 {
		t.Errorf("previous or staged files remain after replacing and removing: %v", found)
	}
}

func TestApplySkipsUnchangedFiles(t *testing.T) {
	dir, runner, applier := setup(t)
	plan := Plan{Files: []File{{Path: filepath.Join(dir, "a.conf"), Content: []byte("same")}}, Checks: []system.Command{check}, Reloads: []system.Command{reload}}

	if _, err := applier.Apply(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	runner.Reset()

	changed, err := applier.Apply(context.Background(), plan)
	if err != nil || changed {
		t.Fatalf("second Apply = %v, %v", changed, err)
	}
	if len(runner.Calls()) != 0 {
		t.Errorf("unchanged plan ran %v", runner.Commands())
	}
}

func TestFailedCheckRestoresEveryFile(t *testing.T) {
	dir, runner, applier := setup(t)
	existing := filepath.Join(dir, "existing.conf")
	added := filepath.Join(dir, "added.conf")
	removed := filepath.Join(dir, "removed.conf")
	os.WriteFile(existing, []byte("old"), 0o644)
	os.WriteFile(removed, []byte("keep me"), 0o644)
	runner.Fail("nginx", 1, "nginx: [emerg] unknown directive \"bogus\"")

	_, err := applier.Apply(context.Background(), Plan{
		Files: []File{
			{Path: existing, Content: []byte("broken")},
			{Path: added, Content: []byte("new")},
			{Path: removed, Remove: true},
		},
		Checks:  []system.Command{check},
		Reloads: []system.Command{reload},
	})

	var applyErr *Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if applyErr.Output != "nginx: [emerg] unknown directive \"bogus\"" {
		t.Errorf("output = %q", applyErr.Output)
	}

	if read(t, existing) != "old" || read(t, removed) != "keep me" {
		t.Error("files not restored")
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Error("added file left behind")
	}
	for _, command := range runner.Commands() {
		if command == "systemctl reload nginx" {
			t.Error("reloaded after a failed check")
		}
	}
}

func TestFailedReloadRestoresAndReloadsAgain(t *testing.T) {
	dir, runner, applier := setup(t)
	path := filepath.Join(dir, "pool.conf")
	os.WriteFile(path, []byte("old"), 0o644)

	reloads := 0
	runner.Handle("systemctl", func(system.Command) (system.Result, error) {
		reloads++
		if reloads == 1 {
			return system.Result{Output: []byte("Job failed")}, &system.ExitError{Command: "systemctl", ExitCode: 1, Output: []byte("Job failed")}
		}
		return system.Result{}, nil
	})

	_, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("new")}}, Reloads: []system.Command{reload}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if read(t, path) != "old" {
		t.Error("not restored")
	}
	if reloads != 2 {
		t.Errorf("reloads = %d, want 2 (failed, then restore)", reloads)
	}
}

func TestModeIsApplied(t *testing.T) {
	dir, _, applier := setup(t)
	path := filepath.Join(dir, "start.sh")

	if _, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("#!/bin/sh\n"), Mode: 0o755}}}); err != nil {
		t.Fatal(err)
	}

	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v", info.Mode())
	}

	changed, _ := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("#!/bin/sh\n"), Mode: 0o700}}})
	if !changed {
		t.Error("a mode change counted as unchanged")
	}
}

func TestFailedReloadThatCannotRestoreSaysSo(t *testing.T) {
	dir, runner, applier := setup(t)
	path := filepath.Join(dir, "pool.conf")
	os.WriteFile(path, []byte("old"), 0o644)

	runner.Handle("systemctl", func(system.Command) (system.Result, error) {
		return system.Result{Output: []byte("Job failed")}, &system.ExitError{Command: "systemctl", ExitCode: 1, Output: []byte("Job failed")}
	})

	_, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("new")}}, Reloads: []system.Command{reload}})

	var applyErr *Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(applyErr.Summary, "also failed") || strings.Contains(applyErr.Summary, "was restored") {
		t.Errorf("summary = %q", applyErr.Summary)
	}
	if !strings.Contains(applyErr.Output, "Job failed") || !strings.Contains(applyErr.Output, "systemctl reload nginx again") {
		t.Errorf("output = %q", applyErr.Output)
	}
}

func TestFailedRestoreIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}

	dir, runner, applier := setup(t)
	path := filepath.Join(dir, "existing.conf")
	os.WriteFile(path, []byte("old"), 0o644)

	runner.Handle("nginx", func(system.Command) (system.Result, error) {
		os.Chmod(dir, 0o555)
		t.Cleanup(func() { os.Chmod(dir, 0o755) })

		return system.Result{Output: []byte("bad config")}, &system.ExitError{Command: "nginx", ExitCode: 1, Output: []byte("bad config")}
	})

	_, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("broken")}}, Checks: []system.Command{check}})

	var applyErr *Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(applyErr.Summary, "restoring") || strings.Contains(applyErr.Summary, "nothing was changed") {
		t.Errorf("summary = %q", applyErr.Summary)
	}
	if !strings.Contains(applyErr.Output, "bad config") || !strings.Contains(applyErr.Output, path) {
		t.Errorf("output = %q", applyErr.Output)
	}
}

func TestFailedReloadUsesTheCommandsDescription(t *testing.T) {
	dir, runner, applier := setup(t)
	path := filepath.Join(dir, "site.conf")
	os.WriteFile(path, []byte("old"), 0o644)

	helper := system.Command{Name: "/usr/local/bin/serverdog-agent", Args: []string{"reload-nginx"}, Description: "systemctl reload nginx"}
	failed := false
	runner.Handle("/usr/local/bin/serverdog-agent", func(system.Command) (system.Result, error) {
		if failed {
			return system.Result{}, nil
		}
		failed = true
		output := []byte("Nginx didn't switch to the new configuration.")

		return system.Result{Output: output}, &system.ExitError{Command: "/usr/local/bin/serverdog-agent", ExitCode: 1, Output: output}
	})

	_, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: path, Content: []byte("new")}}, Reloads: []system.Command{helper}})

	var applyErr *Error
	if !errors.As(err, &applyErr) {
		t.Fatalf("err = %v", err)
	}
	if !strings.HasPrefix(applyErr.Summary, "systemctl reload nginx failed") || strings.Contains(applyErr.Summary+applyErr.Output, "serverdog-agent") {
		t.Errorf("err = %q\n%s", applyErr.Summary, applyErr.Output)
	}
}

func TestHoldMakesItsApplyAndWhatFollowsOneChange(t *testing.T) {
	dir, _, applier := setup(t)
	site := filepath.Join(dir, "sites-available/a.conf")
	inside := make(chan struct{})
	finish := make(chan struct{})
	held := make(chan error, 1)

	go func() {
		held <- applier.Hold(context.Background(), func(a Applier) error {
			if _, err := a.Apply(context.Background(), Plan{Files: []File{{Path: site, Content: []byte("held")}}}); err != nil {
				return err
			}
			close(inside)
			<-finish

			return nil
		})
	}()
	<-inside

	other := make(chan error, 1)
	go func() {
		_, err := applier.Apply(context.Background(), Plan{Files: []File{{Path: site, Content: []byte("other")}}})
		other <- err
	}()

	select {
	case err := <-other:
		t.Fatalf("another Apply ran while the lock was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(finish)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	if err := <-other; err != nil {
		t.Fatal(err)
	}
	if read(t, site) != "other" {
		t.Errorf("content = %q", read(t, site))
	}
}
