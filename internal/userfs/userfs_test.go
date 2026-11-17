package userfs

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/catnapstudio/serverdog-agent/internal/system"
)

func TestWriteReadAndRemove(t *testing.T) {
	dir := t.TempDir()
	fs := FS{Runner: system.Exec{}}
	ctx := context.Background()
	path := filepath.Join(dir, "shared", ".env")

	if err := fs.MkdirAll(ctx, "0750", filepath.Join(dir, "shared")); err != nil {
		t.Fatal(err)
	}

	if err := fs.WriteFile(ctx, path, []byte("APP_KEY=secret\n"), "0600"); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode())
	}

	content, ok, err := fs.ReadFile(ctx, path)
	if err != nil || !ok || string(content) != "APP_KEY=secret\n" {
		t.Errorf("ReadFile = %q %v %v", content, ok, err)
	}

	if _, ok, err := fs.ReadFile(ctx, filepath.Join(dir, "missing")); ok || err != nil {
		t.Errorf("missing file: ok=%v err=%v", ok, err)
	}

	if err := fs.Remove(ctx, path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("not removed")
	}
}

func TestConcurrentWritesToOnePathBothSucceedAndLeaveNoTemp(t *testing.T) {
	dir := t.TempDir()
	fs := FS{Runner: system.Exec{}}
	ctx := context.Background()
	path := filepath.Join(dir, "index.html")
	contents := []string{"first\n", "second\n", "third\n", "fourth\n"}

	for round := 0; round < 25; round++ {
		errs := make([]error, len(contents))
		start := make(chan struct{})

		var wg sync.WaitGroup
		for i, content := range contents {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = fs.WriteFile(ctx, path, []byte(content), "0644")
			}()
		}

		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d writer %d: %v", round, i, err)
			}
		}

		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(contents, string(got)) {
			t.Fatalf("round %d: content = %q, want one of the written contents", round, got)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("round %d: folder holds %d entries, want only the file: %v", round, len(entries), entries)
		}
	}
}

func TestFailedWriteLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	fs := FS{Runner: system.Exec{}}

	if err := fs.WriteFile(context.Background(), filepath.Join(dir, "file"), []byte("x"), "not-a-mode"); err == nil {
		t.Fatal("an invalid mode should fail the write")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("folder holds %v, want it empty", entries)
	}
}

func TestWriteFileSendsContentOnStdinOnly(t *testing.T) {
	recorder := &recording{}
	fs := FS{Runner: recorder}
	secret := "DB_PASSWORD=hunter2"

	if err := fs.WriteFile(context.Background(), "/x/.env", []byte(secret), "0600"); err != nil {
		t.Fatal(err)
	}

	for _, arg := range recorder.last.Args {
		if strings.Contains(arg, secret) || strings.Contains(arg, "hunter2") {
			t.Fatalf("secret passed as an argument: %q", arg)
		}
	}

	if recorder.last.Stdin == nil {
		t.Fatal("no stdin")
	}

	sent, err := io.ReadAll(recorder.last.Stdin)
	if err != nil || string(sent) != secret {
		t.Errorf("stdin = %q, %v", sent, err)
	}
}

func TestEveryOperationRunsAsTheSiteUser(t *testing.T) {
	user := system.User{Name: "forge"}
	ctx := context.Background()

	operations := map[string]func(FS) error{
		"MkdirAll":  func(fs FS) error { return fs.MkdirAll(ctx, "0750", "/home/forge/site") },
		"WriteFile": func(fs FS) error { return fs.WriteFile(ctx, "/home/forge/site/.env", []byte("A=1"), "0600") },
		"ReadFile": func(fs FS) error {
			_, _, err := fs.ReadFile(ctx, "/home/forge/site/.env")

			return err
		},
		"Remove": func(fs FS) error { return fs.Remove(ctx, "/home/forge/site/.env") },
	}

	for name, operation := range operations {
		recorder := &recording{}

		if err := operation(FS{Runner: recorder, User: &user}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if recorder.last.User != &user {
			t.Errorf("%s ran as %v, want the site user", name, recorder.last.User)
		}
	}
}

type recording struct{ last system.Command }

func (r *recording) Run(_ context.Context, cmd system.Command) (system.Result, error) {
	r.last = cmd
	return system.Result{}, nil
}
