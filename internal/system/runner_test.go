package system

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunCapturesOutputAndExitCode(t *testing.T) {
	result, err := Exec{}.Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "echo out; echo err >&2; exit 3"}})

	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("err = %v, want ExitError", err)
	}
	if exitErr.ExitCode != 3 || result.ExitCode != 3 {
		t.Errorf("exit = %d / %d", exitErr.ExitCode, result.ExitCode)
	}
	if !strings.Contains(string(result.Output), "out") || !strings.Contains(string(result.Output), "err") {
		t.Errorf("output = %q", result.Output)
	}

	code, ok := ExitCode(err)
	if !ok || code != 3 {
		t.Errorf("ExitCode = %d, %v", code, ok)
	}
}

func TestRunStreamsToStdout(t *testing.T) {
	var out bytes.Buffer

	_, err := Exec{}.Run(context.Background(), Command{Name: "sh", Args: []string{"-c", "echo streamed"}, Stdout: &out})
	if err != nil {
		t.Fatal(err)
	}

	if out.String() != "streamed\n" {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestRunKillsTheWholeProcessGroupOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Exec{}.Run(ctx, Command{Name: "sh", Args: []string{"-c", "sleep 30 & sleep 30; wait"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v; children kept the command alive", elapsed)
	}
}

func TestTailKeepsLastLines(t *testing.T) {
	if got := Tail([]byte("a\nb\n\nc\nd\n"), 2); got != "c\nd" {
		t.Errorf("Tail = %q", got)
	}
}

func TestCurrentUser(t *testing.T) {
	user, err := CurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	if user.Name == "" || user.Home == "" {
		t.Errorf("user = %+v", user)
	}
}
