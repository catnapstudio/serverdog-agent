package deploy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

func TestWatchStreamsLogAndEndsWithTheFinalState(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	d := deployment(t, f, id)

	log := logPath(t, f, id)
	writeLog(t, log, "first line\n\x1eserverdog:"+d.Marker+":npm ci\n")

	go func() {
		time.Sleep(100 * time.Millisecond)
		appendLog(t, log, "second line\n")
		finish(t, f, id)
	}()

	watcher := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: 20 * time.Millisecond}
	updates := watchAll(t, ctx, watcher, id, 0)

	text, commands := textAndCommands(updates)
	if text != "first line\nsecond line\n" {
		t.Errorf("log = %q", text)
	}
	if len(commands) != 1 || commands[0] != "npm ci" {
		t.Errorf("commands = %v", commands)
	}

	first, last := updates[0], updates[len(updates)-1]
	if first.Deployment == nil || first.Deployment.State != state.Running {
		t.Errorf("first update = %+v", first)
	}
	if last.Deployment == nil || last.Deployment.State != state.Succeeded {
		t.Errorf("last update = %+v", last)
	}
}

func TestWatchResumesFromAnOffset(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	f.store.UpdateDeployment(id, func(d *state.Deployment) { d.State = state.Failed })

	writeLog(t, logPath(t, f, id), "seen\nnot seen yet\n")

	var text strings.Builder
	var offsets []int64
	err := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: 10 * time.Millisecond}.Watch(ctx, id, 5, func(update Update) error {
		text.WriteString(update.Log)
		if update.Log != "" {
			offsets = append(offsets, update.NextOffset)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if text.String() != "not seen yet\n" || offsets[len(offsets)-1] != 18 {
		t.Errorf("text = %q, offsets = %v", text.String(), offsets)
	}
}

func TestWatchResumesWithoutGapsOrRepeatsFromEveryOffset(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	d := deployment(t, f, id)

	content := "==> start\n" +
		"\x1eserverdog:" + d.Marker + ":composer install\n" +
		"Installing\n" +
		"no newline yet\x1eserverdog:" + d.Marker + ":npm ci\n" +
		"added 12 packages\n" +
		"tail without newline"
	writeLog(t, logPath(t, f, id), content)
	finish(t, f, id)

	watcher := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: time.Millisecond}
	full := watchAll(t, ctx, watcher, id, 0)
	fullText, fullCommands := textAndCommands(full)

	if fullText != "==> start\nInstalling\nno newline yetadded 12 packages\ntail without newline" {
		t.Fatalf("full text = %q", fullText)
	}
	if !reflect.DeepEqual(fullCommands, []string{"composer install", "npm ci"}) {
		t.Fatalf("full commands = %v", fullCommands)
	}

	for _, update := range full {
		offset := update.NextOffset
		beforeText, beforeCommands := textAndCommands(filtered(content[:offset], d.Marker))
		resumedText, resumedCommands := textAndCommands(watchAll(t, ctx, watcher, id, offset))

		if beforeText+resumedText != fullText {
			t.Errorf("from offset %d: %q + %q != %q", offset, beforeText, resumedText, fullText)
		}
		if !reflect.DeepEqual(append(beforeCommands, resumedCommands...), fullCommands) {
			t.Errorf("from offset %d: commands %v + %v != %v", offset, beforeCommands, resumedCommands, fullCommands)
		}
	}
}

func TestWatchDeliversAPartialLineOnceWhenItCompletes(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	log := logPath(t, f, id)
	writeLog(t, log, "partial")

	go func() {
		time.Sleep(60 * time.Millisecond)
		appendLog(t, log, " line\nnext\n")
		time.Sleep(60 * time.Millisecond)
		finish(t, f, id)
	}()

	watcher := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: 5 * time.Millisecond}
	updates := watchAll(t, ctx, watcher, id, 0)

	text, _ := textAndCommands(updates)
	if text != "partial line\nnext\n" {
		t.Errorf("text = %q", text)
	}
	for _, update := range updates {
		if update.Log != "" && !strings.HasSuffix(update.Log, "\n") {
			t.Errorf("partial line sent before it completed: %q", update.Log)
		}
	}
}

func TestWatchStreamsALineLongerThanTheReadWindow(t *testing.T) {
	restore := maxReadPerPoll
	maxReadPerPoll = 16
	t.Cleanup(func() { maxReadPerPoll = restore })

	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")
	line := strings.Repeat("héllo wörld ", 40)
	writeLog(t, logPath(t, f, id), line)

	go func() {
		time.Sleep(50 * time.Millisecond)
		finish(t, f, id)
	}()

	timed, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	watcher := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: 5 * time.Millisecond}
	updates := watchAll(t, timed, watcher, id, 0)

	text, _ := textAndCommands(updates)
	if text != line {
		t.Errorf("streamed %d bytes, want %d", len(text), len(line))
	}
	for _, update := range updates {
		if !utf8.ValidString(update.Log) {
			t.Errorf("piece splits a character: %q", update.Log)
		}
	}
}

func TestWatchRejectsANegativeOffset(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")

	err := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}}.Watch(ctx, id, -1, func(Update) error { return nil })
	if err == nil {
		t.Error("negative offset accepted")
	}
}

func TestWatchStopsWhenTheClientGoes(t *testing.T) {
	f := newFixture(t, nil)
	id := f.start(state.KindDeploy, "")

	cancelled, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()

	err := Watcher{Store: f.store, Paths: paths.Paths{Root: f.root}, Poll: 10 * time.Millisecond}.Watch(cancelled, id, 0, func(Update) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v; want the client's deadline", err)
	}
}

func deployment(t *testing.T, f *fixture, id string) state.Deployment {
	t.Helper()

	d, err := f.store.GetDeployment(id)
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func logPath(t *testing.T, f *fixture, id string) string {
	t.Helper()

	return paths.Paths{Root: f.root}.File(paths.DeployLog(deployment(t, f, id).SiteID, id))
}

func writeLog(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// appendLog reports with Error rather than Fatal, so it is safe to call from a goroutine.
func appendLog(t *testing.T, path, content string) {
	t.Helper()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Error(err)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(content); err != nil {
		t.Error(err)
	}
}

// finish marks the deployment succeeded; it reports with Error, so it is safe to call from a goroutine.
func finish(t *testing.T, f *fixture, id string) {
	t.Helper()

	if _, err := f.store.UpdateDeployment(id, func(d *state.Deployment) { d.State = state.Succeeded }); err != nil {
		t.Error(err)
	}
}

func watchAll(t *testing.T, watchCtx context.Context, watcher Watcher, id string, from int64) []Update {
	t.Helper()

	var updates []Update
	err := watcher.Watch(watchCtx, id, from, func(update Update) error {
		updates = append(updates, update)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return updates
}

func textAndCommands(updates []Update) (string, []string) {
	var text strings.Builder
	var commands []string
	for _, update := range updates {
		text.WriteString(update.Log)
		if update.Command != "" {
			commands = append(commands, update.Command)
		}
	}

	return text.String(), commands
}

// filtered is what a client that had received data up to its end would hold.
func filtered(data, marker string) []Update {
	pieces, _ := Filter([]byte(data), marker, true)

	updates := make([]Update, 0, len(pieces))
	for _, piece := range pieces {
		updates = append(updates, Update{Log: piece.Text, Command: piece.Command})
	}

	return updates
}
