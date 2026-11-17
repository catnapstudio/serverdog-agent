package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"
	"unicode/utf8"

	"github.com/catnapstudio/serverdog-agent/internal/paths"
	"github.com/catnapstudio/serverdog-agent/internal/state"
)

// Update is one event for a watching client: a deployment snapshot, log text, or the command now running.
type Update struct {
	Deployment *state.Deployment
	Log        string
	Command    string
	NextOffset int64
}

// Watcher follows a deployment's log and state by polling.
type Watcher struct {
	Store *state.Store
	Paths paths.Paths
	Poll  time.Duration
}

const defaultPoll = 250 * time.Millisecond

// maxReadPerPoll bounds one log read; a variable so tests can lower it.
var maxReadPerPoll = 1 << 20

// Watch sends the deployment, then log pieces from offset from as they appear, then the final deployment, and returns.
func (w Watcher) Watch(ctx context.Context, id string, from int64, send func(Update) error) error {
	if from < 0 {
		return fmt.Errorf("watch deployment %s from offset %d: offsets start at zero", id, from)
	}

	poll := w.Poll
	if poll <= 0 {
		poll = defaultPoll
	}

	offset := from
	var last []byte

	for {
		d, err := w.Store.GetDeployment(id)
		if err != nil {
			return err
		}

		// Read the log after reading the state: the runner writes its last line before recording the outcome.
		data, err := readFrom(w.Paths.File(paths.DeployLog(d.SiteID, id)), offset)
		if err != nil {
			return err
		}

		// While running, a changed snapshot goes before the log, so the client sees the phases first.
		snapshot, _ := json.Marshal(d)
		if !d.Finished() && !bytes.Equal(snapshot, last) {
			if err := send(Update{Deployment: &d, NextOffset: offset}); err != nil {
				return err
			}
			last = snapshot
		}

		moreToRead := len(data) >= maxReadPerPoll
		pieces, consumed := Filter(data, d.Marker, d.Finished() && !moreToRead)
		if moreToRead && consumed == 0 {
			// A line longer than the window: stream the window as text, cut so no character is split.
			cut := utf8Boundary(data)
			pieces = []Piece{{Text: string(data[:cut]), End: cut}}
			consumed = cut
		}

		for _, piece := range pieces {
			update := Update{Log: piece.Text, Command: piece.Command, NextOffset: offset + int64(piece.End)}
			if err := send(update); err != nil {
				return err
			}
		}
		offset += int64(consumed)

		// Once finished and fully read, the final snapshot is the last update.
		if d.Finished() && !moreToRead {
			return send(Update{Deployment: &d, NextOffset: offset})
		}
		if moreToRead {
			if err := ctx.Err(); err != nil {
				return err
			}
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// utf8Boundary returns the length of the longest prefix of data that does not end in a split character.
func utf8Boundary(data []byte) int {
	for start := len(data) - 1; start >= 0 && start >= len(data)-utf8.UTFMax; start-- {
		if !utf8.RuneStart(data[start]) {
			continue
		}
		if utf8.FullRune(data[start:]) {
			return len(data)
		}
		if start == 0 {
			return len(data)
		}

		return start
	}

	return len(data)
}

func readFrom(path string, offset int64) ([]byte, error) {
	file, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}

	return io.ReadAll(io.LimitReader(file, int64(maxReadPerPoll)))
}
