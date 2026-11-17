// Package lock serialises work: Acquire across processes with flock, Keyed within one process.
package lock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Acquire takes an exclusive flock on path, waiting until ctx ends. The returned func releases it.
func Acquire(ctx context.Context, path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create lock dir: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}

	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				unix.Flock(int(file.Fd()), unix.LOCK_UN)
				file.Close()
			}, nil
		}

		if errors.Is(err, unix.EINTR) {
			continue
		}

		if !errors.Is(err, unix.EWOULDBLOCK) {
			file.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}

		select {
		case <-ctx.Done():
			file.Close()
			return nil, fmt.Errorf("wait for lock %s: %w", path, ctx.Err())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// Keyed is a set of mutexes, one per key. The zero value is ready to use.
type Keyed struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// Lock locks key and returns its unlock func.
func (k *Keyed) Lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*sync.Mutex{}
	}
	m, ok := k.locks[key]
	if !ok {
		m = &sync.Mutex{}
		k.locks[key] = m
	}
	k.mu.Unlock()

	m.Lock()

	return m.Unlock
}
