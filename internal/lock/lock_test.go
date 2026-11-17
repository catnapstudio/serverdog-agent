package lock

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestAcquireWaitsForTheHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apply.lock")

	release, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := Acquire(ctx, path); err == nil {
		t.Fatal("second Acquire succeeded while the lock was held")
	}

	release()

	again, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatalf("Acquire after release: %v", err)
	}
	again()
}

func TestKeyedSerialisesSameKeyOnly(t *testing.T) {
	var keyed Keyed

	unlockA := keyed.Lock("a")
	unlockB := keyed.Lock("b")
	unlockB()

	done := make(chan struct{})
	go func() {
		keyed.Lock("a")()
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("second Lock(a) didn't wait")
	case <-time.After(50 * time.Millisecond):
	}

	unlockA()
	<-done
}

func TestAcquireReturnsErrorsOtherThanContention(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apply.lock")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	release, err := Acquire(ctx, path)
	if err == nil {
		release()
		t.Skip("flock works on FIFOs here, so there is no non-contention error to trigger")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire retried a non-contention error until the context ended: %v", err)
	}
}
