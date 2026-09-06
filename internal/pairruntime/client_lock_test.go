//go:build darwin || linux

package pairruntime

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

func TestClientOperationLockWaitsAndCancels(t *testing.T) {
	path := privatePath(t, "lock-test")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	first, err := root.TryLock("client-operation.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		lock, err := clientOperationLock(ctx, root)
		if lock != nil {
			lock.Close()
		}
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("startup did not wait for the existing operation")
	case <-time.After(60 * time.Millisecond):
	}
	first.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	held, err := root.TryLock("client-operation.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	blocked, stop := context.WithCancel(context.Background())
	go func() {
		lock, err := clientOperationLock(blocked, root)
		if lock != nil {
			lock.Close()
		}
		done <- err
	}()
	stop()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled lock wait stuck")
	}
	if _, err := root.TryLock("client-operation.lock"); !errors.Is(err, securefs.ErrLocked) {
		t.Fatal("waiter released another operation's lock")
	}
}

func TestAlarmClosesClientWaitingForOperationLock(t *testing.T) {
	path := privatePath(t, "waiting-client")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := initPolicy(root); err != nil {
		t.Fatal(err)
	}
	held, err := root.TryLock("client-operation.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, release, err := OpenClient(ctx, path, nil)
		if c != nil {
			c.Close()
		}
		if release != nil {
			release()
		}
		done <- err
	}()
	eventually(t, func() bool {
		lock, err := root.TryLock("active.lock")
		if lock != nil {
			lock.Close()
		}
		return errors.Is(err, securefs.ErrLocked)
	})
	if err := SetLocked(ctx, path, false, true); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("alarmed waiter opened a carrier")
		}
	case <-ctx.Done():
		t.Fatal("alarm left startup waiting")
	}
	p, err := ReadPolicy(path)
	if err != nil || !p.Locked {
		t.Fatal("alarm was not retained")
	}
}
