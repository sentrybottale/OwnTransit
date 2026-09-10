//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func removedClientFixture(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "client")
	root, err := securefs.CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := initPolicy(root); err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(root, "client.json", clientRecord{Schema: "owntransit.paired-client.v1", Token: []byte("invalid-fixture-token"), Pending: []byte("retained-fixture-request")}, true); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLocalRemovalRetainsStateAndCancelsActiveWorkers(t *testing.T) {
	path := removedClientFixture(t)
	other := removedClientFixture(t)
	before, _ := os.ReadFile(filepath.Join(path, "client.json"))
	policyBefore, _ := os.ReadFile(filepath.Join(path, "policy.json"))
	gate, err := Admission(path)
	if err != nil {
		t.Fatal(err)
	}
	watch, cancel := watchPolicy(context.Background(), path)
	defer cancel()
	go func() { <-watch.Done(); gate.Close() }()
	ctx, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if err := RemoveLocal(ctx, path, false, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Admission(path); !errors.Is(err, ErrRemoved) {
		t.Fatal("removed state admitted a new worker", err)
	}
	if gate, err := Admission(other); err != nil {
		t.Fatal("removal changed another tunnel", err)
	} else {
		gate.Close()
	}
	after, _ := os.ReadFile(filepath.Join(path, "client.json"))
	policyAfter, _ := os.ReadFile(filepath.Join(path, "policy.json"))
	if !bytes.Equal(before, after) || !bytes.Equal(policyBefore, policyAfter) {
		t.Fatal("local removal changed credentials or alarm policy")
	}
	if err := RestoreLocal(ctx, path, false, nil); err != nil {
		t.Fatal(err)
	}
	if gate, err := Admission(path); err != nil {
		t.Fatal("explicit restore did not reopen retained tunnel", err)
	} else {
		gate.Close()
	}
}

func TestLocalRemovalInterruptedStopAndDrainRequireRetry(t *testing.T) {
	for _, failStop := range []bool{false, true} {
		t.Run(map[bool]string{false: "active-worker", true: "service-stop"}[failStop], func(t *testing.T) {
			path := removedClientFixture(t)
			gate, err := Admission(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			stop := func(context.Context) error {
				if failStop {
					return errors.New("fixture stop failed")
				}
				return nil
			}
			if err := RemoveLocal(ctx, path, false, stop); err == nil {
				t.Fatal("unconfirmed shutdown reported successful removal")
			}
			if _, err := Admission(path); !errors.Is(err, ErrRemoved) {
				t.Fatal("interrupted removal lost denial")
			}
			if err := RestoreLocal(context.Background(), path, false, nil); err == nil {
				t.Fatal("restored an unfinished removal")
			}
			gate.Close()
			if err := RemoveLocal(context.Background(), path, false, nil); err != nil {
				t.Fatal(err)
			}
			if err := RestoreLocal(context.Background(), path, false, nil); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalRemovalCannotRestoreOrClearTerminalAlarm(t *testing.T) {
	for _, alarmFirst := range []bool{false, true} {
		path := removedClientFixture(t)
		if alarmFirst {
			if err := SetLocked(context.Background(), path, false, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := RemoveLocal(context.Background(), path, false, nil); err != nil {
			t.Fatal(err)
		}
		if !alarmFirst {
			if err := SetLocked(context.Background(), path, false, true); err != nil {
				t.Fatal(err)
			}
		}
		if err := RestoreLocal(context.Background(), path, false, nil); !errors.Is(err, leasewire.ErrLocked) {
			t.Fatal("restored terminal alarm", err)
		}
		policy, err := ReadRetainedPolicy(path)
		if err != nil || !policy.Locked {
			t.Fatal("removal or restore cleared alarm")
		}
	}
}

func TestRestoreCannotCommitAfterAlarmDuringDrain(t *testing.T) {
	path := removedClientFixture(t)
	if err := RemoveLocal(context.Background(), path, false, nil); err != nil {
		t.Fatal(err)
	}
	root, err := securefs.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	service, err := root.TryLock("service.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	draining := make(chan struct{})
	result := make(chan error, 1)
	started := make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		result <- restoreLocal(ctx, path, false, func(context.Context) error { started <- struct{}{}; return nil }, func(ctx context.Context, root *securefs.Root) error { close(draining); return drainLocal(ctx, root) })
	}()
	<-draining
	if err := SetLocked(ctx, path, false, true); err != nil {
		t.Fatal(err)
	}
	service.Close()
	if err := <-result; !errors.Is(err, leasewire.ErrLocked) {
		t.Fatal("restore succeeded after a committed alarm", err)
	}
	select {
	case <-started:
		t.Fatal("restore started service after committed alarm")
	default:
	}
	if removed, err := IsRemoved(path); err != nil || !removed {
		t.Fatal("failed restore removed its denial marker")
	}
}

func TestLocalRemovalRejectsRoleLinksCorruptionAndConcurrentLifecycle(t *testing.T) {
	path := removedClientFixture(t)
	if err := RemoveLocal(context.Background(), path, true, nil); err == nil {
		t.Fatal("target removal accepted client state")
	}
	if removed, err := IsRemoved(path); err != nil || removed {
		t.Fatal("wrong role changed state")
	}
	alias := filepath.Join(filepath.Dir(path), "alias")
	if err := os.Symlink(path, alias); err != nil {
		t.Fatal(err)
	}
	if err := RemoveLocal(context.Background(), alias, false, nil); err == nil {
		t.Fatal("removal followed symlink")
	}
	serial, err := localLifecycleLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveLocal(context.Background(), path, false, nil); !errors.Is(err, securefs.ErrLocked) {
		t.Fatal("concurrent lifecycle accepted")
	}
	serial.Close()
	for _, data := range [][]byte{[]byte(`{"schema":"owntransit.local-removal.v1","role":"client","phase":"removed","unknown":true}`), bytes.Repeat([]byte("a"), 257)} {
		if err := os.WriteFile(filepath.Join(path, removalFile), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Admission(path); err == nil {
			t.Fatal("malformed removal marker admitted a worker")
		}
		if err := RestoreLocal(context.Background(), path, false, nil); err == nil {
			t.Fatal("malformed marker restored")
		}
	}
}

func TestTargetRemovalRetainsCodeAndBlocksReplacementUntilRestore(t *testing.T) {
	current, dial, _ := shortRelayFixture(t)
	f, _, _ := shortRouteFixture(t, current.Load(), dial)
	before, err := ReceiverCode(f.serverPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before.Code)
	snapshot, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := RemoveLocal(context.Background(), f.serverPath, true, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ReceiverCode(f.serverPath, time.Now()); !errors.Is(err, ErrRemoved) {
		t.Fatal("removed target revealed private code", err)
	}
	if _, _, err := RebuildReceiverWithOffer(context.Background(), f.serverPath, snapshot.Meta.Origin, snapshot.Meta.ServerInfo, ""); !errors.Is(err, ErrRemoved) {
		t.Fatal("replacement implicitly restored removed target", err)
	}
	if err := RestoreLocal(context.Background(), f.serverPath, true, nil); err != nil {
		t.Fatal(err)
	}
	after, err := ReceiverCode(f.serverPath, time.Now())
	defer clear(after.Code)
	if err != nil || !bytes.Equal(before.Code, after.Code) || before.ReceiverID != after.ReceiverID {
		t.Fatal("restore changed pending target identity/code")
	}
}

func TestLocalRemovalClosesRealCarrierAndRestoresSSH(t *testing.T) {
	for _, target := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "target"}[target], func(t *testing.T) {
			f := newIntegrated(t)
			_, _ = f.start(t)
			f.pair(t)
			f.assertSSH(t)
			path := f.clientPath
			if target {
				path = f.serverPath
			}
			before, _ := ReadRetainedPolicy(path)
			carrier, release := f.open(t)
			defer release()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			removed := make(chan error, 1)
			go func() { removed <- RemoveLocal(ctx, path, target, nil) }()
			select {
			case <-carrier.Done():
			case <-ctx.Done():
				t.Fatal("local removal left the real carrier open")
			}
			release()
			if err := <-removed; err != nil {
				t.Fatal(err)
			}
			after, err := ReadRetainedPolicy(path)
			if err != nil || before != after || after.Locked {
				t.Fatal("removal changed alarm policy")
			}
			if err := RestoreLocal(ctx, path, target, nil); err != nil {
				t.Fatal(err)
			}
			if target {
				_, _ = f.start(t)
			}
			f.assertSSH(t)
		})
	}
}
