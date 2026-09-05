//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func TestReceiverSetupRegeneratesAndRetiresOldPair(t *testing.T) {
	f := newIntegrated(t)
	before, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	next, retired, err := RebuildReceiver(ctx, f.serverPath, before.Meta.Origin, before.Meta.ServerInfo, "")
	if err != nil {
		t.Fatal(err)
	}
	if next.ReceiverID == f.attempt.ReceiverID || bytes.Equal(next.Code, f.attempt.Code) {
		t.Fatal("setup reused identity or code")
	}
	after, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Meta.Leaves.Keys.Inner, after.Meta.Leaves.Keys.Inner) || before.Trust.InnerClientCAPEM == after.Trust.InnerClientCAPEM {
		t.Fatal("setup retained old authority")
	}
	old, err := ReadPolicy(retired)
	if err != nil || !old.Locked {
		t.Fatal("retired pairing not terminally locked")
	}
	if gate, err := Admission(retired); err == nil {
		gate.Close()
		t.Fatal("retired pairing admitted a worker")
	}
	if _, err := receiverpairing.CreateRequestWithPayload(receiverpairing.CreateRequestOptions{Advertisement: next.Advertisement, Code: f.attempt.Code, RelayOrigin: before.Meta.Origin, Now: time.Now(), Validity: time.Minute}, nil); err == nil {
		t.Fatal("old code accepted for new receiver")
	}
	again, _, err := RebuildReceiver(ctx, f.serverPath, before.Meta.Origin, before.Meta.ServerInfo, "")
	if err != nil || again.ReceiverID == next.ReceiverID || bytes.Equal(again.Code, next.Code) {
		t.Fatal("repeated setup did not issue fresh values")
	}
}

func TestReceiverRebuildFailurePreservesActiveIdentity(t *testing.T) {
	f := newIntegrated(t)
	old, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RebuildReceiver(context.Background(), f.serverPath, "wss://relay.example/connects", pairrelay.ServerInfo{}, ""); err == nil {
		t.Fatal("bad relay info accepted")
	}
	p, err := ReadPolicy(f.serverPath)
	if err != nil || p.Locked {
		t.Fatal("failed preparation retired active pairing")
	}
	current, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil || current.Status.ReceiverID != old.Status.ReceiverID {
		t.Fatal("failed preparation replaced active identity")
	}
}

func TestReceiverRebuildRejectsSymlinkAndConcurrentSetup(t *testing.T) {
	f := newIntegrated(t)
	old, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(f.serverPath), "alias")
	if err := os.Symlink(f.serverPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RebuildReceiver(context.Background(), alias, old.Meta.Origin, old.Meta.ServerInfo, ""); err == nil {
		t.Fatal("symlink state accepted")
	}
	control, err := securefs.CreateRoot(f.serverPath + ".setup")
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	held, err := control.TryLock("setup.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, _, err := RebuildReceiver(context.Background(), f.serverPath, old.Meta.Origin, old.Meta.ServerInfo, ""); err == nil {
		t.Fatal("concurrent setup accepted")
	}
	p, err := ReadPolicy(f.serverPath)
	if err != nil || p.Locked {
		t.Fatal("rejected setup changed old policy")
	}
}

func TestReceiverRebuildWaitsForActiveWorkers(t *testing.T) {
	f := newIntegrated(t)
	s, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	gate, err := Admission(f.serverPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, _, err = RebuildReceiver(ctx, f.serverPath, s.Meta.Origin, s.Meta.ServerInfo, "")
	gate.Close()
	if err == nil {
		t.Fatal("replaced state with old worker still admitted")
	}
	p, err := ReadPolicy(f.serverPath)
	if err != nil || !p.Locked {
		t.Fatal("interrupted retirement did not fail closed")
	}
	next, _, err := RebuildReceiver(context.Background(), f.serverPath, s.Meta.Origin, s.Meta.ServerInfo, "")
	if err != nil || next.ReceiverID == s.Status.ReceiverID {
		t.Fatal("could not deliberately rebuild locked pairing")
	}
}

func TestReceiverRebuildConsentBoundToCurrentPeer(t *testing.T) {
	f := newIntegrated(t)
	f.start(t)
	f.pair(t)
	s, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := RebuildReceiver(ctx, f.serverPath, s.Meta.Origin, s.Meta.ServerInfo, ""); err == nil {
		t.Fatal("unpaired consent replaced a concurrently paired client")
	}
	p, err := ReadPolicy(f.serverPath)
	if err != nil || p.Locked {
		t.Fatal("consent mismatch changed active policy")
	}
	if _, _, err := RebuildReceiver(ctx, f.serverPath, s.Meta.Origin, s.Meta.ServerInfo, s.Status.PairedClientID); err != nil {
		t.Fatal(err)
	}
}
