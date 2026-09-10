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

	"github.com/sentrybottale/owntransit/internal/receiverpairing"
)

func TestLostCodeRecoveryThenPairCheckAndRealSSH(t *testing.T) {
	current, dial, _ := shortRelayFixture(t)
	f, _, offer := shortRouteFixture(t, current.Load(), dial)
	before, err := os.ReadFile(filepath.Join(f.serverPath, "authority", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), f.attempt.Code...)
	defer clear(original)
	clear(f.attempt.Code) // User moved terminals without saving the displayed code.
	for i := 0; i < 2; i++ {
		recovered, err := ReceiverCode(f.serverPath, time.Now())
		if err != nil || !bytes.Equal(original, recovered.Code) || recovered.ReceiverID != f.attempt.ReceiverID {
			t.Fatal("lost code recovery changed identity or code")
		}
		if bytes.Contains(offer, recovered.Code) {
			t.Fatal("public offer leaked recoverable code")
		}
		clear(recovered.Code)
	}
	after, err := os.ReadFile(filepath.Join(f.serverPath, "authority", "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("code display changed authority state")
	}
	approveShortFixture(t, f)
	stop, done := f.start(t)
	defer stopShortFixture(t, stop, done)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := Check(ctx, f.clientPath, f.dial); err == nil || f.dials.Load() != 0 {
		t.Fatal("approval alone passed end-to-end check")
	}
	recovered, err := ReceiverCode(f.serverPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(recovered.Code)
	if err := PairClientShort(ctx, f.clientPath, "wss://relay.example/connects", recovered.Code, dial); err != nil {
		t.Fatal(err)
	}
	if f.dials.Load() != 0 {
		t.Fatal("credential exchange pretended to check the SSH transport")
	}
	if code, err := ReceiverCode(f.serverPath, time.Now()); err == nil || len(code.Code) != 0 {
		t.Fatal("consumed private code remained retrievable")
	}
	if err := Check(ctx, f.clientPath, dial); err != nil || f.dials.Load() != 1 {
		t.Fatal("real authenticated end-to-end check did not reach fixed SSH target", err)
	}
	f.assertSSH(t)
	if err := SetLocked(ctx, f.clientPath, false, true); err != nil {
		t.Fatal(err)
	}
	count := f.dials.Load()
	if err := Check(ctx, f.clientPath, dial); err == nil || f.dials.Load() != count {
		t.Fatal("check reopened alarmed tunnel")
	}
}

func TestLegacyPendingCodeCannotBeInventedOnUpgrade(t *testing.T) {
	current, dial, _ := shortRelayFixture(t)
	f, _, _ := shortRouteFixture(t, current.Load(), dial)
	if err := os.Remove(filepath.Join(f.serverPath, "authority", "private-pairing-code.v1")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(f.serverPath, "authority", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReceiverCode(f.serverPath, time.Now())
	defer clear(got.Code)
	if !errors.Is(err, receiverpairing.ErrPendingCodeUnavailable) || len(got.Code) != 0 {
		t.Fatal("old missing code was invented")
	}
	after, err := os.ReadFile(filepath.Join(f.serverPath, "authority", "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("missing code reset old state")
	}
}
