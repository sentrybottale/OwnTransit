//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func readStatusClient(t *testing.T, path string) clientRecord {
	t.Helper()
	root, err := securefs.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s, err := readClient(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestUncommittedExpiredRenewalReconcilesThroughSSHAndRestarts(t *testing.T) {
	for _, cut := range []string{"none", "before-fresh-exchange", "after-fresh-commit"} {
		t.Run(cut, func(t *testing.T) {
			f, before := pendingRenewalFixture(t, false)
			if cut != "none" {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				interrupted := false
				dial := func(ctx context.Context, url string) (net.Conn, error) {
					staged := readStatusClient(t, f.clientPath)
					if !bytes.Equal(staged.PendingRenewal, before.PendingRenewal) {
						interrupted = true
						if !bytes.Equal(staged.Pairing, before.Pairing) || !bytes.Equal(staged.Authorization, before.Authorization) || !bytes.Equal(staged.Keys.Inner, before.Keys.Inner) || !bytes.Equal(staged.Keys.Outer, before.Keys.Outer) {
							t.Fatal("status replaced active state or did not save fresh request")
						}
						if cut == "after-fresh-commit" {
							pending, err := receiverpairing.ParseRenewalMaterial(staged.PendingRenewal)
							if err != nil {
								t.Fatal(err)
							}
							if _, err := (ReceiverBackend{Path: f.serverPath}).Exchange(pending.RequestBytes()); err != nil {
								t.Fatal(err)
							}
						}
						cancel()
						return nil, context.Canceled
					}
					return f.dial(ctx, url)
				}
				if c, release, err := OpenClient(ctx, f.clientPath, dial); err == nil {
					c.Close()
					release()
					t.Fatal("interruption opened SSH")
				}
				if !interrupted || f.dials.Load() != 0 {
					t.Fatal("recovery failed to reach fresh exchange without SSH")
				}
			}
			f.assertSSH(t)
			after := readStatusClient(t, f.clientPath)
			old, err := receiverpairing.ParsePairing(before.Pairing)
			if err != nil {
				t.Fatal(err)
			}
			p, err := receiverpairing.ParsePairing(after.Pairing)
			if err != nil {
				t.Fatal(err)
			}
			if p.CredentialGeneration() != 2 || len(after.PendingRenewal) != 0 || p.ClientID() != old.ClientID() || p.ReceiverID() != old.ReceiverID() || p.RouteID() != old.RouteID() || !bytes.Equal(p.PairingPrivateKeyPEM(), old.PairingPrivateKeyPEM()) || after.Trust != before.Trust || after.Origin != before.Origin {
				t.Fatal("reconciliation changed persistent identity/trust or wrong generation")
			}
		})
	}
}

func TestUnavailableStatusDoesNotReplacePendingOrResetTrust(t *testing.T) {
	f, before := pendingRenewalFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	calls := 0
	dial := func(ctx context.Context, url string) (net.Conn, error) {
		calls++
		if calls == 2 {
			cancel()
			return nil, context.Canceled
		}
		return f.dial(ctx, url)
	}
	if c, release, err := OpenClient(ctx, f.clientPath, dial); err == nil {
		c.Close()
		release()
		t.Fatal("missing status opened SSH")
	}
	after := readStatusClient(t, f.clientPath)
	if calls != 2 || f.dials.Load() != 0 || !bytes.Equal(after.PendingRenewal, before.PendingRenewal) || !bytes.Equal(after.PendingKeys.Inner, before.PendingKeys.Inner) || !bytes.Equal(after.Pairing, before.Pairing) || after.Trust != before.Trust {
		t.Fatal("silence replaced pending authority")
	}
}

func TestRenewalStatusStagingHonorsCancellationAndAlarm(t *testing.T) {
	for _, alarm := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "alarm"}[alarm], func(t *testing.T) {
			f, before := pendingRenewalFixture(t, false)
			pending, err := receiverpairing.ParseRenewalMaterial(before.PendingRenewal)
			if err != nil {
				t.Fatal(err)
			}
			q, err := receiverpairing.CreateRenewalStatus(pending, before.Origin, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			answer, err := (ReceiverBackend{Path: f.serverPath}).Exchange(q.Encrypted)
			if err != nil {
				t.Fatal(err)
			}
			var keys LeafKeys
			next, err := receiverpairing.RecoverRenewalStatus(answer, q, before.Origin, time.Now(), func(id receiverpairing.ClientIdentity) ([]byte, error) {
				p, k, e := NewCredentialRequest(id)
				keys = k
				return p, e
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if alarm {
				if err := SetLocked(ctx, f.clientPath, false, true); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			root, err := securefs.OpenRoot(f.clientPath)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			staged := before
			if err := stageClientRenewal(ctx, f.clientPath, root, &staged, next, keys); err == nil {
				t.Fatal("cancel/alarm allowed status staging")
			}
			after := readStatusClient(t, f.clientPath)
			if !bytes.Equal(after.PendingRenewal, before.PendingRenewal) || f.dials.Load() != 0 {
				t.Fatal("status staging changed denied state")
			}
		})
	}
}

func TestStatusRecoveryHonorsOpeningDeadline(t *testing.T) {
	f, before := pendingRenewalFixture(t, false)
	calls := 0
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return nil, ErrState
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	start := time.Now()
	if c, release, err := openClient(context.Background(), f.clientPath, dial, 2*time.Second); err == nil {
		c.Close()
		release()
		t.Fatal("offline status opened carrier")
	}
	if time.Since(start) > 4*time.Second || calls != 2 || f.dials.Load() != 0 {
		t.Fatal("status escaped opening budget", calls)
	}
	after := readStatusClient(t, f.clientPath)
	if !bytes.Equal(before.PendingRenewal, after.PendingRenewal) || !bytes.Equal(before.Pairing, after.Pairing) {
		t.Fatal("timeout changed durable pairing")
	}
}
