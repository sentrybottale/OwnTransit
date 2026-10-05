//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

// Model a lost acknowledgement with the original wire/state schemas: the
// unchanged target has committed a renewal, while the client retains its exact
// pending request. Both the cached response and its TLS leaves have expired.
func expiredRenewalFixture(t *testing.T) (*integrated, clientRecord) {
	return pendingRenewalFixture(t, true)
}

func pendingRenewalFixture(t *testing.T, committed bool) (*integrated, clientRecord) {
	t.Helper()
	f := newIntegrated(t)
	f.start(t)
	f.pair(t)
	root, err := securefs.OpenRoot(f.clientPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	s, err := readClient(root)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := receiverpairing.ParsePairing(s.Pairing)
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Minute)
	request, err := receiverpairing.CreateRenewalWithPayload(pair, s.Origin, past, time.Minute, func(id receiverpairing.ClientIdentity) ([]byte, error) {
		payload, keys, err := NewCredentialRequest(id)
		s.PendingKeys = keys
		return payload, err
	})
	if err != nil {
		t.Fatal(err)
	}
	s.PendingRenewal, err = request.Material.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeRecord(root, "client.json", s, false); err != nil {
		t.Fatal(err)
	}
	if !committed {
		return f, s
	}
	receiver, err := receiverpairing.Open(filepath.Join(f.serverPath, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := receiver.LoadPrivateAuthority(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := receiver.Renew(request.Encrypted, past, func(peer receiverpairing.PeerRequest) ([]byte, error) {
		return IssueCredentials(peer, authority, snapshot.Meta.Leaves, time.Now().Add(-48*time.Hour))
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiverpairing.OpenRenewalResponse(receipt.Response, request.Material, s.Origin, time.Now()); err == nil {
		t.Fatal("old client accepted expired response")
	}
	old, err := receiverpairing.OpenRenewalResponse(receipt.Response, request.Material, s.Origin, past)
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAuthorization(old.Authorization, scopeOf(old.Pairing))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientTLS(a, s.PendingKeys, s.Trust); err == nil {
		t.Fatal("fixture credentials did not expire")
	}
	return f, s
}

func TestExpiredCommittedRenewalRecoversThroughSSH(t *testing.T) {
	for _, name := range []string{"uninterrupted", "restart-before-fresh-exchange", "restart-after-fresh-target-commit"} {
		t.Run(name, func(t *testing.T) {
			f, before := expiredRenewalFixture(t)
			if name != "uninterrupted" {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				calls := 0
				dial := func(ctx context.Context, url string) (net.Conn, error) {
					calls++
					if calls == 2 {
						if name == "restart-after-fresh-target-commit" {
							root, err := securefs.OpenRoot(f.clientPath)
							if err != nil {
								t.Fatal(err)
							}
							staged, err := readClient(root)
							root.Close()
							if err != nil {
								t.Fatal(err)
							}
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
					release()
					c.Close()
					t.Fatal("interrupted recovery opened a carrier")
				}
				if calls != 2 || f.dials.Load() != 0 {
					t.Fatal("recovery dialed SSH before fresh authorization")
				}
				root, err := securefs.OpenRoot(f.clientPath)
				if err != nil {
					t.Fatal(err)
				}
				staged, err := readClient(root)
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(staged.Pairing, before.Pairing) || !bytes.Equal(staged.Authorization, before.Authorization) || !bytes.Equal(staged.Keys.Inner, before.Keys.Inner) || !bytes.Equal(staged.Keys.Outer, before.Keys.Outer) {
					t.Fatal("expired receipt replaced activated credentials")
				}
				if len(staged.PendingRenewal) == 0 || bytes.Equal(staged.PendingRenewal, before.PendingRenewal) || bytes.Equal(staged.PendingKeys.Inner, before.PendingKeys.Inner) || bytes.Equal(staged.PendingKeys.Outer, before.PendingKeys.Outer) {
					t.Fatal("fresh pending request and keys were not saved together")
				}
			}
			f.assertSSH(t)
			root, err := securefs.OpenRoot(f.clientPath)
			if err != nil {
				t.Fatal(err)
			}
			after, err := readClient(root)
			root.Close()
			if err != nil {
				t.Fatal(err)
			}
			pair, err := receiverpairing.ParsePairing(after.Pairing)
			if err != nil || pair.CredentialGeneration() != 3 || len(after.PendingRenewal) != 0 {
				t.Fatal("fresh generation was not activated")
			}
			original, err := receiverpairing.ParsePairing(before.Pairing)
			if err != nil {
				t.Fatal(err)
			}
			if after.Trust != before.Trust || after.Origin != before.Origin || pair.ClientID() != original.ClientID() || pair.ReceiverID() != original.ReceiverID() || pair.RouteID() != original.RouteID() || !bytes.Equal(pair.PairingPrivateKeyPEM(), original.PairingPrivateKeyPEM()) {
				t.Fatal("recovery replaced pairing identity or trust")
			}
		})
	}
}

func TestExpiredRenewalRecoveryHonorsLocalAlarm(t *testing.T) {
	f, before := expiredRenewalFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := SetLocked(ctx, f.clientPath, false, true); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, f.clientPath, f.dial); err == nil || f.dials.Load() != 0 {
		t.Fatal("recovery bypassed local alarm")
	}
	root, err := securefs.OpenRoot(f.clientPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	after, err := readClient(root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after.PendingRenewal, before.PendingRenewal) || !bytes.Equal(after.Pairing, before.Pairing) {
		t.Fatal("alarmed recovery changed pairing")
	}
}
