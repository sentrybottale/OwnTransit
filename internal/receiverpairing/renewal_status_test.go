//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"crypto/ed25519"
	"math"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func statusFixture(t *testing.T) (*Receiver, Pairing, time.Time) {
	t.Helper()
	r, _, now := newTestReceiver(t)
	a, err := r.CreateAttempt(now, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req, err := CreateRequest(CreateRequestOptions{Advertisement: a.Advertisement, Code: a.Code, RelayOrigin: testRelayOrigin, Now: now, Validity: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.Claim(req.Encrypted, now, staticIssuer("initial"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenResponse(a.Advertisement, c.Response, req.Material, testRelayOrigin, now)
	if err != nil {
		t.Fatal(err)
	}
	return r, p.Pairing, now
}

func TestRenewalStatusRejectsForgedCrossedStaleAndMalformedResponses(t *testing.T) {
	r, p, now := statusFixture(t)
	pending, err := CreateRenewal(p, testRelayOrigin, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	q, err := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
	if err != nil {
		t.Fatal(err)
	}
	response, err := r.RenewalStatus(q.Encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := signing.ParsePublic(p.receiverPublic)
	plain, err := openAge(response, statusResponseCipher, q.responseIdentity, MaxResponseSize)
	if err != nil {
		t.Fatal(err)
	}
	var payload renewalStatusResponse
	if err := openSigned(plain, statusResponseEnvelope, statusResponseDomain, pub, MaxResponseSize, &payload); err != nil {
		t.Fatal(err)
	}
	root, lock, state, err := r.lockedState()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := readSecrets(root, state, now)
	lock.Close()
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	other, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	responseID, _ := age.ParseX25519Identity(q.responseIdentity)
	for _, tc := range []struct {
		name      string
		change    func(*renewalStatusResponse)
		badSigner bool
	}{
		{"schema", func(p *renewalStatusResponse) { p.Schema = "unknown" }, false},
		{"profile", func(p *renewalStatusResponse) { p.Profile = Profile }, false},
		{"receiver", func(p *renewalStatusResponse) { p.ReceiverID, _ = randomID() }, false},
		{"route", func(p *renewalStatusResponse) { p.RouteID, _ = randomID() }, false},
		{"client", func(p *renewalStatusResponse) { p.ClientID, _ = randomID() }, false},
		{"origin", func(p *renewalStatusResponse) { p.RelayOrigin = "wss://other.example/connects" }, false},
		{"query", func(p *renewalStatusResponse) { p.QuerySHA256 = digestText([]byte("other")) }, false},
		{"pending", func(p *renewalStatusResponse) { p.PendingSHA256 = digestText([]byte("other")) }, false},
		{"rollback", func(p *renewalStatusResponse) { p.Generation = 0 }, false},
		{"jump", func(p *renewalStatusResponse) { p.Generation += 2 }, false},
		{"overflow", func(p *renewalStatusResponse) { p.Generation = math.MaxUint64 }, false},
		{"future", func(p *renewalStatusResponse) { p.IssuedUnix += 3600; p.ExpiresUnix += 3600 }, false},
		{"expiry", func(p *renewalStatusResponse) { p.ExpiresUnix++ }, false},
		{"empty-window", func(p *renewalStatusResponse) { p.ExpiresUnix = p.IssuedUnix }, false},
		{"signature", func(p *renewalStatusResponse) {}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := payload
			tc.change(&changed)
			key := secrets.signingPrivate
			if tc.badSigner {
				key = other.Private
			}
			signed, err := signPayload(statusResponseEnvelope, statusResponseDomain, changed, key, MaxResponseSize)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := sealAge(statusResponseCipher, signed, responseID.Recipient().String(), MaxResponseSize)
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if _, err := RecoverRenewalStatus(wire, q, testRelayOrigin, now, func(ClientIdentity) ([]byte, error) { called = true; return nil, nil }); err == nil || called {
				t.Fatal("invalid status prepared renewal")
			}
		})
	}
	if _, err := RecoverRenewalStatus(response, q, testRelayOrigin, now.Add(2*time.Minute), nil); err == nil {
		t.Fatal("expired query accepted")
	}
	q2, err := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RecoverRenewalStatus(response, q2, testRelayOrigin, now, nil); err == nil {
		t.Fatal("old response answered fresh challenge")
	}
	if _, err := RecoverRenewalStatus(response, q, "wss://other.example/connects", now, nil); err == nil {
		t.Fatal("changed origin")
	}
	// Legacy response readers must never interpret status as credentials.
	if _, err := OpenRenewalResponse(response, pending.Material, testRelayOrigin, now); err == nil {
		t.Fatal("status activated credentials")
	}
	if _, err := r.Renew(q.Encrypted, now, staticIssuer("forbidden")); err == nil {
		t.Fatal("legacy renewal reader accepted extension")
	}
}

func TestRenewalStatusRejectsRequestsWithoutCurrentPairingAuthority(t *testing.T) {
	r, p, now := statusFixture(t)
	pending, _ := CreateRenewal(p, testRelayOrigin, now, time.Minute)
	q, _ := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
	root, lock, state, err := r.lockedState()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := readSecrets(root, state, now)
	lock.Close()
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openAge(q.Encrypted, statusRequestCipher, secrets.ageIdentity.String(), MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := signing.ParsePrivate(p.pairingPrivate)
	if err != nil {
		t.Fatal(err)
	}
	var payload renewalStatusPayload
	if err := openSigned(plain, statusRequestEnvelope, statusRequestDomain, priv.Public().(ed25519.PublicKey), MaxRequestSize, &payload); err != nil {
		t.Fatal(err)
	}
	other, _ := signing.Generate()
	for _, tc := range []struct {
		name   string
		change func(*renewalStatusPayload)
		key    ed25519.PrivateKey
	}{
		{"signature", func(p *renewalStatusPayload) {}, other.Private},
		{"client", func(p *renewalStatusPayload) { p.ClientID, _ = randomID() }, priv},
		{"receiver", func(p *renewalStatusPayload) { p.ReceiverID, _ = randomID() }, priv},
		{"route", func(p *renewalStatusPayload) { p.RouteID, _ = randomID() }, priv},
		{"origin", func(p *renewalStatusPayload) { p.RelayOrigin = "wss://other.example/connects" }, priv},
		{"nonce", func(p *renewalStatusPayload) { p.Nonce = "" }, priv},
		{"digest", func(p *renewalStatusPayload) { p.PendingSHA256 = "" }, priv},
		{"generation", func(p *renewalStatusPayload) { p.KnownGeneration++ }, priv},
		{"overflow", func(p *renewalStatusPayload) { p.KnownGeneration = math.MaxUint64 }, priv},
		{"recipient", func(p *renewalStatusPayload) { p.ResponseRecipient = "invalid" }, priv},
		{"window", func(p *renewalStatusPayload) { p.ExpiresUnix = p.CreatedUnix + 3601 }, priv},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := payload
			tc.change(&changed)
			signed, err := signPayload(statusRequestEnvelope, statusRequestDomain, changed, tc.key, MaxRequestSize)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := sealAge(statusRequestCipher, signed, p.receiverRecipient, MaxRequestSize)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.RenewalStatus(wire, now); err == nil {
				t.Fatal("invalid query answered")
			}
		})
	}
	if _, err := r.RenewalStatus(q.Encrypted, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired query answered")
	}
	if _, err := r.RevokePeer(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenewalStatus(q.Encrypted, now); err == nil {
		t.Fatal("revoked pairing answered")
	}
}

func TestRenewalStatusRepeatedExpiryLostCommitAndDelayedOriginal(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "uncommitted", true: "committed"}[committed], func(t *testing.T) {
			r, p, now := statusFixture(t)
			pending, err := CreateRenewal(p, testRelayOrigin, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if committed {
				if _, err := r.Renew(pending.Encrypted, now, staticIssuer("lost")); err != nil {
					t.Fatal(err)
				}
			}
			now = now.Add(2 * time.Minute)
			for i := 0; i < 4; i++ {
				q, err := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
				if err != nil {
					t.Fatal(err)
				}
				root, lock, _, err := r.lockedState()
				if err != nil {
					t.Fatal(err)
				}
				before, err := root.ReadFile(stateFile, maxStateSize)
				lock.Close()
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
				answer, err := r.RenewalStatus(q.Encrypted, now)
				if err != nil {
					t.Fatal(err)
				}
				root, lock, _, err = r.lockedState()
				if err != nil {
					t.Fatal(err)
				}
				after, err := root.ReadFile(stateFile, maxStateSize)
				lock.Close()
				root.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("status mutated authority")
				}
				next, err := RecoverRenewalStatus(answer, q, testRelayOrigin, now, nil)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(next.Material.pairing.pairingPrivate, p.pairingPrivate) || !bytes.Equal(next.Material.pairing.receiverPublic, p.receiverPublic) {
					t.Fatal("trust replaced")
				}
				saved, err := next.Material.MarshalPrivate()
				if err != nil {
					t.Fatal(err)
				}
				restored, err := ParseRenewalMaterial(saved)
				if err != nil {
					t.Fatal(err)
				}
				next.Material = restored
				// Alternate uncommitted expiry and lost committed responses repeatedly.
				if i%2 == 1 {
					if _, err := r.Renew(next.Encrypted, now, staticIssuer("lost-again")); err != nil {
						t.Fatal(err)
					}
				}
				pending = next
				now = now.Add(2 * time.Hour)
			}
			q, _ := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
			answer, err := r.RenewalStatus(q.Encrypted, now)
			if err != nil {
				t.Fatal(err)
			}
			next, err := RecoverRenewalStatus(answer, q, testRelayOrigin, now, nil)
			if err != nil {
				t.Fatal(err)
			}
			fresh, err := r.Renew(next.Encrypted, now, staticIssuer("fresh"))
			if err != nil {
				t.Fatal(err)
			}
			opened, err := OpenRenewalResponse(fresh.Response, next.Material, testRelayOrigin, now)
			if err != nil || string(opened.Authorization) != "fresh" {
				t.Fatal("fresh activation failed", err)
			}
		})
	}
	// A delayed original can win after a status snapshot. The replacement fails
	// closed; another fresh snapshot reconciles that competing same-generation commit.
	r, p, now := statusFixture(t)
	old, _ := CreateRenewal(p, testRelayOrigin, now, time.Hour)
	q, _ := CreateRenewalStatus(old.Material, testRelayOrigin, now)
	answer, err := r.RenewalStatus(q.Encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err := RecoverRenewalStatus(answer, q, testRelayOrigin, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Renew(old.Encrypted, now, staticIssuer("delayed")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Renew(next.Encrypted, now, staticIssuer("wrong")); err == nil {
		t.Fatal("stale snapshot overrode committed generation")
	}
	q, _ = CreateRenewalStatus(next.Material, testRelayOrigin, now)
	answer, err = r.RenewalStatus(q.Encrypted, now)
	if err != nil {
		t.Fatal(err)
	}
	next, err = RecoverRenewalStatus(answer, q, testRelayOrigin, now, nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := r.Renew(next.Encrypted, now, staticIssuer("fresh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRenewalResponse(fresh.Response, next.Material, testRelayOrigin, now); err != nil {
		t.Fatal(err)
	}
}

func TestRenewalStatusLocksStrictParsingAndBounds(t *testing.T) {
	for _, kind := range []string{"local", "peer", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			r, p, now := statusFixture(t)
			req, _ := CreateRenewal(p, testRelayOrigin, now, time.Minute)
			q, _ := CreateRenewalStatus(req.Material, testRelayOrigin, now)
			var err error
			switch kind {
			case "local":
				_, err = r.SetLocalLocked(true)
			case "peer":
				_, err = r.SetPeerLocked(true)
			case "revoked":
				_, err = r.RevokePeer()
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := r.RenewalStatus(q.Encrypted, now); err == nil {
				t.Fatal("locked status answered")
			}
		})
	}
	r, p, now := statusFixture(t)
	pending, _ := CreateRenewal(p, testRelayOrigin, now, time.Minute)
	q, _ := CreateRenewalStatus(pending.Material, testRelayOrigin, now)
	for _, wire := range [][]byte{nil, []byte("{}\n"), append([]byte(" "), q.Encrypted...), bytes.Repeat([]byte("x"), MaxRequestSize+1)} {
		if _, err := r.RenewalStatus(wire, now); err == nil {
			t.Fatal("noncanonical or unbounded query accepted")
		}
	}
	// Sign an otherwise valid payload carrying an extra field: even an authorized
	// peer cannot make the extension reinterpret an unknown schema field.
	root, lock, state, err := r.lockedState()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := readSecrets(root, state, now)
	lock.Close()
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := openAge(q.Encrypted, statusRequestCipher, secrets.ageIdentity.String(), MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	private, _ := signing.ParsePrivate(p.pairingPrivate)
	var payload renewalStatusPayload
	if err := openSigned(plain, statusRequestEnvelope, statusRequestDomain, private.Public().(ed25519.PublicKey), MaxRequestSize, &payload); err != nil {
		t.Fatal(err)
	}
	unknown := struct {
		renewalStatusPayload
		Unknown string `json:"unknown"`
	}{payload, "forbidden"}
	signed, err := signPayload(statusRequestEnvelope, statusRequestDomain, unknown, private, MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealAge(statusRequestCipher, signed, p.receiverRecipient, MaxRequestSize)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.RenewalStatus(wire, now); err == nil {
		t.Fatal("unknown signed field accepted")
	}
}
