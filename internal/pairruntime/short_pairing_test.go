//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/transport"
)

func shortRelayFixture(t *testing.T) (*atomic.Pointer[pairrelay.Relay], pairrelay.DialFunc, func() *pairrelay.Relay) {
	t.Helper()
	now := time.Now()
	ca, err := pki.NewCA("short pairing relay fixture", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.IssueLeaf(ca, "relay.paired.owntransit.invalid", x509.ExtKeyUsageServerAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := identity.ParseKeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	config := pairrelay.RelayConfig{
		TokenKey: key, RelayTLS: pairrelay.TLSMaterial{Certificate: certificate, CAPEM: ca.CertPEM, ServerName: "relay.paired.owntransit.invalid"},
		VerifyAdvertisement: func(encoded []byte, now time.Time) (pairrelay.Descriptor, error) {
			ad, err := receiverpairing.VerifyAdvertisement(encoded, now)
			if err != nil {
				return pairrelay.Descriptor{}, err
			}
			receiver, err := protocol.ParseID(ad.ReceiverID)
			if err != nil {
				return pairrelay.Descriptor{}, err
			}
			route, err := protocol.ParseRouteID(ad.RouteID)
			return pairrelay.Descriptor{ReceiverID: receiver, RouteID: route, AdmissionCAPEM: []byte(ad.Trust.OuterEndpointCAPEM)}, err
		},
	}
	current := &atomic.Pointer[pairrelay.Relay]{}
	restart := func() *pairrelay.Relay {
		next, err := pairrelay.NewRelay(config)
		if err != nil {
			t.Fatal(err)
		}
		if previous := current.Swap(next); previous != nil {
			_ = previous.Close()
		}
		return next
	}
	restart()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = current.Load().Close() })
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		ws, _, err := websocket.Dial(ctx, server.URL+pairrelay.Path, &websocket.DialOptions{Subprotocols: []string{pairrelay.WebSocketSubprotocol}})
		if err != nil {
			return nil, err
		}
		return transport.WrapWebSocket(ctx, ws, 2<<20)
	}
	return current, dial, restart
}

func shortRouteFixture(t *testing.T, relay *pairrelay.Relay, dial pairrelay.DialFunc) (*integrated, *pairrelay.PublicClient, []byte) {
	t.Helper()
	f := &integrated{relay: relay, dial: dial, serverPath: privatePath(t, "receiver"), clientPath: privatePath(t, "client")}
	public, err := pairrelay.NewPublicClient("wss://relay.example/connects", dial)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	info, err := public.FetchServerInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.attempt, err = InitializeReceiverWithOffer(f.serverPath, "wss://relay.example/connects", info)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.attempt.Code) != pairoffer.CodeSize || pairoffer.ValidateCode(f.attempt.Code) != nil {
		t.Fatal("new receiver did not return the fixed short code")
	}
	snapshot, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil || len(snapshot.Offer) == 0 {
		t.Fatal("new receiver did not retain its public offer")
	}
	if err := public.PublishOffer(ctx, snapshot.Offer, nil); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.sshSigner, err = ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return f, public, snapshot.Offer
}

func approveShortFixture(t *testing.T, f *integrated) {
	t.Helper()
	receiverID, err := protocol.ParseID(f.attempt.ReceiverID)
	if err != nil {
		t.Fatal(err)
	}
	f.registration, err = f.relay.RegisterReceiver(receiverID, pairrelay.RouteLimits{
		PendingPairings: 4, PendingCarriers: 4, ActiveCarriers: 4, PairingBytes: pairrelay.MaxPairingBytes, SessionLifetime: time.Hour,
	}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
}

func stopShortFixture(t *testing.T, stop context.CancelFunc, done <-chan error) {
	t.Helper()
	stop()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("pending receiver did not stop")
	}
}

func TestShortPairingSurvivesPendingReceiverAndRelayRestartThenCarriesSSH(t *testing.T) {
	current, dial, restart := shortRelayFixture(t)
	f, public, originalOffer := shortRouteFixture(t, current.Load(), dial)
	approveShortFixture(t, f)
	originalToken := append([]byte(nil), f.registration.Token...)
	stop, done := f.start(t)
	eventually(t, func() bool {
		snapshot, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
		return err == nil && bytes.Equal(snapshot.Meta.Token, originalToken)
	})
	approveShortFixture(t, f)
	if !bytes.Equal(f.registration.Token, originalToken) {
		t.Fatal("repeated VPS approval changed a pending receiver's token")
	}
	stopShortFixture(t, stop, done)
	before, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil || before.Status.PairedClientID != "" || !bytes.Equal(before.Offer, originalOffer) {
		t.Fatal("pending restart changed receiver pairing")
	}
	// A receiver restart retains its exact setup identity and code binding.
	stop, done = f.start(t)
	eventually(t, func() bool {
		snapshot, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
		return err == nil && snapshot.Status.ReceiverID == before.Status.ReceiverID && bytes.Equal(snapshot.Offer, originalOffer)
	})
	stopShortFixture(t, stop, done)
	// A cache-losing relay restart keeps only relay-owned key material. No
	// second local registration is performed anywhere after this point.
	f.relay = restart()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	locator, err := pairoffer.Locator(f.attempt.Code)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := public.FetchOffer(ctx, locator); err == nil {
		t.Fatal("new relay unexpectedly retained offer")
	}
	if _, err := public.FetchRegistration(ctx, f.attempt.Advertisement); err == nil {
		t.Fatal("new relay unexpectedly retained registration")
	}
	stop, done = f.start(t)
	eventually(t, func() bool {
		token, err := public.FetchRegistration(ctx, f.attempt.Advertisement)
		return err == nil && bytes.Equal(token, originalToken)
	})
	gotOffer, err := public.FetchOffer(ctx, locator)
	if err != nil || !bytes.Equal(gotOffer, originalOffer) {
		t.Fatal("restart changed offer bytes")
	}
	if err := PairClientShort(ctx, f.clientPath, "wss://relay.example/connects", f.attempt.Code, f.dial); err != nil {
		t.Fatal(err)
	}
	if f.dials.Load() != 0 {
		t.Fatal("short pairing dialed local SSH before runtime authentication")
	}
	f.assertSSH(t)
	stopShortFixture(t, stop, done)
	after, err := (ReceiverBackend{Path: f.serverPath}).Snapshot()
	if err != nil || after.Status.PairedClientID == "" || len(after.Offer) != 0 {
		t.Fatal("paired worker still depends on one-use offer")
	}
	// A corrupt, spent sidecar cannot disable an already paired tunnel.
	root, err := securefs.OpenRoot(f.serverPath)
	if err != nil {
		t.Fatal(err)
	}
	err = root.ReplaceFile("pair-offer.json", []byte("spent offer fixture"), 0600)
	root.Close()
	if err != nil {
		t.Fatal(err)
	}
	f.relay = restart()
	stop, done = f.start(t)
	f.assertSSH(t)
	if _, err := public.FetchOffer(ctx, locator); err == nil {
		t.Fatal("paired worker republished spent offer")
	}
	stopShortFixture(t, stop, done)
}

func TestShortPairingMissingApprovalAndWrongOriginCreateNoClientState(t *testing.T) {
	current, dial, _ := shortRelayFixture(t)
	f, _, _ := shortRouteFixture(t, current.Load(), dial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := PairClientShort(ctx, f.clientPath, "wss://relay.example/connects", f.attempt.Code, dial); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("missing VPS approval was not identified: %v", err)
	}
	assertNoShortClientState(t, f.clientPath)
	approveShortFixture(t, f)
	if err := PairClientShort(ctx, f.clientPath, "wss://other-relay.example/connects", f.attempt.Code, dial); !errors.Is(err, ErrReceiverOffer) {
		t.Fatalf("wrong origin accepted an offer: %v", err)
	}
	assertNoShortClientState(t, f.clientPath)
	if f.dials.Load() != 0 {
		t.Fatal("failed setup dialed local SSH")
	}
}

func assertNoShortClientState(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed public discovery created client state")
	}
}

// An intentionally hostile transport fixture implements only the two public
// offer operations. Any attempt to proceed to registration or an encrypted
// pairing exchange is counted and rejected.
func hostileShortOfferDial(offer []byte, old bool, calls *atomic.Int32, leaked *atomic.Bool, code []byte) pairrelay.DialFunc {
	secret, _ := pairoffer.Secret(code)
	return func(ctx context.Context, _ string) (net.Conn, error) {
		local, remote := net.Pipe()
		stop := context.AfterFunc(ctx, func() { _ = local.Close(); _ = remote.Close() })
		go func() {
			defer stop()
			defer remote.Close()
			calls.Add(1)
			var header [12]byte
			if _, err := io.ReadFull(remote, header[:]); err != nil || string(header[:4]) != "OTR2" || header[4] != 2 {
				return
			}
			size := int(binary.BigEndian.Uint32(header[8:]))
			if size > 128 {
				return
			}
			body := make([]byte, size)
			if _, err := io.ReadFull(remote, body); err != nil {
				return
			}
			if bytes.Contains(body, code) || bytes.Contains(body, secret[:]) {
				leaked.Store(true)
			}
			kind := byte(0xff)
			var response []byte
			if !old {
				switch header[5] {
				case 9:
					kind, response = 0x87, []byte("owntransit.receiver-offer.v1\n")
				case 11:
					kind, response = 0x88, offer
				}
			}
			header[5] = kind
			binary.BigEndian.PutUint32(header[8:], uint32(len(response)))
			_, _ = io.Copy(remote, bytesReader(header[:], response))
		}()
		return local, nil
	}
}

func TestShortPairingOldRelayAndTamperedOffersStopBeforeStateAndSecrets(t *testing.T) {
	current, dial, _ := shortRelayFixture(t)
	f, _, encoded := shortRouteFixture(t, current.Load(), dial)
	parsed, err := pairoffer.Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	changed := parsed
	changed.Proof[0] ^= 1
	wrongProof, err := pairoffer.Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	changed = parsed
	changed.Advertisement = []byte("substituted public advertisement")
	wrongAd, err := pairoffer.Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	changed = parsed
	changed.Locator[0] ^= 1
	wrongLocator, err := pairoffer.Encode(changed)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name      string
		offer     []byte
		old       bool
		wantCalls int32
		wantError error
	}{
		{"old relay", nil, true, 1, ErrOfferUnavailable},
		{"changed proof", wrongProof, false, 2, ErrReceiverOffer},
		{"changed advertisement", wrongAd, false, 2, ErrReceiverOffer},
		{"changed locator", wrongLocator, false, 2, ErrOfferUnavailable},
		{"unknown version", bytes.Replace(encoded, []byte("receiver-offer.v1"), []byte("receiver-offer.v2"), 1), false, 2, ErrOfferUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			var calls atomic.Int32
			var leaked atomic.Bool
			path := privatePath(t, "client")
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := PairClientShort(ctx, path, "wss://relay.example/connects", f.attempt.Code, hostileShortOfferDial(test.offer, test.old, &calls, &leaked, f.attempt.Code))
			if !errors.Is(err, test.wantError) || calls.Load() != test.wantCalls || leaked.Load() {
				t.Fatalf("public verification gate failed: calls=%d error=%v", calls.Load(), err)
			}
			assertNoShortClientState(t, path)
		})
	}
	legacy, err := receiverpairing.RecoverLegacyCode(f.attempt.Code, encoded, "wss://relay.example/connects", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(legacy)
	var calls atomic.Int32
	var leaked atomic.Bool
	err = PairClientShort(context.Background(), f.clientPath, "wss://relay.example/connects", legacy, hostileShortOfferDial(encoded, false, &calls, &leaked, f.attempt.Code))
	if !errors.Is(err, ErrReceiverOffer) || calls.Load() != 0 {
		t.Fatal("short setup silently accepted the legacy code profile")
	}
	assertNoShortClientState(t, f.clientPath)
	if _, err := os.Stat(filepath.Join(f.clientPath, "client.json")); !errors.Is(err, os.ErrNotExist) || f.dials.Load() != 0 {
		t.Fatal("failed hostile relay checks created state or dialed SSH")
	}
}
