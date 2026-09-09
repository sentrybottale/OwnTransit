package pairrelay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/transport"
)

func publicOfferFixture(t *testing.T, advertisement []byte) (pairoffer.Offer, []byte) {
	t.Helper()
	offer := pairoffer.Offer{Advertisement: append([]byte(nil), advertisement...)}
	if _, err := rand.Read(offer.Locator[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(offer.Proof[:]); err != nil {
		t.Fatal(err)
	}
	return offer, encodePublicOffer(t, offer)
}

func encodePublicOffer(t *testing.T, offer pairoffer.Offer) []byte {
	t.Helper()
	encoded, err := pairoffer.Encode(offer)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func offerRouteLimits() RouteLimits {
	return RouteLimits{PendingPairings: 1, PendingCarriers: 1, ActiveCarriers: 1, PairingBytes: 1024, SessionLifetime: time.Hour}
}

func TestOfferRequiresVerifiedAdvertisementAndDoesNotMintRegistration(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := f.public.CheckOfferSupport(ctx); err != nil {
		t.Fatal(err)
	}
	_, invalid := publicOfferFixture(t, []byte("unverified-advertisement"))
	if err := f.public.PublishOffer(ctx, invalid, nil); err == nil {
		t.Fatal("offer bypassed mandatory advertisement verifier")
	}
	if len(f.relay.advertisements) != 0 || len(f.relay.registrations) != 0 {
		t.Fatal("failed offer left cache state")
	}
	offer, encoded := publicOfferFixture(t, f.advertisement)
	if err := f.public.PublishOffer(ctx, encoded, nil); err != nil {
		t.Fatal(err)
	}
	got, err := f.public.FetchOffer(ctx, offer.Locator)
	if err != nil || !bytes.Equal(got, encoded) {
		t.Fatalf("offer delivery changed bytes: %v", err)
	}
	if _, err := f.public.FetchRegistration(ctx, f.advertisement); err == nil || len(f.relay.registrations) != 0 {
		t.Fatal("public offer minted registration")
	}
	registration, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	gotToken, err := f.public.FetchRegistration(ctx, f.advertisement)
	if err != nil || !bytes.Equal(gotToken, registration.Token) {
		t.Fatalf("explicit registration unavailable: %v", err)
	}
	// Existing public APIs retain their wire meanings on a new relay.
	if err := f.public.PublishAdvertisement(ctx, f.advertisement); err != nil {
		t.Fatal(err)
	}
	gotAd, err := f.public.FetchAdvertisement(ctx, registration.Token)
	if err != nil || !bytes.Equal(gotAd, f.advertisement) {
		t.Fatalf("legacy advertisement API changed: %v", err)
	}
}

func TestOfferBindingsAreImmutableAndShareAdvertisementQuota(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.Advertisements = 1
	f.relay.limits.AdvertisementTTL = time.Minute
	now := f.now
	f.relay.now = func() time.Time { return now }
	secondAd := []byte("another-verified-advertisement")
	secondDescriptor := f.descriptor
	secondDescriptor.ReceiverID, secondDescriptor.RouteID = mustID(t), mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		switch {
		case bytes.Equal(encoded, f.advertisement), bytes.Equal(encoded, []byte("changed-same-route")):
			return f.descriptor, nil
		case bytes.Equal(encoded, secondAd):
			return secondDescriptor, nil
		default:
			return Descriptor{}, ErrUnauthorized
		}
	}
	offer, encoded := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(encoded, nil); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func(*pairoffer.Offer){
		func(value *pairoffer.Offer) { value.Proof[0] ^= 1 },
		func(value *pairoffer.Offer) { value.Locator[0] ^= 1 },
		func(value *pairoffer.Offer) { value.Advertisement = []byte("changed-same-route") },
		func(value *pairoffer.Offer) { value.Advertisement = secondAd },
	} {
		changed := offer
		mutation(&changed)
		if err := f.relay.publishOffer(encodePublicOffer(t, changed), nil); err == nil {
			t.Fatal("offer binding replaced")
		}
	}
	if err := f.relay.publishAdvertisement([]byte("changed-same-route")); err == nil {
		t.Fatal("ordinary publication replaced offer advertisement")
	}
	if err := f.relay.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	if err := f.relay.publishOffer(encoded, nil); err != nil {
		t.Fatal("exact retry was not idempotent")
	}
	got, err := f.relay.fetchOffer(offer.Locator)
	if err != nil || !bytes.Equal(got, encoded) {
		t.Fatal("ordinary publication cleared offer proof")
	}
	secondOffer, secondEncoded := publicOfferFixture(t, secondAd)
	if err := f.relay.publishOffer(secondEncoded, nil); !errors.Is(err, ErrCapacity) {
		t.Fatalf("offer bypassed advertisement quota: %v", err)
	}
	now = now.Add(f.relay.limits.AdvertisementTTL)
	if _, err := f.relay.fetchOffer(offer.Locator); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired offer remained visible")
	}
	if err := f.relay.publishOffer(secondEncoded, nil); err != nil {
		t.Fatalf("expired slot was not reusable: %v", err)
	}
	if len(f.relay.advertisements) != 1 {
		t.Fatal("offer created independent cache state")
	}
	if err := f.relay.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.relay.fetchOffer(secondOffer.Locator); err == nil || len(f.relay.advertisements) != 0 {
		t.Fatal("closed relay retained offer")
	}
}

func TestOfferRestoresOnlyExactUnexpiredRegistrationAfterRestart(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	offer, encoded := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(encoded, nil); err != nil {
		t.Fatal(err)
	}
	registration, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(f.tokenKey, registration.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.relay.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewRelay(f.relay.config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if err := restarted.publishOffer(encoded, registration.Token); err != nil {
		t.Fatal(err)
	}
	got, err := restarted.fetchRegistration(f.advertisement)
	if err != nil || !bytes.Equal(got, registration.Token) {
		t.Fatalf("restart changed exact token: %v", err)
	}
	restoredClaims, err := VerifyToken(f.tokenKey, got, f.now)
	if err != nil || restoredClaims != claims {
		t.Fatal("restore changed token claims, limits or expiry")
	}
	if err := restarted.publishOffer(encoded, got); err != nil {
		t.Fatal("exact restore retry failed")
	}
	if err := restarted.publishOffer(encoded, nil); err != nil {
		t.Fatal("tokenless retry failed")
	}
	gotOffer, err := restarted.fetchOffer(offer.Locator)
	if err != nil || !bytes.Equal(gotOffer, encoded) {
		t.Fatal("restored offer changed")
	}
	for _, mutate := range []func(*TokenClaims){
		func(value *TokenClaims) { value.ReceiverID = mustID(t) },
		func(value *TokenClaims) { value.RouteID = mustRouteID(t) },
		func(value *TokenClaims) { value.AdmissionRootSHA256[0] ^= 1 },
		func(value *TokenClaims) { value.Limits.ActiveCarriers++ },
		func(value *TokenClaims) { value.ExpiresUnix++ },
		func(value *TokenClaims) { value.Generation++ },
	} {
		changed := claims
		mutate(&changed)
		otherToken, err := sealToken(f.tokenKey, changed)
		if err != nil {
			t.Fatal(err)
		}
		if err := restarted.publishOffer(encoded, otherToken); err == nil {
			t.Fatal("conflicting token overwrote registration")
		}
	}
	got, err = restarted.fetchRegistration(f.advertisement)
	if err != nil || !bytes.Equal(got, registration.Token) {
		t.Fatal("conflicting restore mutated registration")
	}
}

func TestOfferRestoreRejectsInvalidTokensWithoutCaching(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	_, encoded := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	registration, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(f.tokenKey, registration.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*TokenClaims){
		"receiver":       func(value *TokenClaims) { value.ReceiverID = mustID(t) },
		"route":          func(value *TokenClaims) { value.RouteID = mustRouteID(t) },
		"root":           func(value *TokenClaims) { value.AdmissionRootSHA256[0] ^= 1 },
		"expired":        func(value *TokenClaims) { value.IssuedUnix -= 7200; value.ExpiresUnix -= 7200 },
		"future":         func(value *TokenClaims) { value.IssuedUnix += 7200; value.ExpiresUnix += 7200 },
		"invalid limits": func(value *TokenClaims) { value.Limits.ActiveCarriers = 0 },
		"forged":         func(value *TokenClaims) {},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			restarted, err := NewRelay(f.relay.config)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.Close()
			changed := claims
			mutate(&changed)
			token, err := sealToken(f.tokenKey, changed)
			if err != nil {
				t.Fatal(err)
			}
			if name == "forged" {
				token[len(token)-1] ^= 1
			}
			if err := restarted.publishOffer(encoded, token); err == nil {
				t.Fatal("invalid restore accepted")
			}
			if len(restarted.advertisements) != 0 || len(restarted.registrations) != 0 {
				t.Fatal("failed restoration cached offer or registration")
			}
		})
	}
}

func TestOfferLocatorCollisionDoesNotConsumeAnotherSlot(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.Advertisements = 2
	otherAd := []byte("another-public-advertisement")
	otherDescriptor := f.descriptor
	otherDescriptor.ReceiverID, otherDescriptor.RouteID = mustID(t), mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, otherAd) {
			return otherDescriptor, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	offer, encoded := publicOfferFixture(t, f.advertisement)
	if err := f.relay.publishOffer(encoded, nil); err != nil {
		t.Fatal(err)
	}
	collision := offer
	collision.Advertisement = otherAd
	if err := f.relay.publishOffer(encodePublicOffer(t, collision), nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("cross-route locator collision accepted: %v", err)
	}
	if len(f.relay.advertisements) != 1 {
		t.Fatal("failed collision consumed capacity")
	}
	collision.Locator[0] ^= 1
	if err := f.relay.publishOffer(encodePublicOffer(t, collision), nil); err != nil {
		t.Fatal("independent locator could not use free slot")
	}
}

func TestOfferRegistrationRestorationHasBoundedDeliveryState(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.Advertisements = 1
	f.relay.limits.AdvertisementTTL = time.Minute
	now := f.now
	f.relay.now = func() time.Time { return now }
	otherAd := []byte("another-public-advertisement")
	otherDescriptor := f.descriptor
	otherDescriptor.ReceiverID, otherDescriptor.RouteID = mustID(t), mustRouteID(t)
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, otherAd) {
			return otherDescriptor, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	if err := f.relay.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	first, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(f.tokenKey, first.Token, now)
	if err != nil {
		t.Fatal(err)
	}
	claims.ReceiverID, claims.RouteID = otherDescriptor.ReceiverID, otherDescriptor.RouteID
	claims.ExpiresUnix = now.Add(2 * time.Hour).Unix()
	secondToken, err := IssueToken(f.tokenKey, claims, now)
	if err != nil {
		t.Fatal(err)
	}
	_, secondOffer := publicOfferFixture(t, otherAd)
	now = now.Add(time.Minute)
	if err := f.relay.publishOffer(secondOffer, secondToken); !errors.Is(err, ErrCapacity) {
		t.Fatalf("restoration bypassed registration delivery capacity: %v", err)
	}
	if len(f.relay.advertisements) != 0 || len(f.relay.registrations) != 1 {
		t.Fatal("failed restoration partially published offer")
	}
	if err := f.relay.publishAdvertisement(otherAd); err != nil {
		t.Fatal(err)
	}
	if _, err := f.relay.RegisterReceiver(otherDescriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrCapacity) {
		t.Fatal("local registration bypassed delivery capacity")
	}
	now = f.now.Add(time.Hour)
	if err := f.relay.publishOffer(secondOffer, secondToken); err != nil {
		t.Fatalf("expired registration capacity not reusable: %v", err)
	}
	if len(f.relay.advertisements) != 1 || len(f.relay.registrations) != 1 {
		t.Fatal("restoration grew bounded delivery state")
	}
}

func TestRepeatedLocalRegistrationPreservesExistingTokenAndExpiry(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	now := f.now
	f.relay.now = func() time.Time { return now }
	if err := f.relay.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	first, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	repeated, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil || !bytes.Equal(repeated.Token, first.Token) {
		t.Fatalf("repeated local approval replaced live token: %v", err)
	}
	changed, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), 2*time.Hour)
	if err != nil || bytes.Equal(changed.Token, first.Token) {
		t.Fatal("explicit validity change ignored")
	}
	limits := offerRouteLimits()
	limits.ActiveCarriers++
	changedAgain, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, limits, 2*time.Hour)
	if err != nil || bytes.Equal(changedAgain.Token, changed.Token) {
		t.Fatal("explicit limits change ignored")
	}
}

func TestOfferRejectsOversizedHeaderBeforeReadingPayload(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.HandshakeTimeout = 2 * time.Second
	for _, test := range []struct {
		kind  byte
		limit int
	}{
		{kindCheckOfferSupport, len(offerProfile)}, {kindPublishOffer, maxOfferPublicationBytes}, {kindFetchOffer, offerLocatorBytes},
	} {
		local, remote := net.Pipe()
		done := make(chan error, 1)
		go func() { done <- f.relay.handleConnection(remote); _ = remote.Close() }()
		var header [wireHeaderSize]byte
		copy(header[:4], "OTR2")
		header[4], header[5] = wireVersion, test.kind
		binary.BigEndian.PutUint32(header[8:], uint32(test.limit+1))
		if _, err := local.Write(header[:]); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.Is(err, ErrProtocol) {
				t.Fatal("oversized header did not fail protocol validation")
			}
		case <-time.After(300 * time.Millisecond):
			t.Fatal("oversized header waited for body")
		}
		_ = local.Close()
	}
}

func TestOfferExtensionKeepsOriginalWireConstantsAndRejectsFrameVersions(t *testing.T) {
	if wireVersion != 2 || wireHeaderSize != 12 || WebSocketSubprotocol != "owntransit.carrier.v2" || OuterALPN != "owntransit-relay-admission/2" {
		t.Fatal("offer changed existing wire profile")
	}
	for index, kind := range []byte{kindPublishAdvertisement, kindFetchAdvertisement, kindPairReceiver, kindPairClient, kindRuntime, kindRenewToken, kindFetchRegistration, kindFetchServerInfo} {
		if kind != byte(index+1) {
			t.Fatal("offer renumbered existing operation")
		}
	}
	for index, kind := range []byte{kindOK, kindAdvertisement, kindPairRequest, kindPairResponse, kindRenewedToken, kindReady, kindServerInfo} {
		if kind != byte(index+0x80) {
			t.Fatal("offer renumbered existing response")
		}
	}
	for _, version := range []byte{0, 1, 3, 255} {
		var header [wireHeaderSize]byte
		copy(header[:4], "OTR2")
		header[4], header[5] = version, kindCheckOfferSupport
		if _, err := readWireFrame(bytes.NewReader(header[:]), maxWirePayload); !errors.Is(err, ErrProtocol) {
			t.Fatal("unsupported frame version accepted")
		}
	}
}

func TestOfferWireRejectsMalformedAndUnsupportedInput(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	_, encoded := publicOfferFixture(t, f.advertisement)
	payload, err := encodeOfferPublication(encoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	unknownVersion := append([]byte(nil), payload...)
	unknownVersion[0]++
	for _, invalid := range [][]byte{nil, {1}, payload[:len(payload)-1], append(append([]byte(nil), payload...), 0), unknownVersion} {
		if _, _, err := decodeOfferPublication(invalid); err == nil {
			t.Fatal("malformed offer publication accepted")
		}
	}
	for _, invalid := range [][]byte{nil, {1}, make([]byte, 33), append([]byte{2}, bytes.Repeat([]byte{1}, 32)...)} {
		if _, err := decodeOfferLocator(invalid); err == nil {
			t.Fatal("malformed offer locator accepted")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, invalid := range [][]byte{nil, []byte("otpair2.private-input"), bytes.Repeat([]byte{1}, pairoffer.MaxOfferBytes+1), bytes.Replace(encoded, []byte("receiver-offer.v1"), []byte("receiver-offer.v2"), 1)} {
		if err := f.public.PublishOffer(ctx, invalid, nil); !errors.Is(err, ErrProtocol) {
			t.Fatal("malformed offer reached network")
		}
	}
	if _, err := f.public.FetchOffer(ctx, [32]byte{}); !errors.Is(err, ErrProtocol) {
		t.Fatal("empty locator reached network")
	}
	for _, test := range []struct {
		kind byte
		data []byte
	}{
		{kindCheckOfferSupport, nil}, {kindCheckOfferSupport, []byte("owntransit.receiver-offer.v2\n")},
		{kindPublishOffer, unknownVersion}, {kindFetchOffer, make([]byte, 33)}, {12, nil},
	} {
		connection, err := f.public.connect(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeWireFrame(connection, test.kind, test.data, maxWirePayload); err != nil {
			t.Fatal(err)
		}
		if _, err := readWireFrame(connection, maxWirePayload); err == nil {
			t.Fatal("unsupported operation returned success")
		}
		_ = connection.Close()
	}
}

func TestOfferSupportRejectsOldRelayAndWrongProfileWithoutFallback(t *testing.T) {
	for _, response := range []wireFrame{{kind: kindFailure}, {kind: kindServerInfo, data: []byte("old-server-info")}, {kind: kindOfferSupport, data: []byte("owntransit.receiver-offer.v2\n")}} {
		calls := 0
		client, err := NewPublicClient("wss://relay.example/connects", func(ctx context.Context, _ string) (net.Conn, error) {
			calls++
			local, remote := net.Pipe()
			go func() {
				defer remote.Close()
				request, err := readWireFrame(remote, maxWirePayload)
				if err == nil && request.kind == kindCheckOfferSupport {
					_ = writeWireFrame(remote, response.kind, response.data, maxWirePayload)
				}
			}()
			return local, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckOfferSupport(context.Background()); err == nil || calls != 1 {
			t.Fatal("old relay negotiated another operation")
		}
	}
}

func TestOfferInitialFrameBoundsReleaseWebSocketCapacity(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	f.relay.limits.HandshakeTimeout = 60 * time.Millisecond
	f.relay.connections = make(chan struct{}, 1)
	server := httptest.NewServer(f.relay)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, size := range []int{maxOfferPublicationBytes, maxOfferPublicationBytes + 1} {
		ws, _, err := websocket.Dial(ctx, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}})
		if err != nil {
			t.Fatal(err)
		}
		var header [wireHeaderSize]byte
		copy(header[:4], "OTR2")
		header[4], header[5] = wireVersion, kindPublishOffer
		binary.BigEndian.PutUint32(header[8:], uint32(size))
		if err := ws.Write(ctx, websocket.MessageBinary, header[:]); err != nil {
			t.Fatal(err)
		}
		// An aborted WebSocket or the generic failure frame both represent
		// rejection; neither can keep the admission slot.
		_, _, _ = ws.Read(ctx)
		_ = ws.CloseNow()
		deadline := time.Now().Add(time.Second)
		for len(f.relay.connections) != 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if len(f.relay.connections) != 0 {
			t.Fatal("partial/oversized offer kept admission capacity")
		}
		public, err := NewPublicClient("wss://relay.example/connects", func(ctx context.Context, _ string) (net.Conn, error) {
			ws, _, err := websocket.Dial(ctx, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}})
			if err != nil {
				return nil, err
			}
			return transport.WrapWebSocket(ctx, ws, maxWirePayload+wireHeaderSize)
		})
		if err != nil || public.CheckOfferSupport(ctx) != nil {
			t.Fatal("released capacity could not serve capability check")
		}
	}
}
