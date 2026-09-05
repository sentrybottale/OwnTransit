package pairrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

type relayFixture struct {
	relay         *Relay
	public        *PublicClient
	descriptor    Descriptor
	advertisement []byte
	tokenKey      []byte
	now           time.Time
	relayInfo     ServerInfo
	admissionCA   pki.Material
	relayCA       pki.Material
}

func TestPublicRegistrationPairingRuntimeAndRenewal(t *testing.T) {
	fixture := newRelayFixture(t)
	defer fixture.relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := fixture.public.PublishAdvertisement(ctx, fixture.advertisement); err != nil {
		t.Fatal(err)
	}
	routeLimits := RouteLimits{
		PendingPairings: 2, PendingCarriers: 2, ActiveCarriers: 2,
		PairingBytes: MaxPairingBytes, SessionLifetime: time.Hour,
	}
	registration, err := fixture.relay.RegisterReceiver(fixture.descriptor.ReceiverID, routeLimits, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	receivedToken, err := fixture.public.FetchRegistration(ctx, fixture.advertisement)
	if err != nil || !bytes.Equal(receivedToken, registration.Token) {
		t.Fatalf("registration delivery differs: err=%v", err)
	}
	info, err := fixture.public.FetchServerInfo(ctx)
	if err != nil || info.ServerName != registration.ServerInfo.ServerName ||
		info.LeafSPKISHA256 != registration.ServerInfo.LeafSPKISHA256 || !bytes.Equal(info.CAPEM, registration.ServerInfo.CAPEM) {
		t.Fatalf("server discovery differs: info=%+v err=%v", info, err)
	}
	fetched, err := fixture.public.FetchAdvertisement(ctx, registration.Token)
	if err != nil || !bytes.Equal(fetched, fixture.advertisement) {
		t.Fatalf("advertisement fetch differs: err=%v", err)
	}

	pairingReceiver, err := NewPairingReceiver("wss://relay.example/connects", inMemoryDialer(fixture.relay))
	if err != nil {
		t.Fatal(err)
	}
	request := bytes.Repeat([]byte{0x5a}, 600<<10)
	response := bytes.Repeat([]byte{0xa5}, 600<<10)
	receiverDone := make(chan error, 1)
	go func() {
		receiverDone <- pairingReceiver.AcceptPairing(ctx, registration.Token, func(_ context.Context, got []byte) ([]byte, error) {
			if !bytes.Equal(got, request) {
				return nil, errors.New("request changed")
			}
			return response, nil
		})
	}()
	waitForQueue(t, fixture.relay, true)
	gotResponse, err := fixture.public.ExchangePairing(ctx, registration.Token, request)
	if err != nil || !bytes.Equal(gotResponse, response) {
		t.Fatalf("pairing response differs: size=%d err=%v", len(gotResponse), err)
	}
	if err := <-receiverDone; err != nil {
		t.Fatal(err)
	}

	receiverCertificate := issueEndpointLeaf(t, fixture.admissionCA, RoleReceiver, fixture.descriptor.ReceiverID, fixture.descriptor)
	clientID := mustID(t)
	clientCertificate := issueEndpointLeaf(t, fixture.admissionCA, RoleClient, clientID, fixture.descriptor)
	base := EndpointConfig{
		URL: "wss://relay.example/connects", Token: registration.Token, Descriptor: fixture.descriptor,
		AdmissionCAPEM: fixture.admissionCA.CertPEM, RelayCAPEM: info.CAPEM,
		RelayServerName: info.ServerName, RelayServerSPKI: info.LeafSPKISHA256,
		Dial: inMemoryDialer(fixture.relay),
	}
	receiverConfig := base
	receiverConfig.PeerID, receiverConfig.Certificate = fixture.descriptor.ReceiverID, receiverCertificate
	clientConfig := base
	clientConfig.PeerID, clientConfig.Certificate = clientID, clientCertificate
	receiver, err := NewReceiver(receiverConfig)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		connection net.Conn
		err        error
	}
	receiverResult := make(chan result, 1)
	go func() { connection, err := receiver.Accept(ctx); receiverResult <- result{connection, err} }()
	waitForQueue(t, fixture.relay, false)
	clientConnection, err := client.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	received := <-receiverResult
	if received.err != nil {
		t.Fatal(received.err)
	}
	defer clientConnection.Close()
	defer received.connection.Close()
	payload := []byte("opaque-inner-tls-stream")
	writeDone := make(chan error, 1)
	go func() { _, err := clientConnection.Write(payload); writeDone <- err }()
	read := make([]byte, len(payload))
	if _, err := io.ReadFull(received.connection, read); err != nil || !bytes.Equal(read, payload) {
		t.Fatalf("runtime payload differs: %q err=%v", read, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}

	renewed, err := client.RenewToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyToken(fixture.tokenKey, renewed, fixture.now)
	if err != nil || claims.Generation != 2 || claims.ReceiverID != fixture.descriptor.ReceiverID ||
		claims.RouteID != fixture.descriptor.RouteID || claims.Limits != routeLimits {
		t.Fatalf("renewed claims changed: %+v err=%v", claims, err)
	}
}

func TestTokenTamperAndAuthenticatedRenewalBinding(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	key := bytes.Repeat([]byte{0x42}, tokenKeySize)
	receiverID, routeID := mustID(t), mustRouteID(t)
	claims := TokenClaims{
		ReceiverID: receiverID, RouteID: routeID, AdmissionRootSHA256: sha256.Sum256([]byte("ca")),
		Limits:     RouteLimits{PendingPairings: 1, PendingCarriers: 1, ActiveCarriers: 1, PairingBytes: 1024, SessionLifetime: time.Minute},
		Generation: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
	}
	token, err := IssueToken(key, claims, now)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), token...)
	tampered[20] ^= 1
	if _, err := VerifyToken(key, tampered, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered token error = %v", err)
	}
	wrong := AuthenticatedPeer{
		ReceiverID: receiverID, RouteID: routeID, AdmissionRootSHA256: claims.AdmissionRootSHA256,
		Role: RoleReceiver, PeerID: mustID(t),
	}
	if _, err := RenewToken(key, token, wrong, now, time.Hour); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong receiver renewed token: %v", err)
	}
	peer := wrong
	peer.Role, peer.PeerID = RoleClient, mustID(t)
	renewed, err := RenewToken(key, token, peer, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyToken(key, renewed, now)
	if err != nil || got.Generation != claims.Generation+1 || !sameRouteClaims(got, claims) {
		t.Fatalf("valid renewal changed route: %+v err=%v", got, err)
	}
}

func TestExpiredTokenAllowsOnlyOpaquePairingGrace(t *testing.T) {
	fixture := newRelayFixture(t)
	defer fixture.relay.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, digest, err := parseAdmissionCA(fixture.descriptor.AdmissionCAPEM, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	claims := TokenClaims{
		ReceiverID: fixture.descriptor.ReceiverID, RouteID: fixture.descriptor.RouteID,
		AdmissionRootSHA256: digest,
		Limits:              RouteLimits{PendingPairings: 1, PendingCarriers: 1, ActiveCarriers: 1, PairingBytes: 4096, SessionLifetime: time.Minute},
		Generation:          1, IssuedUnix: fixture.now.Add(-time.Hour).Unix(), ExpiresUnix: fixture.now.Add(-time.Minute).Unix(),
	}
	expired, err := sealToken(fixture.tokenKey, claims)
	if err != nil {
		t.Fatal(err)
	}
	pairingReceiver, err := NewPairingReceiver("wss://relay.example/connects", inMemoryDialer(fixture.relay))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- pairingReceiver.AcceptPairing(ctx, expired, func(_ context.Context, request []byte) ([]byte, error) {
			return append([]byte("reply:"), request...), nil
		})
	}()
	waitForQueue(t, fixture.relay, true)
	response, err := fixture.public.ExchangePairing(ctx, expired, []byte("renew"))
	if err != nil || string(response) != "reply:renew" {
		t.Fatalf("expired-token pairing response=%q err=%v", response, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	runtimeDone := make(chan error, 1)
	go func() { runtimeDone <- fixture.relay.handleConnection(server) }()
	preface, err := encodeRuntimePreface(runtimePreface{
		token: expired, admissionCA: fixture.descriptor.AdmissionCAPEM,
		role: RoleReceiver, peerID: fixture.descriptor.ReceiverID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWireFrame(client, kindRuntime, preface, maxWirePayload); err != nil {
		t.Fatal(err)
	}
	if err := <-runtimeDone; !errors.Is(err, ErrExpired) {
		t.Fatalf("expired runtime error=%v", err)
	}
	_ = client.Close()
	_ = server.Close()
}

func TestEndpointRejectsUnpinnedRelayAndHTTPAliases(t *testing.T) {
	fixture := newRelayFixture(t)
	defer fixture.relay.Close()
	recorder := httptest.NewRecorder()
	fixture.relay.ServeHTTP(recorder, httptest.NewRequest("GET", "http://relay.example/not-connects", nil))
	if recorder.Code != 400 {
		t.Fatalf("wrong path HTTP status = %d", recorder.Code)
	}

	certificate := issueEndpointLeaf(t, fixture.admissionCA, RoleReceiver, fixture.descriptor.ReceiverID, fixture.descriptor)
	config := EndpointConfig{
		URL: "wss://relay.example/connects", Token: bytes.Repeat([]byte{1}, 16), Descriptor: fixture.descriptor,
		AdmissionCAPEM: fixture.admissionCA.CertPEM, PeerID: fixture.descriptor.ReceiverID, Certificate: certificate,
		RelayCAPEM: fixture.relayInfo.CAPEM, RelayServerName: fixture.relayInfo.ServerName,
		RelayServerSPKI: "", Dial: inMemoryDialer(fixture.relay),
	}
	if _, err := NewReceiver(config); err == nil {
		t.Fatal("receiver accepted a relay pin different from the configured leaf")
	}
}

func newRelayFixture(t *testing.T) relayFixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	receiverID, routeID := mustID(t), mustRouteID(t)
	admissionCA, err := pki.NewCA("OwnTransit test admission CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCA, err := pki.NewCA("OwnTransit test relay CA", now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayLeaf, err := pki.IssueLeaf(relayCA, "relay.example", 1, now, 23*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	relayCertificate, err := tls.X509KeyPair(relayLeaf.CertPEM, relayLeaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := Descriptor{ReceiverID: receiverID, RouteID: routeID, AdmissionCAPEM: admissionCA.CertPEM}
	advertisement := []byte("signed-public-advertisement")
	tokenKey := bytes.Repeat([]byte{0x33}, tokenKeySize)
	relay, err := NewRelay(RelayConfig{
		TokenKey: tokenKey, RelayTLS: TLSMaterial{Certificate: relayCertificate, CAPEM: relayCA.CertPEM, ServerName: "relay.example"},
		VerifyAdvertisement: func(encoded []byte, _ time.Time) (Descriptor, error) {
			if !bytes.Equal(encoded, advertisement) {
				return Descriptor{}, ErrUnauthorized
			}
			return descriptor, nil
		}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	public, err := NewPublicClient("wss://relay.example/connects", inMemoryDialer(relay))
	if err != nil {
		t.Fatal(err)
	}
	info, err := serverInfoFromMaterial(relay.config.RelayTLS)
	if err != nil {
		t.Fatal(err)
	}
	return relayFixture{relay: relay, public: public, descriptor: descriptor, advertisement: advertisement, tokenKey: tokenKey, now: now, relayInfo: info, admissionCA: admissionCA, relayCA: relayCA}
}

func issueEndpointLeaf(t *testing.T, ca pki.Material, role Role, peerID protocol.ID, descriptor Descriptor) tls.Certificate {
	t.Helper()
	name, err := PeerDNSName(role, peerID, descriptor.ReceiverID, descriptor.RouteID)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.IssueLeaf(ca, name, 2, time.Now().UTC().Truncate(time.Second), 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func inMemoryDialer(relay *Relay) DialFunc {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		stop := context.AfterFunc(ctx, func() { _ = client.Close(); _ = server.Close() })
		go func() {
			defer stop()
			defer server.Close()
			_ = relay.handleConnection(server)
		}()
		return client, nil
	}
}

func waitForQueue(t *testing.T, relay *Relay, pairing bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		relay.mu.Lock()
		count := relay.runtimePending
		if pairing {
			count = relay.pairingPending
		}
		relay.mu.Unlock()
		if count > 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("relay waiter was not registered")
}

func mustID(t *testing.T) protocol.ID {
	t.Helper()
	value, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func mustRouteID(t *testing.T) protocol.RouteID {
	t.Helper()
	value, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
