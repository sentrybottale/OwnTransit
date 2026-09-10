package pairrelay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/transport"
)

func registerInventoryFixture(t *testing.T, f relayFixture) Registration {
	t.Helper()
	if err := f.relay.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	registration, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return registration
}

func inventoryEndpointConfig(t *testing.T, f relayFixture, registration Registration, role Role) EndpointConfig {
	t.Helper()
	peer := f.descriptor.ReceiverID
	if role == RoleClient {
		peer = mustID(t)
	}
	return EndpointConfig{URL: "wss://relay.example/connects", Token: registration.Token, Descriptor: f.descriptor,
		AdmissionCAPEM: f.admissionCA.CertPEM, PeerID: peer,
		Certificate: issueEndpointLeaf(t, f.admissionCA, role, peer, f.descriptor),
		RelayCAPEM:  f.relayInfo.CAPEM, RelayServerName: f.relayInfo.ServerName,
		RelayServerSPKI: f.relayInfo.LeafSPKISHA256, Dial: inMemoryDialer(f.relay)}
}

func TestAdmissionRemovalPersistsAndSameSecondReapprovalKeepsOldTokenDenied(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	var saved []AdmissionRecord
	f.relay.config.SaveAdmissions = func(records []AdmissionRecord) error { saved = append([]AdmissionRecord(nil), records...); return nil }
	registration := registerInventoryFixture(t, f)
	oldClaims, err := VerifyToken(f.tokenKey, registration.Token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	_, offer := publicOfferFixture(t, f.advertisement)
	oldConfig := inventoryEndpointConfig(t, f, registration, RoleClient)
	if len(saved) != 1 || saved[0].Status != "approved" {
		t.Fatal("approval was not durably recorded")
	}
	if err := f.relay.RemoveAdmission(f.descriptor.ReceiverID, f.descriptor.RouteID); err != nil {
		t.Fatal(err)
	}
	if saved[0].Status != "removed" {
		t.Fatal("removal was not persisted")
	}
	if err := f.relay.publishOffer(offer, registration.Token); err == nil {
		t.Fatal("old token restored removed admission")
	}
	if _, err := f.relay.fetchAdvertisement(registration.Token); err == nil {
		t.Fatal("removed token fetched advertisement")
	}
	old, _ := NewClient(oldConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := old.RenewToken(ctx); err == nil {
		t.Fatal("removed token renewed")
	}
	// A restart loads policy without needing the one-use advertisement.
	config := f.relay.config
	config.Admissions = append([]AdmissionRecord(nil), saved...)
	restarted, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	oldConfig.Dial = inMemoryDialer(restarted)
	old, _ = NewClient(oldConfig)
	if _, err := old.RenewToken(ctx); err == nil {
		t.Fatal("restart forgot removed token")
	}
	if err := restarted.publishOffer(offer, registration.Token); err == nil {
		t.Fatal("restart allowed token restoration")
	}
	// Explicit reapproval on the original relay is safe in the exact same second.
	reapproved, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(reapproved.Token, registration.Token) {
		t.Fatal("reapproval reused removed token")
	}
	claims, err := VerifyToken(f.tokenKey, reapproved.Token, f.now)
	if err != nil || claims.IssuedUnix <= saved[0].RejectIssuedThrough {
		t.Fatal("fresh token did not clear retained cutoff")
	}
	if err := f.relay.publishOffer(offer, registration.Token); err == nil {
		t.Fatal("reapproval admitted old token")
	}
	oldConfig.Dial = inMemoryDialer(f.relay)
	old, _ = NewClient(oldConfig)
	if _, err := old.RenewToken(ctx); err == nil {
		t.Fatal("reapproval renewed removed old token")
	}
	freshConfig := oldConfig
	freshConfig.Dial, freshConfig.Token = inMemoryDialer(f.relay), reapproved.Token
	fresh, err := NewClient(freshConfig)
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := fresh.RenewToken(ctx)
	if err != nil {
		t.Fatal("fresh same-second token could not renew", err)
	}
	renewedClaims, err := VerifyToken(f.tokenKey, renewed, f.now)
	if err != nil || renewedClaims.IssuedUnix <= saved[0].RejectIssuedThrough {
		t.Fatal("renewal moved behind cutoff")
	}
	if saved[0].RejectIssuedThrough < oldClaims.IssuedUnix {
		t.Fatal("reapproval erased cutoff")
	}
}

func TestAdmissionInventoryLearnsOnlyAuthenticatedLegacyRuntime(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	registration := registerInventoryFixture(t, f)
	clientConfig := inventoryEndpointConfig(t, f, registration, RoleClient)
	config := f.relay.config
	var saved []AdmissionRecord
	config.SaveAdmissions = func(records []AdmissionRecord) error { saved = append([]AdmissionRecord(nil), records...); return nil }
	restarted, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	_, offer := publicOfferFixture(t, f.advertisement)
	if err := restarted.publishOffer(offer, registration.Token); err != nil {
		t.Fatal(err)
	}
	entries, _ := restarted.ListAdmissions()
	if len(entries) != 0 {
		t.Fatal("public token restoration claimed authenticated runtime")
	}
	clientConfig.Dial = inMemoryDialer(restarted)
	client, _ := NewClient(clientConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.RenewToken(ctx); err != nil {
		t.Fatal("legacy retained token was denied", err)
	}
	entries, err = restarted.ListAdmissions()
	if err != nil || len(entries) != 1 || entries[0].Status != "observed" || len(saved) != 1 {
		t.Fatal("authenticated route was not retained", entries, err)
	}
	config.Admissions = saved
	again, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	entries, _ = again.ListAdmissions()
	if len(entries) != 1 || entries[0].Status != "observed" {
		t.Fatal("restart inventory lost known offline route")
	}
}

func TestExplicitApprovalPersistsPreviouslyRestoredToken(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	registration := registerInventoryFixture(t, f)
	config := f.relay.config
	var saved []AdmissionRecord
	config.SaveAdmissions = func(records []AdmissionRecord) error { saved = append([]AdmissionRecord(nil), records...); return nil }
	restarted, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	_, offer := publicOfferFixture(t, f.advertisement)
	if err := restarted.publishOffer(offer, registration.Token); err != nil {
		t.Fatal(err)
	}
	approved, err := restarted.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour)
	if err != nil || !bytes.Equal(approved.Token, registration.Token) {
		t.Fatal("idempotent approval changed token", err)
	}
	if len(saved) != 1 || saved[0].Status != "approved" {
		t.Fatal("idempotent approval was not persisted")
	}
	restarted.mu.Lock()
	restarted.expireAdvertisementsLocked(f.now.Add(48 * time.Hour))
	restarted.mu.Unlock()
	entries, err := restarted.ListAdmissions()
	if err != nil || len(entries) != 1 || entries[0].Status != "approved" {
		t.Fatal("delivery expiry erased durable inventory", err)
	}
}

func TestAdmissionRemovalAbortsSelectedLiveCarrierAndKeepsOtherRoute(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	other := f
	other.descriptor.ReceiverID, other.descriptor.RouteID = mustID(t), mustRouteID(t)
	other.advertisement = []byte("second-signed-public-advertisement")
	f.relay.config.VerifyAdvertisement = func(encoded []byte, _ time.Time) (Descriptor, error) {
		if bytes.Equal(encoded, f.advertisement) {
			return f.descriptor, nil
		}
		if bytes.Equal(encoded, other.advertisement) {
			return other.descriptor, nil
		}
		return Descriptor{}, ErrUnauthorized
	}
	firstRegistration, secondRegistration := registerInventoryFixture(t, f), registerInventoryFixture(t, other)
	server := httptest.NewServer(f.relay)
	defer server.Close()
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		ws, _, err := websocket.Dial(ctx, server.URL+Path, &websocket.DialOptions{Subprotocols: []string{WebSocketSubprotocol}})
		if err != nil {
			return nil, err
		}
		return transport.WrapWebSocket(ctx, ws, maxWirePayload+wireHeaderSize)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connect := func(f relayFixture, registration Registration) (net.Conn, net.Conn) {
		receiverConfig := inventoryEndpointConfig(t, f, registration, RoleReceiver)
		receiverConfig.Dial = dial
		receiver, err := NewReceiver(receiverConfig)
		if err != nil {
			t.Fatal(err)
		}
		clientConfig := inventoryEndpointConfig(t, f, registration, RoleClient)
		clientConfig.Dial = dial
		client, err := NewClient(clientConfig)
		if err != nil {
			t.Fatal(err)
		}
		type accepted struct {
			connection net.Conn
			err        error
		}
		ready := make(chan accepted, 1)
		go func() { c, err := receiver.Accept(ctx); ready <- accepted{c, err} }()
		waitForQueue(t, f.relay, false)
		clientConnection, err := client.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		result := <-ready
		if result.err != nil {
			t.Fatal(result.err)
		}
		t.Cleanup(func() { _ = clientConnection.Close(); _ = result.connection.Close() })
		return clientConnection, result.connection
	}
	firstClient, firstReceiver := connect(f, firstRegistration)
	otherClient, otherReceiver := connect(other, secondRegistration)
	if err := f.relay.RemoveAdmission(f.descriptor.ReceiverID, f.descriptor.RouteID); err != nil {
		t.Fatal(err)
	}
	for _, connection := range []net.Conn{firstClient, firstReceiver} {
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err := connection.Read(make([]byte, 1))
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatal("removed carrier remained open")
		}
	}
	write := make(chan error, 1)
	go func() { _, err := otherClient.Write([]byte("live")); write <- err }()
	_ = otherReceiver.SetReadDeadline(time.Now().Add(time.Second))
	got := make([]byte, 4)
	if _, err := io.ReadFull(otherReceiver, got); err != nil || string(got) != "live" {
		t.Fatal("other route was disrupted", err)
	}
	if err := <-write; err != nil {
		t.Fatal(err)
	}
}

func TestAdmissionRemovalPersistenceFailureAndCapacityFailClosed(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	registration := registerInventoryFixture(t, f)
	writes := 0
	f.relay.config.SaveAdmissions = func([]AdmissionRecord) error { writes++; return errors.New("disk failure") }
	for i := 0; i < 2; i++ {
		if f.relay.RemoveAdmission(f.descriptor.ReceiverID, f.descriptor.RouteID) == nil {
			t.Fatal("failed persistence acknowledged")
		}
	}
	if writes != 2 {
		t.Fatal("retry skipped uncommitted tombstone")
	}
	if _, err := f.relay.fetchAdvertisement(registration.Token); err == nil {
		t.Fatal("failed removal reopened current process")
	}
	if _, err := f.relay.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); err == nil {
		t.Fatal("unpersisted reapproval succeeded")
	}
	entries, _ := f.relay.ListAdmissions()
	if entries[0].Status != "removed" {
		t.Fatal("failed reapproval cleared denial")
	}
	base := f.relay.admissionRecordsLocked()[0]
	records := make([]AdmissionRecord, MaxAdmissionRecords)
	for i := range records {
		records[i] = base
		records[i].ReceiverID, records[i].RouteID = mustID(t).String(), mustRouteID(t).String()
	}
	config := f.relay.config
	config.SaveAdmissions, config.Admissions = nil, records
	full, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	if err := full.publishAdvertisement(f.advertisement); err != nil {
		t.Fatal(err)
	}
	if _, err := full.RegisterReceiver(f.descriptor.ReceiverID, offerRouteLimits(), time.Hour); !errors.Is(err, ErrCapacity) {
		t.Fatal("full removal history was evicted", err)
	}
	entries, _ = full.ListAdmissions()
	if len(entries) != MaxAdmissionRecords {
		t.Fatal("capacity failure changed inventory")
	}
	if _, err := NewRelay(RelayConfig{TokenKey: config.TokenKey, RelayTLS: config.RelayTLS, VerifyAdvertisement: config.VerifyAdvertisement, Admissions: append(records, records[0])}); err == nil {
		t.Fatal("oversize inventory accepted")
	}
}

func TestAdmissionRemovalRacesPendingPromotion(t *testing.T) {
	for i := 0; i < 30; i++ {
		f := newRelayFixture(t)
		registration := registerInventoryFixture(t, f)
		claims, _ := VerifyToken(f.tokenKey, registration.Token, f.now)
		key := routeKey{claims.ReceiverID, claims.RouteID}
		local, remote := net.Pipe()
		leg := &waitingLeg{connection: local, claims: claims, expires: time.Now().Add(time.Hour), done: make(chan error, 1)}
		release, err := f.relay.trackRouteConnection(claims, local)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.relay.enqueueLeg(key, leg, false); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; _ = f.relay.RemoveAdmission(claims.ReceiverID, claims.RouteID) }()
		go func() { defer wg.Done(); <-start; _, _ = f.relay.takeLeg(key, false, claims) }()
		close(start)
		wg.Wait()
		if err := f.relay.acquireActive(key, claims, claims); err == nil {
			t.Fatal("removed pending leg became active")
		}
		_ = remote.SetReadDeadline(time.Now().Add(time.Second))
		_, err = remote.Read(make([]byte, 1))
		var timeout net.Error
		if err == nil || (errors.As(err, &timeout) && timeout.Timeout()) {
			t.Fatal("promotion raced past close")
		}
		if f.relay.runtimePending != 0 {
			t.Fatal("pending quota leaked")
		}
		release()
		_ = remote.Close()
		_ = local.Close()
		_ = f.relay.Close()
	}
}
