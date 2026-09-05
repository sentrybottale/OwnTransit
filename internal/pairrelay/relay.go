package pairrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

type routeKey struct {
	receiver protocol.ID
	route    protocol.RouteID
}

type advertisementRecord struct {
	encoded       []byte
	admissionHash [sha256.Size]byte
	expires       time.Time
}

type registrationRecord struct {
	token               []byte
	advertisementSHA256 [sha256.Size]byte
	expires             time.Time
}

type waitingLeg struct {
	connection net.Conn
	claims     TokenClaims
	peer       AuthenticatedPeer
	expires    time.Time
	done       chan error
	claimed    bool
}

// Relay is intentionally memory-only. The caller supplies its persistent token
// MAC key and relay TLS identity; advertisements and waiting connections vanish
// on Close or process restart.
type Relay struct {
	config      RelayConfig
	limits      Limits
	now         func() time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	connections chan struct{}

	mu              sync.Mutex
	closed          bool
	advertisements  map[routeKey]advertisementRecord
	registrations   map[routeKey]registrationRecord
	pairing         map[routeKey][]*waitingLeg
	runtime         map[routeKey][]*waitingLeg
	pairingPending  int
	runtimePending  int
	active          int
	pairingPerRoute map[routeKey]int
	runtimePerRoute map[routeKey]int
	activePerRoute  map[routeKey]int
}

func NewRelay(config RelayConfig) (*Relay, error) {
	if len(config.TokenKey) != tokenKeySize || config.VerifyAdvertisement == nil {
		return nil, ErrProtocol
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	instant := now().UTC()
	if instant.IsZero() || validateTLSMaterial(config.RelayTLS, instant) != nil {
		return nil, ErrProtocol
	}
	limits, err := normalizeLimits(config.Limits)
	if err != nil {
		return nil, err
	}
	config.TokenKey = append([]byte(nil), config.TokenKey...)
	config.RelayTLS.CAPEM = append([]byte(nil), config.RelayTLS.CAPEM...)
	config.RelayTLS.Certificate.Certificate = cloneByteSlices(config.RelayTLS.Certificate.Certificate)
	root, cancel := context.WithCancel(context.Background())
	return &Relay{
		config: config, limits: limits, now: now, ctx: root, cancel: cancel,
		connections:    make(chan struct{}, limits.Connections),
		advertisements: make(map[routeKey]advertisementRecord),
		registrations:  make(map[routeKey]registrationRecord),
		pairing:        make(map[routeKey][]*waitingLeg), runtime: make(map[routeKey][]*waitingLeg),
		pairingPerRoute: make(map[routeKey]int), runtimePerRoute: make(map[routeKey]int),
		activePerRoute: make(map[routeKey]int),
	}, nil
}

func normalizeLimits(value Limits) (Limits, error) {
	defaults := defaultLimits()
	values := []*int{
		&value.Connections, &value.Advertisements, &value.PendingPairings, &value.PendingCarriers,
		&value.ActiveCarriers, &value.PerRoutePending, &value.PerRouteActive,
		&value.AdvertisementBytes, &value.PairingBytes,
	}
	defaultValues := []int{
		defaults.Connections, defaults.Advertisements, defaults.PendingPairings, defaults.PendingCarriers,
		defaults.ActiveCarriers, defaults.PerRoutePending, defaults.PerRouteActive,
		defaults.AdvertisementBytes, defaults.PairingBytes,
	}
	maxima := []int{4096, 4096, 1024, 1024, 1024, 64, 64, MaxAdvertisementBytes, MaxPairingBytes}
	for index, item := range values {
		if *item == 0 {
			*item = defaultValues[index]
		}
		if *item <= 0 || *item > maxima[index] {
			return Limits{}, ErrProtocol
		}
	}
	durations := []*time.Duration{&value.AdvertisementTTL, &value.PairingTimeout, &value.HandshakeTimeout, &value.SessionLifetime}
	defaultDurations := []time.Duration{defaults.AdvertisementTTL, defaults.PairingTimeout, defaults.HandshakeTimeout, defaults.SessionLifetime}
	maxDurations := []time.Duration{7 * 24 * time.Hour, time.Minute, time.Minute, MaxTokenValidity}
	for index, item := range durations {
		if *item == 0 {
			*item = defaultDurations[index]
		}
		if *item <= 0 || *item > maxDurations[index] {
			return Limits{}, ErrProtocol
		}
	}
	return value, nil
}

func cloneByteSlices(values [][]byte) [][]byte {
	result := make([][]byte, len(values))
	for index := range values {
		result[index] = append([]byte(nil), values[index]...)
	}
	return result
}

// Close discards every advertisement and waiting connection. No relay restart
// is an endpoint authorization event.
func (relay *Relay) Close() error {
	if relay == nil {
		return nil
	}
	relay.mu.Lock()
	if relay.closed {
		relay.mu.Unlock()
		return ErrAlreadyClosed
	}
	relay.closed = true
	for _, queues := range []map[routeKey][]*waitingLeg{relay.pairing, relay.runtime} {
		for _, queue := range queues {
			for _, leg := range queue {
				_ = leg.connection.Close()
				select {
				case leg.done <- ErrAlreadyClosed:
				default:
				}
			}
		}
	}
	relay.advertisements = make(map[routeKey]advertisementRecord)
	relay.registrations = make(map[routeKey]registrationRecord)
	relay.pairing = make(map[routeKey][]*waitingLeg)
	relay.runtime = make(map[routeKey][]*waitingLeg)
	relay.mu.Unlock()
	relay.cancel()
	return nil
}

// ServeHTTP accepts only the exact existing path and exact v2 subprotocol. It
// emits no diagnostic body after upgrade and never logs protocol or token data.
func (relay *Relay) ServeHTTP(output http.ResponseWriter, request *http.Request) {
	if relay == nil || output == nil || request == nil || request.Method != http.MethodGet ||
		request.URL == nil || request.URL.Path != Path || request.URL.RawPath != "" || request.URL.RawQuery != "" ||
		request.Host == "" || request.ProtoMajor != 1 || !request.ProtoAtLeast(1, 1) ||
		headerPresent(request.Header, "Origin") || headerPresent(request.Header, "Sec-WebSocket-Extensions") ||
		!exactSubprotocol(request.Header) {
		http.Error(output, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	select {
	case relay.connections <- struct{}{}:
		defer func() { <-relay.connections }()
	default:
		http.Error(output, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	ws, err := websocket.Accept(output, request, &websocket.AcceptOptions{
		Subprotocols: []string{WebSocketSubprotocol}, CompressionMode: websocket.CompressionDisabled,
		OriginPatterns: nil, InsecureSkipVerify: false,
	})
	if err != nil {
		return
	}
	if ws.Subprotocol() != WebSocketSubprotocol {
		_ = ws.CloseNow()
		return
	}
	ws.SetReadLimit(maxWirePayload + wireHeaderSize)
	connection := websocket.NetConn(relay.ctx, ws, websocket.MessageBinary)
	defer connection.Close()
	if err := relay.handleConnection(connection); err != nil {
		_ = writeWireFrame(connection, kindFailure, nil, 0)
	}
}

func headerPresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

func exactSubprotocol(header http.Header) bool {
	var values []string
	for key, next := range header {
		if strings.EqualFold(key, "Sec-WebSocket-Protocol") {
			values = append(values, next...)
		}
	}
	return len(values) == 1 && values[0] == WebSocketSubprotocol
}

func (relay *Relay) handleConnection(connection net.Conn) error {
	if relay == nil || connection == nil {
		return ErrProtocol
	}
	frame, err := readWireFrame(connection, maxWirePayload)
	if err != nil {
		return ErrProtocol
	}
	switch frame.kind {
	case kindPublishAdvertisement:
		if err := relay.publishAdvertisement(frame.data); err != nil {
			return err
		}
		return writeWireFrame(connection, kindOK, nil, 0)
	case kindFetchAdvertisement:
		advertisement, err := relay.fetchAdvertisement(frame.data)
		if err != nil {
			return err
		}
		return writeWireFrame(connection, kindAdvertisement, advertisement, relay.limits.AdvertisementBytes)
	case kindPairReceiver:
		claims, err := openToken(relay.config.TokenKey, frame.data, relay.now(), true)
		if err != nil {
			return err
		}
		return relay.waitPairingReceiver(connection, claims)
	case kindPairClient:
		token, request, err := decodeTokenAndBlob(frame.data, relay.limits.PairingBytes)
		if err != nil {
			return err
		}
		claims, err := openToken(relay.config.TokenKey, token, relay.now(), true)
		if err != nil || len(request) > claims.Limits.PairingBytes {
			return ErrUnauthorized
		}
		return relay.exchangePairing(connection, claims, request)
	case kindRuntime, kindRenewToken:
		preface, err := decodeRuntimePreface(frame.data)
		if err != nil {
			return err
		}
		return relay.handleAuthenticated(connection, preface, frame.kind == kindRenewToken)
	case kindFetchRegistration:
		token, err := relay.fetchRegistration(frame.data)
		if err != nil {
			return err
		}
		return writeWireFrame(connection, kindRenewedToken, token, MaxTokenBytes)
	case kindFetchServerInfo:
		if len(frame.data) != 0 {
			return ErrProtocol
		}
		info, err := serverInfoFromMaterial(relay.config.RelayTLS)
		if err != nil {
			return err
		}
		encoded, err := encodeServerInfo(info)
		if err != nil {
			return err
		}
		return writeWireFrame(connection, kindServerInfo, encoded, maxServerInfoBytes)
	default:
		return ErrProtocol
	}
}

// RegisterReceiver is the root/local initial-token operation. It resolves one
// already-verified in-memory advertisement by public receiver ID, creates a
// stateless token, and records only a bounded delivery copy. ServeHTTP exposes
// no corresponding mint operation.
func (relay *Relay) RegisterReceiver(
	receiverID protocol.ID,
	routeLimits RouteLimits,
	validity time.Duration,
) (Registration, error) {
	if relay == nil || zeroID(receiverID) || validateRouteLimits(routeLimits) != nil || validity <= 0 || validity > MaxTokenValidity {
		return Registration{}, ErrProtocol
	}
	now := relay.now().UTC().Truncate(time.Second)
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return Registration{}, ErrAlreadyClosed
	}
	relay.expireAdvertisementsLocked(now)
	var selectedKey routeKey
	var selected advertisementRecord
	matches := 0
	for key, advertisement := range relay.advertisements {
		if key.receiver == receiverID {
			selectedKey, selected = key, advertisement
			matches++
		}
	}
	if matches != 1 {
		return Registration{}, ErrUnavailable
	}
	descriptor, err := relay.config.VerifyAdvertisement(append([]byte(nil), selected.encoded...), now)
	if err != nil || descriptor.ReceiverID != selectedKey.receiver || descriptor.RouteID != selectedKey.route {
		return Registration{}, ErrUnavailable
	}
	_, _, currentAdmissionHash, err := parseAdmissionCA(descriptor.AdmissionCAPEM, now)
	if err != nil || currentAdmissionHash != selected.admissionHash {
		return Registration{}, ErrUnavailable
	}
	claims := TokenClaims{
		ReceiverID: receiverID, RouteID: selectedKey.route, AdmissionRootSHA256: selected.admissionHash,
		Limits: routeLimits, Generation: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(validity).Unix(),
	}
	token, err := IssueToken(relay.config.TokenKey, claims, now)
	if err != nil {
		return Registration{}, err
	}
	relay.registrations[selectedKey] = registrationRecord{
		token: append([]byte(nil), token...), advertisementSHA256: sha256.Sum256(selected.encoded),
		expires: now.Add(validity),
	}
	info, err := serverInfoFromMaterial(relay.config.RelayTLS)
	if err != nil {
		return Registration{}, err
	}
	return Registration{
		ReceiverID: receiverID, RouteID: selectedKey.route, Token: append([]byte(nil), token...), ServerInfo: info,
	}, nil
}

func (relay *Relay) fetchRegistration(advertisement []byte) ([]byte, error) {
	if len(advertisement) == 0 || len(advertisement) > relay.limits.AdvertisementBytes {
		return nil, ErrProtocol
	}
	descriptor, err := relay.config.VerifyAdvertisement(append([]byte(nil), advertisement...), relay.now())
	if err != nil {
		return nil, ErrUnauthorized
	}
	_, _, admissionHash, err := parseAdmissionCA(descriptor.AdmissionCAPEM, relay.now())
	if err != nil {
		return nil, ErrUnauthorized
	}
	key := routeKey{receiver: descriptor.ReceiverID, route: descriptor.RouteID}
	now := relay.now()
	relay.mu.Lock()
	defer relay.mu.Unlock()
	record, ok := relay.registrations[key]
	if !ok || !now.Before(record.expires) || record.advertisementSHA256 != sha256.Sum256(advertisement) {
		return nil, ErrUnavailable
	}
	claims, err := VerifyToken(relay.config.TokenKey, record.token, now)
	if err != nil || !bytes.Equal(admissionHash[:], claims.AdmissionRootSHA256[:]) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), record.token...), nil
}

func (relay *Relay) publishAdvertisement(encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > relay.limits.AdvertisementBytes {
		return ErrProtocol
	}
	descriptor, err := relay.config.VerifyAdvertisement(append([]byte(nil), encoded...), relay.now())
	if err != nil {
		return ErrUnauthorized
	}
	_, _, digest, err := parseAdmissionCA(descriptor.AdmissionCAPEM, relay.now())
	if err != nil || zeroID(descriptor.ReceiverID) || zeroRoute(descriptor.RouteID) {
		return ErrUnauthorized
	}
	key := routeKey{receiver: descriptor.ReceiverID, route: descriptor.RouteID}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return ErrAlreadyClosed
	}
	relay.expireAdvertisementsLocked(relay.now())
	if _, exists := relay.advertisements[key]; !exists && len(relay.advertisements) >= relay.limits.Advertisements {
		return ErrCapacity
	}
	relay.advertisements[key] = advertisementRecord{
		encoded: append([]byte(nil), encoded...), admissionHash: digest,
		expires: relay.now().Add(relay.limits.AdvertisementTTL),
	}
	return nil
}

func (relay *Relay) fetchAdvertisement(token []byte) ([]byte, error) {
	claims, err := VerifyToken(relay.config.TokenKey, token, relay.now())
	if err != nil {
		return nil, err
	}
	key := routeKey{receiver: claims.ReceiverID, route: claims.RouteID}
	relay.mu.Lock()
	defer relay.mu.Unlock()
	relay.expireAdvertisementsLocked(relay.now())
	record, ok := relay.advertisements[key]
	if !ok || !bytes.Equal(record.admissionHash[:], claims.AdmissionRootSHA256[:]) {
		return nil, ErrUnavailable
	}
	return append([]byte(nil), record.encoded...), nil
}

func (relay *Relay) expireAdvertisementsLocked(now time.Time) {
	for key, record := range relay.advertisements {
		if !now.Before(record.expires) {
			delete(relay.advertisements, key)
		}
	}
}

func (relay *Relay) handleAuthenticated(connection net.Conn, preface runtimePreface, renewal bool) error {
	claims, err := openToken(relay.config.TokenKey, preface.token, relay.now(), renewal)
	if err != nil {
		return err
	}
	_, roots, digest, err := parseAdmissionCA(preface.admissionCA, relay.now())
	if err != nil || !bytes.Equal(digest[:], claims.AdmissionRootSHA256[:]) ||
		(preface.role == RoleReceiver && preface.peerID != claims.ReceiverID) {
		return ErrUnauthorized
	}
	tlsConfig, err := relayTLSConfig(relay.config.RelayTLS, roots, preface.role, preface.peerID, claims.ReceiverID, claims.RouteID)
	if err != nil {
		return ErrUnauthorized
	}
	handshakeCtx, cancel := context.WithTimeout(relay.ctx, relay.limits.HandshakeTimeout)
	defer cancel()
	secured := tls.Server(connection, tlsConfig)
	if err := secured.HandshakeContext(handshakeCtx); err != nil {
		return ErrUnauthorized
	}
	peer := AuthenticatedPeer{
		ReceiverID: claims.ReceiverID, RouteID: claims.RouteID, AdmissionRootSHA256: claims.AdmissionRootSHA256,
		Role: preface.role, PeerID: preface.peerID,
	}
	if renewal {
		validity := time.Duration(claims.ExpiresUnix-claims.IssuedUnix) * time.Second
		renewed, err := RenewToken(relay.config.TokenKey, preface.token, peer, relay.now(), validity)
		if err != nil {
			return err
		}
		return writeWireFrame(secured, kindRenewedToken, renewed, MaxTokenBytes)
	}
	return relay.handleRuntime(secured, claims, peer)
}

func (relay *Relay) waitPairingReceiver(connection net.Conn, claims TokenClaims) error {
	key := routeKey{receiver: claims.ReceiverID, route: claims.RouteID}
	leg := &waitingLeg{connection: connection, claims: claims, expires: relay.pairingExpiry(claims), done: make(chan error, 1)}
	if err := relay.enqueueLeg(key, leg, true); err != nil {
		return err
	}
	return relay.waitLeg(key, leg, true)
}

func (relay *Relay) exchangePairing(client net.Conn, claims TokenClaims, request []byte) error {
	key := routeKey{receiver: claims.ReceiverID, route: claims.RouteID}
	receiver, err := relay.takeLeg(key, true, claims)
	if err != nil {
		return err
	}
	defer relay.finishLeg(receiver, err)
	deadline := relay.pairingExpiry(claims)
	if receiver.expires.Before(deadline) {
		deadline = receiver.expires
	}
	_ = receiver.connection.SetDeadline(deadline)
	_ = client.SetDeadline(deadline)
	if err := writeWireFrame(receiver.connection, kindPairRequest, request, relay.limits.PairingBytes); err != nil {
		return ErrUnavailable
	}
	response, err := readWireFrame(receiver.connection, relay.limits.PairingBytes)
	if err != nil || response.kind != kindPairResponse || len(response.data) == 0 || len(response.data) > claims.Limits.PairingBytes {
		return ErrUnavailable
	}
	return writeWireFrame(client, kindPairResponse, response.data, relay.limits.PairingBytes)
}

func (relay *Relay) handleRuntime(connection net.Conn, claims TokenClaims, peer AuthenticatedPeer) error {
	key := routeKey{receiver: claims.ReceiverID, route: claims.RouteID}
	if peer.Role == RoleReceiver {
		leg := &waitingLeg{connection: connection, claims: claims, peer: peer, expires: relay.pendingExpiry(claims), done: make(chan error, 1)}
		if err := relay.enqueueLeg(key, leg, false); err != nil {
			return err
		}
		return relay.waitLeg(key, leg, false)
	}
	receiver, err := relay.takeLeg(key, false, claims)
	if err != nil {
		return err
	}
	if err := relay.acquireActive(key, claims, receiver.claims); err != nil {
		relay.finishLeg(receiver, err)
		return err
	}
	defer relay.releaseActive(key)
	if err := writeWireFrame(receiver.connection, kindReady, nil, 0); err != nil {
		relay.finishLeg(receiver, ErrUnavailable)
		return ErrUnavailable
	}
	if err := writeWireFrame(connection, kindReady, nil, 0); err != nil {
		relay.finishLeg(receiver, ErrUnavailable)
		return ErrUnavailable
	}
	deadline := relay.sessionExpiry(claims, receiver.claims)
	_ = receiver.connection.SetDeadline(deadline)
	_ = connection.SetDeadline(deadline)
	err = copyOpaque(receiver.connection, connection)
	relay.finishLeg(receiver, err)
	return err
}

func (relay *Relay) pendingExpiry(claims TokenClaims) time.Time {
	deadline := relay.now().Add(relay.limits.PairingTimeout)
	tokenExpiry := time.Unix(claims.ExpiresUnix, 0)
	if tokenExpiry.Before(deadline) {
		deadline = tokenExpiry
	}
	return deadline
}

func (relay *Relay) pairingExpiry(claims TokenClaims) time.Time {
	deadline := relay.now().Add(relay.limits.PairingTimeout)
	graceExpiry := time.Unix(claims.ExpiresUnix, 0).Add(MaxExpiredRenewalGrace)
	if graceExpiry.Before(deadline) {
		deadline = graceExpiry
	}
	return deadline
}

func (relay *Relay) sessionExpiry(first, second TokenClaims) time.Time {
	lifetime := relay.limits.SessionLifetime
	if first.Limits.SessionLifetime < lifetime {
		lifetime = first.Limits.SessionLifetime
	}
	if second.Limits.SessionLifetime < lifetime {
		lifetime = second.Limits.SessionLifetime
	}
	deadline := relay.now().Add(lifetime)
	for _, claims := range []TokenClaims{first, second} {
		expires := time.Unix(claims.ExpiresUnix, 0)
		if expires.Before(deadline) {
			deadline = expires
		}
	}
	return deadline
}

func (relay *Relay) enqueueLeg(key routeKey, leg *waitingLeg, pairing bool) error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.closed {
		return ErrAlreadyClosed
	}
	queue, global, perRoute, routeLimit := relay.runtime, &relay.runtimePending, relay.runtimePerRoute, leg.claims.Limits.PendingCarriers
	globalLimit := relay.limits.PendingCarriers
	if pairing {
		queue, global, perRoute, routeLimit = relay.pairing, &relay.pairingPending, relay.pairingPerRoute, leg.claims.Limits.PendingPairings
		globalLimit = relay.limits.PendingPairings
	}
	limit := minInt(relay.limits.PerRoutePending, routeLimit)
	if *global >= globalLimit || perRoute[key] >= limit {
		return ErrCapacity
	}
	queue[key] = append(queue[key], leg)
	*global++
	perRoute[key]++
	return nil
}

func (relay *Relay) waitLeg(key routeKey, leg *waitingLeg, pairing bool) error {
	timer := time.NewTimer(time.Until(leg.expires))
	defer timer.Stop()
	select {
	case err := <-leg.done:
		return err
	case <-relay.ctx.Done():
		relay.removeLeg(key, leg, pairing)
		return ErrAlreadyClosed
	case <-timer.C:
		relay.removeLeg(key, leg, pairing)
		return ErrUnavailable
	}
}

func (relay *Relay) removeLeg(key routeKey, leg *waitingLeg, pairing bool) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	queue, global, perRoute := relay.runtime, &relay.runtimePending, relay.runtimePerRoute
	if pairing {
		queue, global, perRoute = relay.pairing, &relay.pairingPending, relay.pairingPerRoute
	}
	values := queue[key]
	for index, value := range values {
		if value == leg && !value.claimed {
			queue[key] = append(values[:index], values[index+1:]...)
			*global--
			perRoute[key]--
			if len(queue[key]) == 0 {
				delete(queue, key)
			}
			if perRoute[key] == 0 {
				delete(perRoute, key)
			}
			_ = leg.connection.Close()
			return
		}
	}
}

func (relay *Relay) takeLeg(key routeKey, pairing bool, claims TokenClaims) (*waitingLeg, error) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	queue, global, perRoute := relay.runtime, &relay.runtimePending, relay.runtimePerRoute
	if pairing {
		queue, global, perRoute = relay.pairing, &relay.pairingPending, relay.pairingPerRoute
	}
	now := relay.now()
	values := queue[key]
	for len(values) != 0 {
		leg := values[0]
		values = values[1:]
		*global--
		perRoute[key]--
		if !now.Before(leg.expires) || !sameRouteClaims(leg.claims, claims) {
			_ = leg.connection.Close()
			select {
			case leg.done <- ErrUnavailable:
			default:
			}
			continue
		}
		leg.claimed = true
		if len(values) == 0 {
			delete(queue, key)
		} else {
			queue[key] = values
		}
		if perRoute[key] == 0 {
			delete(perRoute, key)
		}
		return leg, nil
	}
	delete(queue, key)
	delete(perRoute, key)
	return nil, ErrUnavailable
}

func sameRouteClaims(first, second TokenClaims) bool {
	return first.ReceiverID == second.ReceiverID && first.RouteID == second.RouteID &&
		bytes.Equal(first.AdmissionRootSHA256[:], second.AdmissionRootSHA256[:]) && first.Limits == second.Limits
}

func (relay *Relay) finishLeg(leg *waitingLeg, err error) {
	if leg == nil {
		return
	}
	if err == nil {
		err = io.EOF
	}
	select {
	case leg.done <- err:
	default:
	}
}

func (relay *Relay) acquireActive(key routeKey, first, second TokenClaims) error {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	limit := minInt(relay.limits.PerRouteActive, minInt(first.Limits.ActiveCarriers, second.Limits.ActiveCarriers))
	if relay.active >= relay.limits.ActiveCarriers || relay.activePerRoute[key] >= limit {
		return ErrCapacity
	}
	relay.active++
	relay.activePerRoute[key]++
	return nil
}

func (relay *Relay) releaseActive(key routeKey) {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.active > 0 {
		relay.active--
	}
	if relay.activePerRoute[key] > 1 {
		relay.activePerRoute[key]--
	} else {
		delete(relay.activePerRoute, key)
	}
}

func copyOpaque(first, second net.Conn) error {
	result := make(chan error, 2)
	copyOne := func(destination, source net.Conn) { _, err := io.Copy(destination, source); result <- err }
	go copyOne(first, second)
	go copyOne(second, first)
	err := <-result
	_ = first.Close()
	_ = second.Close()
	<-result
	if err == nil || errors.Is(err, net.ErrClosed) {
		return io.EOF
	}
	return err
}

func minInt(first, second int) int {
	if first < second {
		return first
	}
	return second
}
