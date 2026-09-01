// Package relay implements OwnTransit's untrusted rendezvous and byte-copy
// service. It never terminates the inner client-to-connector TLS session.
package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/sessionguard"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
	"github.com/sentrybottale/owntransit/internal/transport"
)

type routeAuthorization struct {
	dnsName string
	pins    identity.PinSet
}

const (
	clientOpenInterval = time.Second
	clientOpenBurst    = 4
	clientOpenCapacity = time.Duration(clientOpenBurst) * clientOpenInterval
)

// clientAdmission is keyed by the authenticated logical DNS identity. Multiple
// allowed pins for one identity share the same bucket and quotas, so credential
// rotation cannot multiply admission capacity. Entries are created only from
// the configured client allowlist and are never added from network input.
type clientAdmission struct {
	openCredit     time.Duration
	lastOpenRefill time.Time
	pending        int
	active         int
}

type Service struct {
	config           config.Relay
	tlsConfig        *tls.Config
	handshakes       chan struct{}
	bufferPool       sync.Pool
	clients          map[string]identity.PinSet
	routes           map[protocol.RouteID]routeAuthorization
	clientAdmissions map[string]*clientAdmission

	mu              sync.Mutex
	controls        map[protocol.RouteID]*control
	pending         map[pendingKey]*pending
	pendingPerRoute map[protocol.RouteID]int
	activeGlobal    int
	activePerRoute  map[protocol.RouteID]int
}

type control struct {
	route protocol.RouteID
	epoch protocol.EpochID
	pin   identity.SPKIHash
	conn  net.Conn

	writeMu sync.Mutex
}

type pendingKey struct {
	route   protocol.RouteID
	epoch   protocol.EpochID
	session protocol.SessionID
}

type pending struct {
	key          pendingKey
	control      *control
	connectorPin identity.SPKIHash
	clientName   string
	admission    *clientAdmission
	client       *tls.Conn
	deadline     time.Time
	resolved     chan *tls.Conn
}

func New(value config.Relay) (*Service, error) {
	return newService(value, nil)
}

// NewFromMaterial snapshots a relay from one authenticated lifecycle
// generation without reopening credential pathnames.
func NewFromMaterial(value config.Relay, reader tlsprofile.MaterialReader) (*Service, error) {
	if reader == nil {
		return nil, errors.New("relay: runtime material reader is required")
	}
	return newService(value, reader)
}

func newService(value config.Relay, reader tlsprofile.MaterialReader) (*Service, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	clients, err := tlsprofile.ParsePeers(value.Clients)
	if err != nil {
		return nil, err
	}
	routes := make(map[protocol.RouteID]routeAuthorization, len(value.Routes))
	allPeers := make(map[string]identity.PinSet, len(value.Clients)+len(value.Routes))
	for name, pins := range clients {
		allPeers[name] = pins
	}
	for _, routeValue := range value.Routes {
		route, err := protocol.ParseRouteID(routeValue.RouteID)
		if err != nil {
			return nil, err
		}
		pins, err := identity.ParsePinAllowlist(routeValue.SPKIPins)
		if err != nil {
			return nil, err
		}
		if _, duplicate := allPeers[routeValue.DNSName]; duplicate {
			return nil, fmt.Errorf("relay: duplicate outer identity %q", routeValue.DNSName)
		}
		allPeers[routeValue.DNSName] = pins
		routes[route] = routeAuthorization{dnsName: routeValue.DNSName, pins: pins}
	}
	var tlsConfig *tls.Config
	if reader == nil {
		tlsConfig, err = tlsprofile.Server(value.OuterTLS, config.RelayDNSName, config.RelayALPN, allPeers)
	} else {
		tlsConfig, err = tlsprofile.ServerFromMaterial(value.OuterTLS, config.RelayDNSName, config.RelayALPN, allPeers, reader)
	}
	if err != nil {
		return nil, err
	}
	service := &Service{
		config:           value,
		tlsConfig:        tlsConfig,
		handshakes:       make(chan struct{}, value.Limits.OuterHandshakes),
		clients:          clients,
		routes:           routes,
		clientAdmissions: newClientAdmissions(clients, time.Now()),
		controls:         make(map[protocol.RouteID]*control),
		pending:          make(map[pendingKey]*pending),
		pendingPerRoute:  make(map[protocol.RouteID]int),
		activePerRoute:   make(map[protocol.RouteID]int),
	}
	service.bufferPool.New = func() any {
		buffer := make([]byte, 32<<10)
		return &buffer
	}
	return service, nil
}

func newClientAdmissions(clients map[string]identity.PinSet, now time.Time) map[string]*clientAdmission {
	admissions := make(map[string]*clientAdmission, len(clients))
	for name := range clients {
		admissions[name] = &clientAdmission{
			openCredit:     clientOpenCapacity,
			lastOpenRefill: now,
		}
	}
	return admissions
}

// allowOpen implements a one-token-per-second bucket with a burst of four.
// Duration credit preserves fractional refill time without floating point. The
// caller holds Service.mu.
func (admission *clientAdmission) allowOpen(now time.Time) bool {
	if elapsed := now.Sub(admission.lastOpenRefill); elapsed > 0 {
		missing := clientOpenCapacity - admission.openCredit
		if missing <= 0 || elapsed >= missing {
			admission.openCredit = clientOpenCapacity
		} else {
			admission.openCredit += elapsed
		}
		admission.lastOpenRefill = now
	}
	if admission.openCredit < clientOpenInterval {
		return false
	}
	admission.openCredit -= clientOpenInterval
	return true
}

// consumeClientCarrier charges a carrier for an already authenticated client
// DNS identity. It runs before the first frame is read, so malformed, stalled,
// wrong-frame, and quota-rejected client carriers cannot bypass the OPEN rate.
// Tokens are never refunded. The fixed map is never populated from this name.
func (service *Service) consumeClientCarrier(clientName string, now time.Time) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	admission := service.clientAdmissions[clientName]
	return admission != nil && admission.allowOpen(now)
}

// Handle owns carrier until it either closes it or transfers a verified data
// join to the matching client handler.
func (service *Service) Handle(ctx context.Context, carrier net.Conn) {
	if carrier == nil {
		return
	}
	owned := true
	defer func() {
		if owned {
			_ = transport.Abort(carrier)
		}
	}()
	handshakeHeld := false
	releaseHandshake := func() {
		if handshakeHeld {
			<-service.handshakes
			handshakeHeld = false
		}
	}
	select {
	case service.handshakes <- struct{}{}:
		handshakeHeld = true
		defer releaseHandshake()
	default:
		return
	}

	outer := tls.Server(carrier, service.tlsConfig)
	deadline := time.Now().Add(service.config.Limits.Handshake.Value())
	if err := outer.SetDeadline(deadline); err != nil {
		return
	}
	handshakeCtx, cancel := context.WithDeadline(ctx, deadline)
	err := outer.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil || outer.SetDeadline(time.Time{}) != nil {
		return
	}
	dnsName, pin, err := tlsprofile.PeerIdentity(outer.ConnectionState())
	if err != nil {
		return
	}
	clientAuthorized := service.authorizedClient(dnsName, pin)
	if clientAuthorized && !service.consumeClientCarrier(dnsName, time.Now()) {
		return
	}

	if err := outer.SetReadDeadline(time.Now().Add(service.config.Limits.Preface.Value())); err != nil {
		return
	}
	frame, err := protocol.ReadFrame(outer)
	if err != nil || outer.SetReadDeadline(time.Time{}) != nil {
		return
	}
	// The handshake slot covers TLS and the bounded first-frame admission so an
	// authenticated peer cannot create unbounded preface waiters. Long-lived
	// control, pending, and paired connections use their own hard limits.
	releaseHandshake()

	switch value := frame.(type) {
	case protocol.ControlRegister:
		route, ok := service.authorizedConnector(dnsName, pin)
		if !ok || route != value.Route {
			return
		}
		service.serveControl(ctx, outer, route, pin)
	case protocol.DataJoin:
		route, ok := service.authorizedConnector(dnsName, pin)
		if !ok || route != value.Route {
			return
		}
		if service.joinData(outer, value, pin) {
			owned = false
		}
	case protocol.ClientOpen:
		if !clientAuthorized {
			return
		}
		service.serveClient(ctx, outer, dnsName, value.Route)
	default:
		return
	}
}

func (service *Service) authorizedClient(name string, pin identity.SPKIHash) bool {
	pins, ok := service.clients[name]
	return ok && pins.Contains(pin)
}

func (service *Service) authorizedConnector(name string, pin identity.SPKIHash) (protocol.RouteID, bool) {
	for route, authorization := range service.routes {
		if authorization.dnsName == name && authorization.pins.Contains(pin) {
			return route, true
		}
	}
	return protocol.RouteID{}, false
}

func (service *Service) serveControl(ctx context.Context, conn *tls.Conn, route protocol.RouteID, pin identity.SPKIHash) {
	epoch, err := protocol.NewEpochID()
	if err != nil {
		return
	}
	current := &control{route: route, epoch: epoch, pin: pin, conn: conn}
	// REGISTERED must be the first frame on a new control connection. Publishing
	// the control before this write lets a concurrent client enqueue OPEN first,
	// causing the connector to reject an otherwise valid registration.
	old, clientsToClose, err := service.registerControl(current)
	if err != nil {
		return
	}
	if old != nil {
		abortConnection(old.conn)
	}
	for _, client := range clientsToClose {
		abortConnection(client)
	}
	defer service.removeControl(current)

	for {
		if err := conn.SetReadDeadline(time.Now().Add(90 * time.Second)); err != nil {
			return
		}
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		switch value := frame.(type) {
		case protocol.Ping:
			if err := service.writeControl(current, protocol.Pong{}); err != nil {
				return
			}
		case protocol.Pong:
			// A PONG is valid but carries no state.
		case protocol.Cancel:
			if value.Epoch != current.epoch {
				return
			}
			if client := service.cancelPendingKey(pendingKey{route: route, epoch: value.Epoch, session: value.Session}); client != nil {
				abortConnection(client)
			}
		default:
			return
		}
	}
}

func (service *Service) registerControl(current *control) (*control, []*tls.Conn, error) {
	if err := service.writeControl(current, protocol.Registered{Epoch: current.epoch}); err != nil {
		return nil, nil, err
	}
	old, clients := service.installControl(current)
	return old, clients, nil
}

func (service *Service) installControl(current *control) (*control, []*tls.Conn) {
	service.mu.Lock()
	defer service.mu.Unlock()
	old := service.controls[current.route]
	service.controls[current.route] = current
	var clients []*tls.Conn
	if old != nil {
		for _, item := range service.pending {
			if item.control == old && item.key.route == current.route && item.key.epoch == old.epoch {
				service.resolvePendingLocked(item, nil)
				clients = append(clients, item.client)
			}
		}
	}
	return old, clients
}

func (service *Service) removeControl(current *control) {
	service.mu.Lock()
	if service.controls[current.route] != current {
		service.mu.Unlock()
		return
	}
	delete(service.controls, current.route)
	var clients []*tls.Conn
	for _, item := range service.pending {
		if item.control == current && item.key.route == current.route && item.key.epoch == current.epoch {
			service.resolvePendingLocked(item, nil)
			clients = append(clients, item.client)
		}
	}
	service.mu.Unlock()
	for _, client := range clients {
		abortConnection(client)
	}
}

func (service *Service) writeControl(control *control, frame protocol.Frame) error {
	control.writeMu.Lock()
	defer control.writeMu.Unlock()
	deadline := time.Now().Add(service.config.Limits.Preface.Value())
	if err := control.conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	err := protocol.WriteFrame(control.conn, frame)
	clearErr := control.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

// serveClient is reached only after Handle has consumed this logical client's
// carrier-admission token.
func (service *Service) serveClient(ctx context.Context, client *tls.Conn, clientName string, route protocol.RouteID) {
	sessionID, err := protocol.NewSessionID()
	if err != nil {
		return
	}
	control, item, ok := service.beginPending(clientName, route, sessionID, client, time.Now())
	if !ok {
		return
	}

	if err := service.writeControl(control, protocol.Open{Epoch: control.epoch, Session: sessionID}); err != nil {
		if connection := service.cancelPendingItem(item); connection != nil {
			abortConnection(connection)
			return
		}
		// A join or external cancellation won the exact state transition.
		service.discardResolution(item)
		return
	}

	timer := time.NewTimer(time.Until(item.deadline))
	defer timer.Stop()
	var connector *tls.Conn
	select {
	case connector = <-item.resolved:
	case <-timer.C:
		if connection := service.cancelPendingItem(item); connection != nil {
			_ = service.writeControl(control, protocol.Cancel{Epoch: item.key.epoch, Session: item.key.session})
			return
		}
		// A join or external cancellation won as the timer fired.
		connector = <-item.resolved
	case <-ctx.Done():
		if connection := service.cancelPendingItem(item); connection != nil {
			abortConnection(connection)
			return
		}
		// If a join won, this handler owns and must close it and release its
		// active slot. A nil resolution means another cancellation won.
		service.discardResolution(item)
		return
	}
	if connector == nil {
		return
	}
	defer abortConnection(connector)
	defer service.finishActive(item)
	service.copyPair(ctx, client, connector)
}

func (service *Service) beginPending(clientName string, route protocol.RouteID, sessionID protocol.SessionID, client *tls.Conn, now time.Time) (*control, *pending, bool) {
	service.mu.Lock()
	defer service.mu.Unlock()
	admission := service.clientAdmissions[clientName]
	if admission == nil {
		return nil, nil, false
	}
	control := service.controls[route]
	if control == nil || len(service.pending) >= service.config.Limits.PendingGlobal ||
		service.pendingPerRoute[route] >= service.config.Limits.PendingPerRoute ||
		admission.pending >= service.config.Limits.PendingPerClientValue() {
		return nil, nil, false
	}
	key := pendingKey{route: route, epoch: control.epoch, session: sessionID}
	if _, duplicate := service.pending[key]; duplicate {
		return nil, nil, false
	}
	item := &pending{
		key:          key,
		control:      control,
		connectorPin: control.pin,
		clientName:   clientName,
		admission:    admission,
		client:       client,
		deadline:     now.Add(service.config.Limits.Join.Value()),
		resolved:     make(chan *tls.Conn, 1),
	}
	service.pending[key] = item
	service.pendingPerRoute[route]++
	admission.pending++
	return control, item, true
}

func (service *Service) cancelPendingKey(key pendingKey) *tls.Conn {
	service.mu.Lock()
	defer service.mu.Unlock()
	item, ok := service.pending[key]
	if !ok {
		return nil
	}
	service.resolvePendingLocked(item, nil)
	return item.client
}

// cancelPendingItem is used by timers and local failure paths. Pointer
// identity prevents a stale timer from deleting a later object with the same
// (cryptographically improbable but still guarded) key.
func (service *Service) cancelPendingItem(item *pending) *tls.Conn {
	service.mu.Lock()
	defer service.mu.Unlock()
	current, ok := service.pending[item.key]
	if !ok || current != item {
		return nil
	}
	service.resolvePendingLocked(item, nil)
	return item.client
}

func (service *Service) resolvePendingLocked(item *pending, connector *tls.Conn) {
	delete(service.pending, item.key)
	service.pendingPerRoute[item.key.route]--
	if service.pendingPerRoute[item.key.route] == 0 {
		delete(service.pendingPerRoute, item.key.route)
	}
	item.admission.pending--
	item.resolved <- connector
}

func (service *Service) discardResolution(item *pending) {
	connector := <-item.resolved
	if connector == nil {
		return
	}
	abortConnection(connector)
	service.finishActive(item)
}

func (service *Service) joinData(conn *tls.Conn, frame protocol.DataJoin, pin identity.SPKIHash) bool {
	key := pendingKey{route: frame.Route, epoch: frame.Epoch, session: frame.Session}
	service.mu.Lock()
	item, ok := service.pending[key]
	current := service.controls[frame.Route]
	var admission *clientAdmission
	if ok {
		admission = item.admission
	}
	if !ok || current == nil || current != item.control || current.epoch != frame.Epoch || current.pin != pin ||
		item.connectorPin != pin || time.Now().After(item.deadline) ||
		service.activeGlobal >= service.config.Limits.ActiveGlobal ||
		service.activePerRoute[frame.Route] >= service.config.Limits.ActivePerRoute || admission == nil ||
		admission.active >= service.config.Limits.ActivePerClientValue() {
		service.mu.Unlock()
		return false
	}
	service.activeGlobal++
	service.activePerRoute[frame.Route]++
	admission.active++
	service.resolvePendingLocked(item, conn)
	service.mu.Unlock()
	return true
}

func (service *Service) finishActive(item *pending) {
	service.mu.Lock()
	service.activeGlobal--
	service.activePerRoute[item.key.route]--
	if service.activePerRoute[item.key.route] == 0 {
		delete(service.activePerRoute, item.key.route)
	}
	item.admission.active--
	service.mu.Unlock()
}

func (service *Service) copyPair(ctx context.Context, left, right net.Conn) {
	guard, err := sessionguard.New(
		left,
		right,
		service.config.Limits.SessionIdleValue(),
		service.config.Limits.SessionLifetimeValue(),
	)
	if err != nil || guard.Arm() != nil {
		abortConnection(left)
		abortConnection(right)
		return
	}
	result := make(chan error, 2)
	copyOne := func(destination, source net.Conn) {
		buffer := service.bufferPool.Get().(*[]byte)
		_, err := io.CopyBuffer(destination, guard.Reader(source), *buffer)
		service.bufferPool.Put(buffer)
		result <- err
	}
	go copyOne(left, right)
	go copyOne(right, left)
	select {
	case <-result:
	case <-ctx.Done():
	}
	deadline := time.Now().Add(service.config.Limits.Drain.Value())
	_ = left.SetDeadline(deadline)
	_ = right.SetDeadline(deadline)
	select {
	case <-result:
	case <-time.After(service.config.Limits.Drain.Value()):
	}
	abortConnection(left)
	abortConnection(right)
}

// abortConnection bypasses TLS close_notify and the WebSocket close handshake
// for relay-owned teardown. Admission failure, control replacement, pending
// cancellation, and post-drain cleanup have no remaining delivery requirement;
// graceful peer-controlled closure would only let a peer retain relay FDs.
func abortConnection(connection net.Conn) {
	if connection == nil {
		return
	}
	if tlsConnection, ok := connection.(*tls.Conn); ok {
		_ = transport.Abort(tlsConnection.NetConn())
		return
	}
	_ = transport.Abort(connection)
}

var errClosed = errors.New("relay: closed")
