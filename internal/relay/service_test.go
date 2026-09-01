package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	testClientOne = "client-one.owntransit.invalid"
	testClientTwo = "client-two.owntransit.invalid"
)

func testRoute(value byte) protocol.RouteID {
	var route protocol.RouteID
	route[0] = value
	return route
}

func testEpoch(value byte) protocol.EpochID {
	var epoch protocol.EpochID
	epoch[0] = value
	return epoch
}

func testSession(value uint64) protocol.SessionID {
	var session protocol.SessionID
	binary.BigEndian.PutUint64(session[:8], value)
	return session
}

func testPin(value byte) identity.SPKIHash {
	var pin identity.SPKIHash
	pin[0] = value
	return pin
}

func testService(pendingGlobal, pendingPerRoute, activeGlobal, activePerRoute int) *Service {
	now := time.Now().Add(time.Hour)
	service := &Service{
		config: config.Relay{Limits: config.RelayLimits{
			PendingGlobal:    pendingGlobal,
			PendingPerRoute:  pendingPerRoute,
			PendingPerClient: 1024,
			ActiveGlobal:     activeGlobal,
			ActivePerRoute:   activePerRoute,
			ActivePerClient:  1024,
			Join:             config.Duration(time.Minute),
			Drain:            config.Duration(10 * time.Millisecond),
			Preface:          config.Duration(time.Second),
		}},
		clients: make(map[string]identity.PinSet),
		routes:  make(map[protocol.RouteID]routeAuthorization),
		clientAdmissions: map[string]*clientAdmission{
			testClientOne: {openCredit: 1 << 60, lastOpenRefill: now},
			testClientTwo: {openCredit: 1 << 60, lastOpenRefill: now},
		},
		controls:        make(map[protocol.RouteID]*control),
		pending:         make(map[pendingKey]*pending),
		pendingPerRoute: make(map[protocol.RouteID]int),
		activePerRoute:  make(map[protocol.RouteID]int),
	}
	service.bufferPool.New = func() any {
		buffer := make([]byte, 32<<10)
		return &buffer
	}
	return service
}

func TestControlIsRegisteredBeforeItBecomesOpenEligible(t *testing.T) {
	service := testService(8, 8, 8, 8)
	route := testRoute(1)
	current := &control{route: route, epoch: testEpoch(2), pin: testPin(1)}
	connection := &controlOrderingConn{
		onWrite: func() {
			if service.controls[route] == current {
				t.Error("control was published before REGISTERED was written")
			}
		},
	}
	current.conn = connection

	old, clients, err := service.registerControl(current)
	if err != nil {
		t.Fatal(err)
	}
	if old != nil || len(clients) != 0 {
		t.Fatalf("unexpected replacement state old=%p clients=%d", old, len(clients))
	}
	if service.controls[route] != current {
		t.Fatal("registered control was not published")
	}
	frame, err := protocol.ReadFrame(bytes.NewReader(connection.written))
	if err != nil {
		t.Fatalf("decode first control frame: %v", err)
	}
	registered, ok := frame.(protocol.Registered)
	if !ok || registered.Epoch != current.epoch {
		t.Fatalf("first control frame = %#v, want REGISTERED for current epoch", frame)
	}
}

type controlOrderingConn struct {
	net.Conn
	onWrite func()
	written []byte
}

func (connection *controlOrderingConn) Write(value []byte) (int, error) {
	connection.onWrite()
	connection.written = append(connection.written, value...)
	return len(value), nil
}

func (connection *controlOrderingConn) SetWriteDeadline(time.Time) error { return nil }

func testControl(route protocol.RouteID, epoch protocol.EpochID, pin identity.SPKIHash) *control {
	return &control{route: route, epoch: epoch, pin: pin, conn: new(tls.Conn)}
}

func mustBeginPending(t testing.TB, service *Service, route protocol.RouteID, session protocol.SessionID) *pending {
	return mustBeginPendingFor(t, service, testClientOne, route, session)
}

func mustBeginPendingFor(t testing.TB, service *Service, clientName string, route protocol.RouteID, session protocol.SessionID) *pending {
	t.Helper()
	_, item, ok := service.beginPending(clientName, route, session, new(tls.Conn), time.Now())
	if !ok {
		t.Fatal("beginPending unexpectedly rejected the session")
	}
	return item
}

func assertResolution(t testing.TB, item *pending, want *tls.Conn) {
	t.Helper()
	select {
	case got := <-item.resolved:
		if got != want {
			t.Fatalf("resolution = %p, want %p", got, want)
		}
	default:
		t.Fatal("pending item was removed without a resolution signal")
	}
}

func assertUnresolved(t testing.TB, item *pending) {
	t.Helper()
	select {
	case value := <-item.resolved:
		t.Fatalf("unexpected resolution %p", value)
	default:
	}
}

func assertAccountingConsistent(t testing.TB, service *Service) {
	t.Helper()
	service.mu.Lock()
	defer service.mu.Unlock()

	clientPending := 0
	clientActive := 0
	for name, admission := range service.clientAdmissions {
		if admission.pending < 0 || admission.active < 0 {
			t.Fatalf("client %q has negative pending/active state %d/%d", name, admission.pending, admission.active)
		}
		clientPending += admission.pending
		clientActive += admission.active
	}
	routePending := 0
	for route, count := range service.pendingPerRoute {
		if count <= 0 {
			t.Fatalf("route %x retained invalid pending count %d", route, count)
		}
		routePending += count
	}
	routeActive := 0
	for route, count := range service.activePerRoute {
		if count <= 0 {
			t.Fatalf("route %x retained invalid active count %d", route, count)
		}
		routeActive += count
	}
	if len(service.pending) != clientPending || len(service.pending) != routePending {
		t.Fatalf("pending accounting disagrees: map=%d clients=%d routes=%d", len(service.pending), clientPending, routePending)
	}
	if service.activeGlobal != clientActive || service.activeGlobal != routeActive {
		t.Fatalf("active accounting disagrees: global=%d clients=%d routes=%d", service.activeGlobal, clientActive, routeActive)
	}
	for key, item := range service.pending {
		if item.admission == nil || item.admission != service.clientAdmissions[item.clientName] {
			t.Fatalf("pending %v does not retain its configured client account", key)
		}
	}
}

func TestClientOpenTokenBucketRateAndBurst(t *testing.T) {
	start := time.Unix(1_000, 0)
	admission := &clientAdmission{
		openCredit:     clientOpenCapacity,
		lastOpenRefill: start,
	}
	for attempt := 0; attempt < clientOpenBurst; attempt++ {
		if !admission.allowOpen(start) {
			t.Fatalf("burst attempt %d was rejected", attempt+1)
		}
	}
	if admission.allowOpen(start) {
		t.Fatal("attempt above the burst was accepted")
	}
	if admission.allowOpen(start.Add(999 * time.Millisecond)) {
		t.Fatal("token refilled before one second")
	}
	if !admission.allowOpen(start.Add(1500 * time.Millisecond)) {
		t.Fatal("first one-per-second refill was rejected")
	}
	if admission.allowOpen(start.Add(1999 * time.Millisecond)) {
		t.Fatal("fractional refill admitted too early")
	}
	if !admission.allowOpen(start.Add(2 * time.Second)) {
		t.Fatal("fractional refill credit was discarded")
	}
	if admission.allowOpen(start.Add(2 * time.Second)) {
		t.Fatal("same instant reused one token")
	}

	refilledAt := start.Add(20 * time.Second)
	for attempt := 0; attempt < clientOpenBurst; attempt++ {
		if !admission.allowOpen(refilledAt) {
			t.Fatalf("refilled burst attempt %d was rejected", attempt+1)
		}
	}
	if admission.allowOpen(refilledAt) {
		t.Fatal("idle time accumulated more than the burst")
	}
	if admission.allowOpen(refilledAt.Add(-time.Hour)) {
		t.Fatal("backward clock movement refilled the bucket")
	}
	if !admission.allowOpen(refilledAt.Add(time.Second)) {
		t.Fatal("bucket did not recover after one forward second")
	}
}

func TestConcurrentClientOpenBurstIsHard(t *testing.T) {
	now := time.Unix(1500, 0)
	clients := map[string]identity.PinSet{
		testClientOne: identity.PinSet{testPin(1): struct{}{}},
	}
	service := &Service{clientAdmissions: newClientAdmissions(clients, now)}

	const contenders = 64
	start := make(chan struct{})
	accepted := make(chan struct{}, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if service.consumeClientCarrier(testClientOne, now) {
				accepted <- struct{}{}
			}
		}()
	}
	close(start)
	wait.Wait()
	close(accepted)
	if len(accepted) != clientOpenBurst {
		t.Fatalf("concurrent burst accepted %d carriers, want %d", len(accepted), clientOpenBurst)
	}
	if len(service.clientAdmissions) != 1 {
		t.Fatalf("concurrent burst changed admission map cardinality to %d", len(service.clientAdmissions))
	}
}

func TestClientAdmissionStateIsFixedAndKeyedByDNSIdentity(t *testing.T) {
	start := time.Unix(2_000, 0)
	firstPin := testPin(1)
	rotatedPin := testPin(2)
	clients := map[string]identity.PinSet{
		testClientOne: identity.PinSet{firstPin: struct{}{}, rotatedPin: struct{}{}},
		testClientTwo: identity.PinSet{testPin(3): struct{}{}},
	}
	admissions := newClientAdmissions(clients, start)
	service := &Service{clients: clients, clientAdmissions: admissions}

	if len(admissions) != len(clients) || admissions[testClientOne] == nil || admissions[testClientTwo] == nil {
		t.Fatalf("admission map has %d entries for %d configured identities", len(admissions), len(clients))
	}
	if !service.authorizedClient(testClientOne, firstPin) || !service.authorizedClient(testClientOne, rotatedPin) {
		t.Fatal("allowed pin rotation was not represented by one logical identity")
	}
	rotationPins := []identity.SPKIHash{firstPin, rotatedPin}
	for attempt := 0; attempt < clientOpenBurst; attempt++ {
		if !service.authorizedClient(testClientOne, rotationPins[attempt%len(rotationPins)]) ||
			!service.consumeClientCarrier(testClientOne, start) {
			t.Fatalf("shared logical-identity burst attempt %d was rejected", attempt+1)
		}
	}
	if service.consumeClientCarrier(testClientOne, start) {
		t.Fatal("pin rotation multiplied the logical identity's burst")
	}
	before := len(service.clientAdmissions)
	if service.consumeClientCarrier("unknown.owntransit.invalid", start) {
		t.Fatal("unknown identity received admission state")
	}
	if len(service.clientAdmissions) != before {
		t.Fatal("network-provided identity grew the fixed admission map")
	}
	if !service.consumeClientCarrier(testClientTwo, start) {
		t.Fatal("one exhausted identity starved another identity's bucket")
	}
}

func TestOuterIdentityAuthorizationIsExact(t *testing.T) {
	service := testService(8, 8, 8, 8)
	clientPin := testPin(1)
	connectorPin := testPin(2)
	otherPin := testPin(3)
	route := testRoute(1)
	otherRoute := testRoute(2)
	service.clients["client.owntransit.invalid"] = identity.PinSet{clientPin: struct{}{}}
	service.routes[route] = routeAuthorization{
		dnsName: "connector-one.owntransit.invalid",
		pins:    identity.PinSet{connectorPin: struct{}{}},
	}
	service.routes[otherRoute] = routeAuthorization{
		dnsName: "connector-two.owntransit.invalid",
		pins:    identity.PinSet{otherPin: struct{}{}},
	}

	if !service.authorizedClient("client.owntransit.invalid", clientPin) {
		t.Fatal("exact client identity and pin were rejected")
	}
	if service.authorizedClient("client.owntransit.invalid", connectorPin) ||
		service.authorizedClient("connector-one.owntransit.invalid", clientPin) ||
		service.authorizedClient("Client.owntransit.invalid", clientPin) {
		t.Fatal("client authorization accepted a wrong role, pin, or DNS spelling")
	}

	gotRoute, ok := service.authorizedConnector("connector-one.owntransit.invalid", connectorPin)
	if !ok || gotRoute != route {
		t.Fatalf("connector authorization = %x, %v; want route %x", gotRoute, ok, route)
	}
	for _, attempt := range []struct {
		name string
		pin  identity.SPKIHash
	}{
		{name: "connector-one.owntransit.invalid", pin: otherPin},
		{name: "connector-two.owntransit.invalid", pin: connectorPin},
		{name: "client.owntransit.invalid", pin: connectorPin},
	} {
		if _, ok := service.authorizedConnector(attempt.name, attempt.pin); ok {
			t.Fatalf("authorized connector with mismatched name/pin: %q, %x", attempt.name, attempt.pin)
		}
	}
}

func TestControlReplacementCancelsOnlyOldUnpairedSessions(t *testing.T) {
	service := testService(16, 16, 16, 16)
	route := testRoute(1)
	otherRoute := testRoute(2)
	pin := testPin(1)
	old := testControl(route, testEpoch(1), pin)
	service.controls[route] = old
	oldOne := mustBeginPending(t, service, route, testSession(1))
	oldTwo := mustBeginPending(t, service, route, testSession(2))

	// This impossible-in-normal-operation entry proves replacement matches the
	// exact control object and epoch rather than sweeping all route state.
	foreignControl := testControl(route, testEpoch(9), pin)
	foreign := &pending{
		key:          pendingKey{route: route, epoch: foreignControl.epoch, session: testSession(3)},
		control:      foreignControl,
		connectorPin: pin,
		clientName:   testClientOne,
		admission:    service.clientAdmissions[testClientOne],
		client:       new(tls.Conn),
		deadline:     time.Now().Add(time.Minute),
		resolved:     make(chan *tls.Conn, 1),
	}
	service.pending[foreign.key] = foreign
	service.pendingPerRoute[route]++
	service.clientAdmissions[testClientOne].pending++

	other := testControl(otherRoute, testEpoch(1), testPin(2))
	service.controls[otherRoute] = other
	otherItem := mustBeginPending(t, service, otherRoute, testSession(4))

	service.activeGlobal = 2
	service.activePerRoute[route] = 2
	service.clientAdmissions[testClientOne].active = 2
	current := testControl(route, testEpoch(2), pin)
	replaced, clients := service.installControl(current)
	if replaced != old {
		t.Fatalf("replaced control = %p, want %p", replaced, old)
	}
	if len(clients) != 2 {
		t.Fatalf("clients to close = %d, want 2", len(clients))
	}
	if service.controls[route] != current {
		t.Fatal("new control was not installed")
	}
	if len(service.pending) != 2 || service.pendingPerRoute[route] != 1 || service.pendingPerRoute[otherRoute] != 1 {
		t.Fatalf("pending state after replacement: global=%d route=%d other=%d", len(service.pending), service.pendingPerRoute[route], service.pendingPerRoute[otherRoute])
	}
	if service.activeGlobal != 2 || service.activePerRoute[route] != 2 {
		t.Fatal("control replacement disturbed already-active sessions")
	}
	if admission := service.clientAdmissions[testClientOne]; admission.pending != 2 || admission.active != 2 {
		t.Fatalf("client accounting after replacement = pending %d active %d, want 2/2", admission.pending, admission.active)
	}
	assertAccountingConsistent(t, service)
	assertResolution(t, oldOne, nil)
	assertResolution(t, oldTwo, nil)
	assertUnresolved(t, foreign)
	assertUnresolved(t, otherItem)
}

func TestPerClientPendingQuotaPreservesCapacityForPeer(t *testing.T) {
	service := testService(8, 4, 8, 4)
	service.config.Limits.PendingPerClient = 2
	route := testRoute(1)
	service.controls[route] = testControl(route, testEpoch(1), testPin(1))

	accepted := []*pending{
		mustBeginPendingFor(t, service, testClientOne, route, testSession(1)),
		mustBeginPendingFor(t, service, testClientOne, route, testSession(2)),
	}
	if _, item, ok := service.beginPending(testClientOne, route, testSession(3), new(tls.Conn), time.Now()); ok || item != nil {
		t.Fatal("one client exceeded its pending quota")
	}
	accepted = append(accepted, mustBeginPendingFor(t, service, testClientTwo, route, testSession(4)))

	if len(service.pending) != 3 || service.pendingPerRoute[route] != 3 {
		t.Fatalf("pending state = %d/%d, want 3/3", len(service.pending), service.pendingPerRoute[route])
	}
	if service.clientAdmissions[testClientOne].pending != 2 || service.clientAdmissions[testClientTwo].pending != 1 {
		t.Fatalf("per-client pending = %d/%d, want 2/1", service.clientAdmissions[testClientOne].pending, service.clientAdmissions[testClientTwo].pending)
	}
	mapSize := len(service.clientAdmissions)
	if _, item, ok := service.beginPending("unknown.owntransit.invalid", route, testSession(5), new(tls.Conn), time.Now()); ok || item != nil {
		t.Fatal("unknown identity entered pending state")
	}
	if len(service.clientAdmissions) != mapSize {
		t.Fatal("unknown pending attempt grew the fixed client map")
	}
	assertAccountingConsistent(t, service)
	cancelAll(t, service, accepted)
	assertAccountingConsistent(t, service)
}

func TestPendingCleanupOwnersReleaseClientAccounting(t *testing.T) {
	t.Run("connector cancel", func(t *testing.T) {
		service := testService(8, 8, 8, 8)
		route := testRoute(1)
		service.controls[route] = testControl(route, testEpoch(1), testPin(1))
		item := mustBeginPendingFor(t, service, testClientOne, route, testSession(1))

		if client := service.cancelPendingKey(item.key); client != item.client {
			t.Fatalf("connector cancellation returned client %p, want %p", client, item.client)
		}
		assertResolution(t, item, nil)
		assertAccountingConsistent(t, service)
	})

	t.Run("control disconnect", func(t *testing.T) {
		service := testService(8, 8, 8, 8)
		route := testRoute(1)
		current := testControl(route, testEpoch(1), testPin(1))
		service.controls[route] = current
		first := mustBeginPendingFor(t, service, testClientOne, route, testSession(1))
		second := mustBeginPendingFor(t, service, testClientTwo, route, testSession(2))

		service.removeControl(current)
		if service.controls[route] != nil {
			t.Fatal("disconnected control remained installed")
		}
		assertResolution(t, first, nil)
		assertResolution(t, second, nil)
		assertAccountingConsistent(t, service)
	})

	t.Run("handler cancellation after join", func(t *testing.T) {
		service := testService(8, 8, 8, 8)
		route := testRoute(1)
		pin := testPin(1)
		current := testControl(route, testEpoch(1), pin)
		service.controls[route] = current
		item := mustBeginPendingFor(t, service, testClientOne, route, testSession(1))
		frame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: item.key.session}
		if !service.joinData(new(tls.Conn), frame, pin) {
			t.Fatal("valid data join was rejected")
		}

		service.discardResolution(item)
		assertAccountingConsistent(t, service)
	})
}

func TestJoinRejectsStaleWrongPinExpiredAndWrongControl(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Service, *pending, *protocol.DataJoin, *identity.SPKIHash)
	}{
		{
			name: "stale epoch",
			mutate: func(_ *Service, _ *pending, frame *protocol.DataJoin, _ *identity.SPKIHash) {
				frame.Epoch = testEpoch(99)
			},
		},
		{
			name: "wrong route",
			mutate: func(_ *Service, _ *pending, frame *protocol.DataJoin, _ *identity.SPKIHash) {
				frame.Route = testRoute(99)
			},
		},
		{
			name: "wrong pin",
			mutate: func(_ *Service, _ *pending, _ *protocol.DataJoin, pin *identity.SPKIHash) {
				*pin = testPin(99)
			},
		},
		{
			name: "expired",
			mutate: func(_ *Service, item *pending, _ *protocol.DataJoin, _ *identity.SPKIHash) {
				item.deadline = time.Now().Add(-time.Second)
			},
		},
		{
			name: "different current control with same epoch and pin",
			mutate: func(service *Service, item *pending, _ *protocol.DataJoin, _ *identity.SPKIHash) {
				service.controls[item.key.route] = testControl(item.key.route, item.key.epoch, item.connectorPin)
			},
		},
		{
			name: "global active limit",
			mutate: func(service *Service, _ *pending, _ *protocol.DataJoin, _ *identity.SPKIHash) {
				service.activeGlobal = service.config.Limits.ActiveGlobal
			},
		},
		{
			name: "route active limit",
			mutate: func(service *Service, item *pending, _ *protocol.DataJoin, _ *identity.SPKIHash) {
				service.activePerRoute[item.key.route] = service.config.Limits.ActivePerRoute
			},
		},
		{
			name: "client active limit",
			mutate: func(service *Service, item *pending, _ *protocol.DataJoin, _ *identity.SPKIHash) {
				item.admission.active = service.config.Limits.ActivePerClientValue()
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := testService(8, 8, 4, 4)
			route := testRoute(1)
			pin := testPin(1)
			current := testControl(route, testEpoch(1), pin)
			service.controls[route] = current
			item := mustBeginPending(t, service, route, testSession(1))
			frame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: item.key.session}
			joinPin := pin
			test.mutate(service, item, &frame, &joinPin)

			if service.joinData(new(tls.Conn), frame, joinPin) {
				t.Fatal("invalid data join was accepted")
			}
			if got := service.pending[item.key]; got != item {
				t.Fatal("rejected join changed the pending entry")
			}
			if service.pendingPerRoute[route] != 1 {
				t.Fatalf("pending route count = %d, want 1", service.pendingPerRoute[route])
			}
			if item.admission.pending != 1 {
				t.Fatalf("client pending count = %d, want 1", item.admission.pending)
			}
			assertUnresolved(t, item)
		})
	}
}

func TestPerClientActiveQuotaPreservesCapacityForPeer(t *testing.T) {
	service := testService(16, 8, 8, 8)
	service.config.Limits.PendingPerClient = 4
	service.config.Limits.ActivePerClient = 2
	route := testRoute(1)
	pin := testPin(1)
	current := testControl(route, testEpoch(1), pin)
	service.controls[route] = current

	clientOne := []*pending{
		mustBeginPendingFor(t, service, testClientOne, route, testSession(1)),
		mustBeginPendingFor(t, service, testClientOne, route, testSession(2)),
		mustBeginPendingFor(t, service, testClientOne, route, testSession(3)),
	}
	clientTwo := mustBeginPendingFor(t, service, testClientTwo, route, testSession(4))
	for _, item := range clientOne[:2] {
		connector := new(tls.Conn)
		frame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: item.key.session}
		if !service.joinData(connector, frame, pin) {
			t.Fatal("client-one join below its active quota was rejected")
		}
		assertResolution(t, item, connector)
	}
	rejectedFrame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: clientOne[2].key.session}
	if service.joinData(new(tls.Conn), rejectedFrame, pin) {
		t.Fatal("client one exceeded its active quota")
	}
	assertUnresolved(t, clientOne[2])

	clientTwoConnector := new(tls.Conn)
	clientTwoFrame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: clientTwo.key.session}
	if !service.joinData(clientTwoConnector, clientTwoFrame, pin) {
		t.Fatal("client one at quota starved client two")
	}
	assertResolution(t, clientTwo, clientTwoConnector)

	if service.activeGlobal != 3 || service.activePerRoute[route] != 3 {
		t.Fatalf("active state = %d/%d, want 3/3", service.activeGlobal, service.activePerRoute[route])
	}
	if service.clientAdmissions[testClientOne].active != 2 || service.clientAdmissions[testClientTwo].active != 1 {
		t.Fatalf("per-client active = %d/%d, want 2/1", service.clientAdmissions[testClientOne].active, service.clientAdmissions[testClientTwo].active)
	}
	if service.clientAdmissions[testClientOne].pending != 1 || service.clientAdmissions[testClientTwo].pending != 0 {
		t.Fatalf("per-client pending = %d/%d, want 1/0", service.clientAdmissions[testClientOne].pending, service.clientAdmissions[testClientTwo].pending)
	}
	assertAccountingConsistent(t, service)

	service.finishActive(clientOne[0])
	service.finishActive(clientOne[1])
	service.finishActive(clientTwo)
	if service.cancelPendingItem(clientOne[2]) != clientOne[2].client {
		t.Fatal("failed to cancel quota-rejected pending session")
	}
	assertResolution(t, clientOne[2], nil)
	for name, admission := range service.clientAdmissions {
		if admission.pending != 0 || admission.active != 0 {
			t.Fatalf("client %q leaked pending/active state %d/%d", name, admission.pending, admission.active)
		}
	}
	assertAccountingConsistent(t, service)
}

func TestJoinIsAtMostOnceUnderConcurrency(t *testing.T) {
	service := testService(64, 64, 64, 64)
	route := testRoute(1)
	pin := testPin(1)
	control := testControl(route, testEpoch(1), pin)
	service.controls[route] = control
	item := mustBeginPending(t, service, route, testSession(1))
	frame := protocol.DataJoin{Route: route, Epoch: control.epoch, Session: item.key.session}

	const contenders = 64
	start := make(chan struct{})
	accepted := make(chan *tls.Conn, contenders)
	var wait sync.WaitGroup
	for range contenders {
		wait.Add(1)
		go func() {
			defer wait.Done()
			connector := new(tls.Conn)
			<-start
			if service.joinData(connector, frame, pin) {
				accepted <- connector
			}
		}()
	}
	close(start)
	wait.Wait()
	close(accepted)

	if len(accepted) != 1 {
		t.Fatalf("accepted joins = %d, want 1", len(accepted))
	}
	winner := <-accepted
	assertResolution(t, item, winner)
	if len(service.pending) != 0 || service.pendingPerRoute[route] != 0 {
		t.Fatal("winning join did not atomically remove pending state")
	}
	if service.activeGlobal != 1 || service.activePerRoute[route] != 1 {
		t.Fatalf("active counts = %d/%d, want 1/1", service.activeGlobal, service.activePerRoute[route])
	}
	if item.admission.pending != 0 || item.admission.active != 1 {
		t.Fatalf("client counts = %d/%d, want 0/1", item.admission.pending, item.admission.active)
	}
	assertAccountingConsistent(t, service)
	service.finishActive(item)
	if service.activeGlobal != 0 || service.activePerRoute[route] != 0 {
		t.Fatal("active counts did not return to zero")
	}
	if item.admission.pending != 0 || item.admission.active != 0 {
		t.Fatal("client counts did not return to zero")
	}
	assertAccountingConsistent(t, service)
}

func TestJoinVersusCancellationMaintainsExactCounts(t *testing.T) {
	service := testService(8, 8, 8, 8)
	route := testRoute(1)
	pin := testPin(1)
	control := testControl(route, testEpoch(1), pin)
	service.controls[route] = control

	for iteration := uint64(0); iteration < 512; iteration++ {
		item := mustBeginPending(t, service, route, testSession(iteration))
		frame := protocol.DataJoin{Route: route, Epoch: control.epoch, Session: item.key.session}
		connector := new(tls.Conn)
		start := make(chan struct{})
		var joinWon bool
		var cancelled *tls.Conn
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			joinWon = service.joinData(connector, frame, pin)
		}()
		go func() {
			defer wait.Done()
			<-start
			cancelled = service.cancelPendingItem(item)
		}()
		close(start)
		wait.Wait()

		resolved := <-item.resolved
		if joinWon {
			if cancelled != nil || resolved != connector {
				t.Fatalf("iteration %d: join won with cancellation=%p resolution=%p", iteration, cancelled, resolved)
			}
			if service.activeGlobal != 1 || service.activePerRoute[route] != 1 {
				t.Fatalf("iteration %d: active counts = %d/%d", iteration, service.activeGlobal, service.activePerRoute[route])
			}
			service.finishActive(item)
		} else {
			if cancelled != item.client || resolved != nil {
				t.Fatalf("iteration %d: cancel won with client=%p resolution=%p", iteration, cancelled, resolved)
			}
		}
		if len(service.pending) != 0 || service.pendingPerRoute[route] != 0 ||
			service.activeGlobal != 0 || service.activePerRoute[route] != 0 ||
			item.admission.pending != 0 || item.admission.active != 0 {
			t.Fatalf("iteration %d leaked state: pending=%d/%d active=%d/%d", iteration, len(service.pending), service.pendingPerRoute[route], service.activeGlobal, service.activePerRoute[route])
		}
		assertAccountingConsistent(t, service)
	}
}

func TestJoinVersusControlReplacementIsAtomic(t *testing.T) {
	for iteration := uint64(0); iteration < 256; iteration++ {
		service := testService(8, 8, 8, 8)
		route := testRoute(1)
		pin := testPin(1)
		old := testControl(route, testEpoch(1), pin)
		service.controls[route] = old
		item := mustBeginPending(t, service, route, testSession(iteration))
		frame := protocol.DataJoin{Route: route, Epoch: old.epoch, Session: item.key.session}
		connector := new(tls.Conn)
		current := testControl(route, testEpoch(2), pin)

		start := make(chan struct{})
		var joinWon bool
		var replaced *control
		var clients []*tls.Conn
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			joinWon = service.joinData(connector, frame, pin)
		}()
		go func() {
			defer wait.Done()
			<-start
			replaced, clients = service.installControl(current)
		}()
		close(start)
		wait.Wait()

		if replaced != old || service.controls[route] != current {
			t.Fatalf("iteration %d: control replacement was not exact", iteration)
		}
		resolved := <-item.resolved
		if joinWon {
			if resolved != connector || len(clients) != 0 || service.activeGlobal != 1 || service.activePerRoute[route] != 1 {
				t.Fatalf("iteration %d: join outcome resolution=%p clients=%d active=%d/%d", iteration, resolved, len(clients), service.activeGlobal, service.activePerRoute[route])
			}
			service.finishActive(item)
		} else {
			if resolved != nil || len(clients) != 1 || service.activeGlobal != 0 || service.activePerRoute[route] != 0 {
				t.Fatalf("iteration %d: replacement outcome resolution=%p clients=%d active=%d/%d", iteration, resolved, len(clients), service.activeGlobal, service.activePerRoute[route])
			}
		}
		if len(service.pending) != 0 || len(service.pendingPerRoute) != 0 || service.activeGlobal != 0 || len(service.activePerRoute) != 0 ||
			item.admission.pending != 0 || item.admission.active != 0 {
			t.Fatalf("iteration %d leaked relay state", iteration)
		}
		assertAccountingConsistent(t, service)
	}
}

func TestStalePendingObjectCannotCancelReplacement(t *testing.T) {
	service := testService(8, 8, 8, 8)
	route := testRoute(1)
	control := testControl(route, testEpoch(1), testPin(1))
	service.controls[route] = control
	session := testSession(1)
	old := mustBeginPending(t, service, route, session)
	if service.cancelPendingItem(old) != old.client {
		t.Fatal("initial cancellation failed")
	}
	assertResolution(t, old, nil)

	replacement := mustBeginPending(t, service, route, session)
	if service.cancelPendingItem(old) != nil {
		t.Fatal("stale object cancelled a replacement with the same key")
	}
	if service.pending[replacement.key] != replacement || service.pendingPerRoute[route] != 1 {
		t.Fatal("replacement pending entry was disturbed")
	}
	if replacement.admission.pending != 1 {
		t.Fatalf("replacement client pending count = %d, want 1", replacement.admission.pending)
	}
	assertAccountingConsistent(t, service)
	assertUnresolved(t, replacement)
}

func TestConcurrentPendingLimitsAreHard(t *testing.T) {
	t.Run("per route", func(t *testing.T) {
		service := testService(100, 4, 100, 100)
		route := testRoute(1)
		service.controls[route] = testControl(route, testEpoch(1), testPin(1))
		accepted := concurrentlyBegin(t, service, []protocol.RouteID{route}, 64)
		if len(accepted) != 4 || len(service.pending) != 4 || service.pendingPerRoute[route] != 4 {
			t.Fatalf("accepted/pending/route = %d/%d/%d, want 4/4/4", len(accepted), len(service.pending), service.pendingPerRoute[route])
		}
		cancelAll(t, service, accepted)
	})

	t.Run("global", func(t *testing.T) {
		service := testService(5, 10, 100, 100)
		routes := []protocol.RouteID{testRoute(1), testRoute(2)}
		for index, route := range routes {
			service.controls[route] = testControl(route, testEpoch(1), testPin(byte(index+1)))
		}
		accepted := concurrentlyBegin(t, service, routes, 64)
		if len(accepted) != 5 || len(service.pending) != 5 {
			t.Fatalf("accepted/global pending = %d/%d, want 5/5", len(accepted), len(service.pending))
		}
		for _, route := range routes {
			if service.pendingPerRoute[route] > 5 {
				t.Fatalf("route %x count exceeds global bound: %d", route, service.pendingPerRoute[route])
			}
		}
		cancelAll(t, service, accepted)
	})

	t.Run("per client", func(t *testing.T) {
		service := testService(8, 8, 100, 100)
		service.config.Limits.PendingPerClient = 2
		routes := []protocol.RouteID{testRoute(1), testRoute(2)}
		for index, route := range routes {
			service.controls[route] = testControl(route, testEpoch(1), testPin(byte(index+1)))
		}
		clients := []string{
			testClientOne, testClientOne, testClientTwo, testClientTwo,
			testClientOne, testClientOne, testClientTwo, testClientTwo,
		}
		accepted := concurrentlyBeginForClients(t, service, routes, clients)
		if len(accepted) != 4 || len(service.pending) != 4 || service.pendingPerRoute[routes[0]]+service.pendingPerRoute[routes[1]] != 4 {
			t.Fatalf("accepted/global/route-sum = %d/%d/%d, want 4/4/4", len(accepted), len(service.pending), service.pendingPerRoute[routes[0]]+service.pendingPerRoute[routes[1]])
		}
		if service.clientAdmissions[testClientOne].pending != 2 || service.clientAdmissions[testClientTwo].pending != 2 {
			t.Fatalf("per-client pending = %d/%d, want 2/2", service.clientAdmissions[testClientOne].pending, service.clientAdmissions[testClientTwo].pending)
		}
		cancelAll(t, service, accepted)
	})
}

func concurrentlyBegin(t testing.TB, service *Service, routes []protocol.RouteID, count int) []*pending {
	t.Helper()
	clients := make([]string, count)
	for index := range clients {
		clients[index] = testClientOne
	}
	return concurrentlyBeginForClients(t, service, routes, clients)
}

func concurrentlyBeginForClients(t testing.TB, service *Service, routes []protocol.RouteID, clients []string) []*pending {
	t.Helper()
	count := len(clients)
	start := make(chan struct{})
	accepted := make(chan *pending, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, item, ok := service.beginPending(clients[index], routes[index%len(routes)], testSession(uint64(index+1)), new(tls.Conn), time.Now())
			if ok {
				accepted <- item
			}
		}()
	}
	close(start)
	wait.Wait()
	close(accepted)
	result := make([]*pending, 0, len(accepted))
	for item := range accepted {
		result = append(result, item)
	}
	return result
}

func cancelAll(t testing.TB, service *Service, items []*pending) {
	t.Helper()
	for _, item := range items {
		if service.cancelPendingItem(item) != item.client {
			t.Fatal("failed to cancel accepted pending item")
		}
		assertResolution(t, item, nil)
	}
	if len(service.pending) != 0 || len(service.pendingPerRoute) != 0 {
		t.Fatalf("pending cleanup leaked state: %d entries, %d route counters", len(service.pending), len(service.pendingPerRoute))
	}
	for name, admission := range service.clientAdmissions {
		if admission.pending != 0 {
			t.Fatalf("client %q leaked %d pending sessions", name, admission.pending)
		}
	}
	assertAccountingConsistent(t, service)
}

func TestConcurrentJoinsRespectActiveLimits(t *testing.T) {
	service := testService(64, 64, 5, 3)
	routes := []protocol.RouteID{testRoute(1), testRoute(2)}
	pins := []identity.SPKIHash{testPin(1), testPin(2)}
	for index, route := range routes {
		service.controls[route] = testControl(route, testEpoch(1), pins[index])
	}

	type candidate struct {
		item  *pending
		route protocol.RouteID
		pin   identity.SPKIHash
	}
	var candidates []candidate
	for index := 0; index < 32; index++ {
		routeIndex := index % len(routes)
		item := mustBeginPending(t, service, routes[routeIndex], testSession(uint64(index+1)))
		candidates = append(candidates, candidate{item: item, route: routes[routeIndex], pin: pins[routeIndex]})
	}

	start := make(chan struct{})
	accepted := make(chan candidate, len(candidates))
	var wait sync.WaitGroup
	for _, value := range candidates {
		value := value
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			frame := protocol.DataJoin{Route: value.route, Epoch: value.item.key.epoch, Session: value.item.key.session}
			if service.joinData(new(tls.Conn), frame, value.pin) {
				accepted <- value
			}
		}()
	}
	close(start)
	wait.Wait()
	close(accepted)

	if len(accepted) != 5 || service.activeGlobal != 5 {
		t.Fatalf("accepted/global active = %d/%d, want 5/5", len(accepted), service.activeGlobal)
	}
	for _, route := range routes {
		if service.activePerRoute[route] > 3 {
			t.Fatalf("route %x active count = %d, exceeds 3", route, service.activePerRoute[route])
		}
	}
	assertAccountingConsistent(t, service)
	acceptedSet := make(map[*pending]struct{}, len(accepted))
	for value := range accepted {
		acceptedSet[value.item] = struct{}{}
		connector := <-value.item.resolved
		if connector == nil {
			t.Fatal("accepted join resolved as cancellation")
		}
		service.finishActive(value.item)
	}
	if service.activeGlobal != 0 || len(service.activePerRoute) != 0 {
		t.Fatalf("active cleanup leaked state: %d global, %d route counters", service.activeGlobal, len(service.activePerRoute))
	}
	if service.clientAdmissions[testClientOne].active != 0 {
		t.Fatalf("client active cleanup leaked %d sessions", service.clientAdmissions[testClientOne].active)
	}
	for _, value := range candidates {
		if _, wasAccepted := acceptedSet[value.item]; wasAccepted {
			continue
		}
		if service.cancelPendingItem(value.item) != value.item.client {
			t.Fatal("rejected join did not remain pending")
		}
		assertResolution(t, value.item, nil)
	}
	if len(service.pending) != 0 || len(service.pendingPerRoute) != 0 || service.clientAdmissions[testClientOne].pending != 0 {
		t.Fatal("rejected active-limit joins leaked pending accounting")
	}
	assertAccountingConsistent(t, service)
}

func TestConcurrentJoinsRespectPerClientActiveLimits(t *testing.T) {
	service := testService(16, 8, 8, 8)
	service.config.Limits.PendingPerClient = 4
	service.config.Limits.ActivePerClient = 2
	route := testRoute(1)
	pin := testPin(1)
	current := testControl(route, testEpoch(1), pin)
	service.controls[route] = current

	var candidates []*pending
	for index := 0; index < 4; index++ {
		candidates = append(candidates, mustBeginPendingFor(t, service, testClientOne, route, testSession(uint64(index+1))))
		candidates = append(candidates, mustBeginPendingFor(t, service, testClientTwo, route, testSession(uint64(index+101))))
	}

	start := make(chan struct{})
	accepted := make(chan *pending, len(candidates))
	var wait sync.WaitGroup
	for _, item := range candidates {
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			frame := protocol.DataJoin{Route: route, Epoch: current.epoch, Session: item.key.session}
			if service.joinData(new(tls.Conn), frame, pin) {
				accepted <- item
			}
		}()
	}
	close(start)
	wait.Wait()
	close(accepted)

	if len(accepted) != 4 || service.activeGlobal != 4 || service.activePerRoute[route] != 4 {
		t.Fatalf("accepted/global/route active = %d/%d/%d, want 4/4/4", len(accepted), service.activeGlobal, service.activePerRoute[route])
	}
	for _, clientName := range []string{testClientOne, testClientTwo} {
		admission := service.clientAdmissions[clientName]
		if admission.active != 2 || admission.pending != 2 {
			t.Fatalf("client %q active/pending = %d/%d, want 2/2", clientName, admission.active, admission.pending)
		}
	}
	assertAccountingConsistent(t, service)

	acceptedSet := make(map[*pending]struct{}, len(accepted))
	for item := range accepted {
		acceptedSet[item] = struct{}{}
		if connector := <-item.resolved; connector == nil {
			t.Fatal("accepted per-client join resolved as cancellation")
		}
		service.finishActive(item)
	}
	for _, item := range candidates {
		if _, ok := acceptedSet[item]; ok {
			continue
		}
		if service.cancelPendingItem(item) != item.client {
			t.Fatal("quota-rejected per-client join did not remain pending")
		}
		assertResolution(t, item, nil)
	}
	if len(service.pending) != 0 || len(service.pendingPerRoute) != 0 || service.activeGlobal != 0 || len(service.activePerRoute) != 0 {
		t.Fatal("per-client active-limit cleanup leaked global or route state")
	}
	for name, admission := range service.clientAdmissions {
		if admission.pending != 0 || admission.active != 0 {
			t.Fatalf("client %q leaked pending/active state %d/%d", name, admission.pending, admission.active)
		}
	}
	assertAccountingConsistent(t, service)
}

func TestCopyPairStopsOnContextCancellation(t *testing.T) {
	service := testService(8, 8, 8, 8)
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	t.Cleanup(func() {
		left.Close()
		leftPeer.Close()
		right.Close()
		rightPeer.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		service.copyPair(ctx, left, right)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("copyPair did not stop after context cancellation")
	}
}

func TestAbortConnectionUnwrapsTLSForImmediateCarrierAbort(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	underlying := &abortTrackingCarrier{Conn: left}
	connection := tls.Server(underlying, &tls.Config{})

	abortConnection(connection)
	if !underlying.aborted {
		t.Fatal("abortConnection used TLS graceful close instead of aborting its carrier")
	}
}

type abortTrackingCarrier struct {
	net.Conn
	aborted bool
}

func (connection *abortTrackingCarrier) Abort() error {
	connection.aborted = true
	return connection.Conn.Close()
}
