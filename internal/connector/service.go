// Package connector implements the outbound-only private-side OwnTransit
// endpoint. The relay can request bounded connection attempts, but it cannot
// choose the local destination or authorize an inner client.
package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sentrybottale/owntransit/internal/carrier"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
)

const (
	fixedSSHNetwork = "tcp4"
	fixedSSHTarget  = config.ConnectorSSHTarget

	controlHeartbeatInterval = 30 * time.Second
	controlHeartbeatTimeout  = 90 * time.Second
	innerPreAuthByteLimit    = 256 << 10
)

var (
	errAlreadyRun         = errors.New("connector: service has already been run")
	errInvalidControl     = errors.New("connector: invalid control state")
	errNoActiveSlot       = errors.New("connector: active-session limit reached")
	errNoClientActiveSlot = errors.New("connector: per-client active-session limit reached")
	errInnerByteLimit     = errors.New("connector: inner pre-authentication byte limit exceeded")
)

// CarrierDialer returns one untrusted byte-stream connection to the configured
// relay. Every returned stream is wrapped in independently authenticated outer
// TLS before any OwnTransit frame is sent.
type CarrierDialer interface {
	Dial(context.Context) (net.Conn, error)
}

// DialContext is the deliberately narrow local-network capability held by the
// connector. It is invoked only after the complete inner TLS handshake and
// local client authorization have succeeded.
type DialContext interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type dependencies struct {
	carrier CarrierDialer
	local   DialContext
	state   StateSink
}

// Option replaces one explicitly injectable connector dependency.
type Option func(*dependencies) error

// State is a deliberately coarse connector control-plane state. It contains
// no route, identity, certificate, address, or peer-controlled text and is
// therefore safe to emit to a local supervisor journal.
type State string

const (
	StateRegistered   State = "registered"
	StateDisconnected State = "disconnected"
)

// StateSink receives coarse control-plane transitions. The default is a
// no-op so library users do not acquire an implicit logging side effect.
type StateSink func(State)

// WithCarrierDialer replaces the WebSocket carrier dialer. It is primarily
// useful for deterministic protocol tests.
func WithCarrierDialer(dialer CarrierDialer) Option {
	return func(deps *dependencies) error {
		if dialer == nil {
			return errors.New("connector: carrier dialer is nil")
		}
		deps.carrier = dialer
		return nil
	}
}

// WithLocalDialer replaces the fixed-target network dialer. The connector
// still supplies the hard-coded network and address; the dependency cannot
// select them.
func WithLocalDialer(dialer DialContext) Option {
	return func(deps *dependencies) error {
		if dialer == nil {
			return errors.New("connector: local dialer is nil")
		}
		deps.local = dialer
		return nil
	}
}

// WithStateSink installs a local-only coarse state observer. Callers must not
// attach peer-controlled detail to these fixed states.
func WithStateSink(sink StateSink) Option {
	return func(deps *dependencies) error {
		if sink == nil {
			return errors.New("connector: state sink is nil")
		}
		deps.state = sink
		return nil
	}
}

type Service struct {
	config    config.Connector
	route     protocol.RouteID
	bootNonce protocol.BootNonce
	carrier   CarrierDialer
	local     DialContext
	outerTLS  *tls.Config
	innerTLS  *tls.Config
	state     StateSink
	preflight func() error

	pending           chan struct{}
	active            chan struct{}
	limiter           *openLimiter
	capabilityProfile bool
	clientActiveMu    sync.Mutex
	clientActive      map[protocol.ID]int

	sessionsMu sync.Mutex
	sessions   map[sessionKey]struct{}
	workers    sync.WaitGroup
	started    atomic.Bool
	bufferPool sync.Pool

	now               func() time.Time
	sleep             func(context.Context, time.Duration) bool
	jitter            func(time.Duration) time.Duration
	heartbeatInterval time.Duration
	heartbeatTimeout  time.Duration
}

type sessionKey struct {
	epoch   protocol.EpochID
	session protocol.SessionID
}

// New validates and snapshots all connector policy. No network connection is
// made until Run. The default carrier adapter is the sole place this package
// depends on the WebSocket cleartext-development option.
func New(value config.Connector, options ...Option) (*Service, error) {
	return newService(value, nil, nil, options...)
}

// NewFromMaterial snapshots a connector from one authenticated lifecycle
// generation without reopening credential pathnames.
func NewFromMaterial(value config.Connector, reader tlsprofile.MaterialReader, finalCheck func() error, options ...Option) (*Service, error) {
	if reader == nil || finalCheck == nil {
		return nil, errors.New("connector: runtime material reader and final selection check are required")
	}
	return newService(value, reader, finalCheck, options...)
}

func newService(value config.Connector, reader tlsprofile.MaterialReader, preflight func() error, options ...Option) (*Service, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	route, err := protocol.ParseRouteID(value.RouteID)
	if err != nil {
		return nil, err
	}
	if value.SSHTarget != fixedSSHTarget {
		return nil, errors.New("connector: SSH target is not the fixed loopback address")
	}

	loadClientTLS := tlsprofile.Client
	if reader != nil {
		loadClientTLS = func(value config.ClientTLS, expectedName, alpn string) (*tls.Config, error) {
			return tlsprofile.ClientFromMaterial(value, expectedName, alpn, reader)
		}
	}
	outerTLS, err := loadClientTLS(value.OuterTLS, config.OuterConnectorDNSName(route), config.RelayALPN)
	if err != nil {
		return nil, fmt.Errorf("connector: outer TLS: %w", err)
	}
	var innerTLS *tls.Config
	switch value.InnerProfile {
	case config.InnerProfileRouteCapability:
		connectorID, parseErr := protocol.ParseID(value.InstallationID)
		if parseErr != nil {
			return nil, fmt.Errorf("connector: installation ID: %w", parseErr)
		}
		if reader == nil {
			innerTLS, err = tlsprofile.CapabilityServer(value.InnerTLS, connectorID, route)
		} else {
			innerTLS, err = tlsprofile.CapabilityServerFromMaterial(value.InnerTLS, connectorID, route, reader)
		}
	case config.InnerProfileLegacyExactPins:
		var peers map[string]identity.PinSet
		peers, err = tlsprofile.ParsePeers(value.InnerTLS.Clients)
		if err == nil {
			serverValue := config.ServerTLS{
				CertFile:     value.InnerTLS.CertFile,
				KeyFile:      value.InnerTLS.KeyFile,
				ClientCAFile: value.InnerTLS.ClientCAFile,
				IssuerCAFile: value.InnerTLS.IssuerCAFile,
				LocalDNSName: value.InnerTLS.LocalDNSName,
			}
			if reader == nil {
				innerTLS, err = tlsprofile.Server(serverValue, value.InnerTLS.ServerName, config.InnerALPN, peers)
			} else {
				innerTLS, err = tlsprofile.ServerFromMaterial(serverValue, value.InnerTLS.ServerName, config.InnerALPN, peers, reader)
			}
		}
	default:
		err = errors.New("unsupported inner profile")
	}
	if err != nil {
		return nil, fmt.Errorf("connector: inner TLS: %w", err)
	}

	deps := dependencies{
		local: &net.Dialer{Timeout: value.Limits.LocalDial.Value()},
		state: func(State) {},
	}
	for index, option := range options {
		if option == nil {
			return nil, fmt.Errorf("connector: option %d is nil", index)
		}
		if err := option(&deps); err != nil {
			return nil, err
		}
	}
	if deps.carrier == nil {
		deps.carrier, err = defaultCarrierDialer(value, reader)
		if err != nil {
			return nil, err
		}
	}
	if deps.local == nil {
		return nil, errors.New("connector: local dialer is required")
	}

	bootNonce, err := protocol.NewBootNonce()
	if err != nil {
		return nil, fmt.Errorf("connector: generate boot nonce: %w", err)
	}
	now := time.Now
	service := &Service{
		config:            value,
		route:             route,
		bootNonce:         bootNonce,
		carrier:           deps.carrier,
		local:             deps.local,
		outerTLS:          outerTLS,
		innerTLS:          innerTLS,
		state:             deps.state,
		preflight:         preflight,
		pending:           make(chan struct{}, value.Limits.Pending),
		active:            make(chan struct{}, value.Limits.Active),
		capabilityProfile: value.InnerProfile == config.InnerProfileRouteCapability,
		clientActive:      make(map[protocol.ID]int, value.Limits.Active),
		sessions:          make(map[sessionKey]struct{}, value.Limits.Pending+value.Limits.Active),
		now:               now,
		sleep:             sleepContext,
		jitter:            jitterDuration,
		heartbeatInterval: controlHeartbeatInterval,
		heartbeatTimeout:  controlHeartbeatTimeout,
	}
	service.limiter = newOpenLimiter(now)
	service.bufferPool.New = func() any {
		buffer := make([]byte, 32<<10)
		return &buffer
	}
	return service, nil
}

func defaultCarrierDialer(value config.Connector, reader tlsprofile.MaterialReader) (CarrierDialer, error) {
	var dialer *carrier.Dialer
	var err error
	if reader == nil {
		dialer, err = carrier.NewDialer(
			value.RelayURL,
			value.CarrierCAFile,
			value.AllowInsecureCarrier,
			value.Limits.ConnectTimeout.Value(),
		)
	} else {
		var caPEM []byte
		if value.CarrierCAFile != "" {
			caPEM, err = reader(value.CarrierCAFile)
			if err != nil {
				return nil, fmt.Errorf("connector: carrier CA material: %w", err)
			}
		}
		dialer, err = carrier.NewDialerFromMaterial(
			value.RelayURL,
			caPEM,
			value.AllowInsecureCarrier,
			value.Limits.ConnectTimeout.Value(),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("connector: carrier: %w", err)
	}
	return dialer, nil
}

// Run maintains one authenticated control registration until ctx is canceled.
// A hostile relay cannot turn reconnects into a tight loop: failures back off,
// and a short-lived successful registration does not reset the backoff.
func (service *Service) Run(ctx context.Context) error {
	if ctx == nil {
		return errors.New("connector: context is nil")
	}
	if !service.started.CompareAndSwap(false, true) {
		return errAlreadyRun
	}
	if service.preflight != nil {
		if err := service.preflight(); err != nil {
			return fmt.Errorf("connector: final runtime selection check: %w", err)
		}
	}

	backoff := service.config.Limits.ReconnectMin.Value()
	maximum := service.config.Limits.ReconnectMax.Value()
	for {
		started := service.now()
		err := service.runControl(ctx)
		if ctx.Err() != nil {
			service.workers.Wait()
			return nil
		}
		if err != nil {
			service.state(StateDisconnected)
		}

		if service.now().Sub(started) >= service.heartbeatTimeout {
			backoff = service.config.Limits.ReconnectMin.Value()
		}
		delay := service.jitter(backoff)
		if delay > maximum {
			delay = maximum
		}
		if !service.sleep(ctx, delay) {
			service.workers.Wait()
			return nil
		}
		backoff = nextBackoff(backoff, maximum)
	}
}

func (service *Service) runControl(ctx context.Context) error {
	outer, err := service.connectOuter(ctx)
	if err != nil {
		return err
	}
	defer outer.Close()
	stopClose := context.AfterFunc(ctx, func() { outer.Close() })
	defer stopClose()

	if err := setWriteDeadline(outer, service.config.Limits.Handshake.Value(), service.now); err != nil {
		return err
	}
	if err := protocol.WriteFrame(outer, protocol.ControlRegister{Route: service.route, BootNonce: service.bootNonce}); err != nil {
		return fmt.Errorf("connector: register control: %w", err)
	}
	if err := outer.SetWriteDeadline(time.Time{}); err != nil {
		return err
	}
	if err := outer.SetReadDeadline(service.now().Add(service.config.Limits.Handshake.Value())); err != nil {
		return err
	}
	frame, err := protocol.ReadFrame(outer)
	if err != nil {
		return fmt.Errorf("connector: read registration: %w", err)
	}
	registered, ok := frame.(protocol.Registered)
	if !ok || registered.Epoch == (protocol.EpochID{}) {
		return errInvalidControl
	}
	if err := outer.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	service.state(StateRegistered)

	control := &controlSession{
		conn:         outer,
		epoch:        registered.Epoch,
		writeTimeout: service.config.Limits.Handshake.Value(),
		now:          service.now,
	}
	return service.serveControl(ctx, control)
}

type controlSession struct {
	conn         *tls.Conn
	epoch        protocol.EpochID
	writeTimeout time.Duration
	now          func() time.Time
	writeMu      sync.Mutex
}

func (control *controlSession) write(frame protocol.Frame) error {
	control.writeMu.Lock()
	defer control.writeMu.Unlock()
	if err := setWriteDeadline(control.conn, control.writeTimeout, control.now); err != nil {
		return err
	}
	err := protocol.WriteFrame(control.conn, frame)
	clearErr := control.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (service *Service) serveControl(ctx context.Context, control *controlSession) error {
	heartbeatContext, cancelHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(service.heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatContext.Done():
				return
			case <-ticker.C:
				if err := control.write(protocol.Ping{}); err != nil {
					control.conn.Close()
					return
				}
			}
		}
	}()
	defer func() {
		cancelHeartbeat()
		<-heartbeatDone
	}()

	lastPong := service.now()
	for {
		if err := control.conn.SetReadDeadline(lastPong.Add(service.heartbeatTimeout)); err != nil {
			return err
		}
		frame, err := protocol.ReadFrame(control.conn)
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		switch value := frame.(type) {
		case protocol.Pong:
			lastPong = service.now()
		case protocol.Ping:
			if err := control.write(protocol.Pong{}); err != nil {
				return err
			}
		case protocol.Open:
			if err := service.acceptOpen(ctx, control, value); err != nil {
				return err
			}
		default:
			return errInvalidControl
		}
	}
}

func (service *Service) acceptOpen(ctx context.Context, control *controlSession, open protocol.Open) error {
	if open.Epoch != control.epoch || open.Session == (protocol.SessionID{}) {
		return errInvalidControl
	}
	if !service.limiter.Allow() {
		// One authenticated client must not be able to tear down the connector's
		// shared control registration by consuming the route burst. Reject only
		// this session and keep the control channel available to other clients.
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return nil
	}
	if !tryAcquire(service.pending) {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return nil
	}

	key := sessionKey{epoch: open.Epoch, session: open.Session}
	service.sessionsMu.Lock()
	if _, duplicate := service.sessions[key]; duplicate {
		service.sessionsMu.Unlock()
		release(service.pending)
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return nil
	}
	service.sessions[key] = struct{}{}
	service.sessionsMu.Unlock()

	service.workers.Add(1)
	go func() {
		defer service.workers.Done()
		defer func() {
			service.sessionsMu.Lock()
			delete(service.sessions, key)
			service.sessionsMu.Unlock()
		}()
		service.runSession(ctx, control, open)
	}()
	return nil
}

func tryAcquire(semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

func release(semaphore chan struct{}) {
	<-semaphore
}

func setWriteDeadline(connection net.Conn, timeout time.Duration, now func() time.Time) error {
	return connection.SetWriteDeadline(now().Add(timeout))
}
