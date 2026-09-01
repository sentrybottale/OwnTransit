package connector

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
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/sessionguard"
)

func (service *Service) connectOuter(ctx context.Context) (*tls.Conn, error) {
	carrierConnection, err := service.carrier.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("connector: carrier connection: %w", err)
	}
	outer := tls.Client(carrierConnection, service.outerTLS)
	if err := explicitHandshake(ctx, outer, service.config.Limits.Handshake.Value(), service.now); err != nil {
		carrierConnection.Close()
		return nil, fmt.Errorf("connector: outer TLS handshake: %w", err)
	}
	return outer, nil
}

func explicitHandshake(ctx context.Context, connection *tls.Conn, timeout time.Duration, now func() time.Time) error {
	deadline := now().Add(timeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	handshakeContext, cancel := context.WithDeadline(ctx, deadline)
	err := connection.HandshakeContext(handshakeContext)
	cancel()
	clearErr := connection.SetDeadline(time.Time{})
	if err != nil {
		return err
	}
	return clearErr
}

func (service *Service) runSession(ctx context.Context, control *controlSession, open protocol.Open) {
	pendingHeld := true
	defer func() {
		if pendingHeld {
			release(service.pending)
		}
	}()

	outer, err := service.connectOuter(ctx)
	if err != nil {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return
	}
	defer outer.Close()
	stopClose := context.AfterFunc(ctx, func() { outer.Close() })
	defer stopClose()

	if err := setWriteDeadline(outer, service.config.Limits.Handshake.Value(), service.now); err != nil {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return
	}
	if err := protocol.WriteFrame(outer, protocol.DataJoin{
		Route: service.route, Epoch: open.Epoch, Session: open.Session,
	}); err != nil {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return
	}
	if err := outer.SetWriteDeadline(time.Time{}); err != nil {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
		return
	}

	ready, err := service.serveInner(ctx, outer, func() {
		release(service.pending)
		pendingHeld = false
	})
	if err != nil && !ready {
		_ = control.write(protocol.Cancel{Epoch: open.Epoch, Session: open.Session})
	}
}

// serveInner is the security-critical local-dial gate. The only call to the
// injected local dialer is below a successful explicit inner TLS handshake and
// successful acquisition of an active-session slot.
func (service *Service) serveInner(ctx context.Context, raw net.Conn, enteredActive func()) (bool, error) {
	budgeted := &preAuthConn{Conn: raw, remaining: innerPreAuthByteLimit, limited: true}
	inner := tls.Server(budgeted, service.innerTLS)
	if err := explicitHandshake(ctx, inner, service.config.Limits.Handshake.Value(), service.now); err != nil {
		return false, fmt.Errorf("connector: inner TLS handshake: %w", err)
	}
	budgeted.disableLimit()
	sessionLifetime, err := service.authenticatedSessionLifetime(inner)
	if err != nil {
		return false, err
	}
	clientID, capability, err := service.authenticatedCapabilityClient(inner)
	if err != nil {
		return false, err
	}
	if capability {
		if !service.tryAcquireClientActive(clientID) {
			return false, errNoClientActiveSlot
		}
		defer service.releaseClientActive(clientID)
	}

	if !tryAcquire(service.active) {
		return false, errNoActiveSlot
	}
	defer release(service.active)
	if enteredActive != nil {
		enteredActive()
	}

	dialContext, cancelDial := context.WithTimeout(ctx, service.config.Limits.LocalDial.Value())
	local, err := service.local.DialContext(dialContext, fixedSSHNetwork, fixedSSHTarget)
	cancelDial()
	if err != nil {
		return false, fmt.Errorf("connector: fixed SSH dial: %w", err)
	}
	defer local.Close()
	stopLocal := context.AfterFunc(ctx, func() { local.Close() })
	defer stopLocal()

	if err := setWriteDeadline(inner, service.config.Limits.Handshake.Value(), service.now); err != nil {
		return false, err
	}
	if err := protocol.WriteReady(inner); err != nil {
		return false, fmt.Errorf("connector: write READY: %w", err)
	}
	if err := inner.SetWriteDeadline(time.Time{}); err != nil {
		return false, err
	}

	err = service.copyPair(ctx, inner, local, sessionLifetime)
	return true, err
}

func (service *Service) authenticatedCapabilityClient(inner *tls.Conn) (protocol.ID, bool, error) {
	if !service.capabilityProfile {
		return protocol.ID{}, false, nil
	}
	state := inner.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil || len(state.PeerCertificates[0].DNSNames) != 1 {
		return protocol.ID{}, false, errors.New("connector: authenticated capability identity is missing")
	}
	clientID, _, _, _, err := config.ParseClientCapabilityDNSName(state.PeerCertificates[0].DNSNames[0])
	if err != nil {
		return protocol.ID{}, false, fmt.Errorf("connector: authenticated capability identity: %w", err)
	}
	return clientID, true, nil
}

func (service *Service) tryAcquireClientActive(clientID protocol.ID) bool {
	service.clientActiveMu.Lock()
	defer service.clientActiveMu.Unlock()
	current := service.clientActive[clientID]
	if current >= service.config.Limits.ActivePerClientValue() {
		return false
	}
	service.clientActive[clientID] = current + 1
	return true
}

func (service *Service) releaseClientActive(clientID protocol.ID) {
	service.clientActiveMu.Lock()
	defer service.clientActiveMu.Unlock()
	current := service.clientActive[clientID]
	if current <= 1 {
		delete(service.clientActive, clientID)
		return
	}
	service.clientActive[clientID] = current - 1
}

func (service *Service) authenticatedSessionLifetime(inner *tls.Conn) (time.Duration, error) {
	state := inner.ConnectionState()
	if len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil {
		return 0, errors.New("connector: authenticated inner peer certificate is missing")
	}
	remaining := state.PeerCertificates[0].NotAfter.Sub(service.now())
	if remaining <= 0 {
		return 0, errors.New("connector: authenticated inner peer certificate has expired")
	}
	lifetime := service.config.Limits.SessionLifetimeValue()
	if remaining < lifetime {
		lifetime = remaining
	}
	return lifetime, nil
}

type preAuthConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int64
	limited   bool
}

func (connection *preAuthConn) Read(buffer []byte) (int, error) {
	connection.mu.Lock()
	if !connection.limited {
		connection.mu.Unlock()
		return connection.Conn.Read(buffer)
	}
	if connection.remaining <= 0 {
		connection.mu.Unlock()
		return 0, errInnerByteLimit
	}
	if int64(len(buffer)) > connection.remaining {
		buffer = buffer[:connection.remaining]
	}
	connection.mu.Unlock()

	count, err := connection.Conn.Read(buffer)
	connection.mu.Lock()
	connection.remaining -= int64(count)
	connection.mu.Unlock()
	return count, err
}

func (connection *preAuthConn) disableLimit() {
	connection.mu.Lock()
	connection.limited = false
	connection.remaining = -1
	connection.mu.Unlock()
}

type copyResult struct {
	direction byte
	err       error
}

func (service *Service) copyPair(ctx context.Context, inner *tls.Conn, local net.Conn, lifetime time.Duration) error {
	idle := service.config.Limits.SessionIdleValue()
	if lifetime < idle {
		idle = lifetime
	}
	guard, err := sessionguard.New(
		inner,
		local,
		idle,
		lifetime,
	)
	if err != nil {
		return err
	}
	if err := guard.Arm(); err != nil {
		return err
	}
	results := make(chan copyResult, 2)
	copyOne := func(direction byte, destination io.Writer, source io.Reader) {
		buffer := service.bufferPool.Get().(*[]byte)
		_, err := io.CopyBuffer(destination, guard.Reader(source), *buffer)
		service.bufferPool.Put(buffer)
		results <- copyResult{direction: direction, err: err}
	}
	go copyOne('l', local, inner)
	go copyOne('i', inner, local)

	stop := context.AfterFunc(ctx, func() {
		inner.Close()
		local.Close()
	})
	defer stop()
	first := <-results
	if first.direction == 'l' {
		if closeWriter, ok := local.(interface{ CloseWrite() error }); ok {
			_ = closeWriter.CloseWrite()
		}
	} else {
		_ = inner.CloseWrite()
	}

	drainDeadline := service.now().Add(service.config.Limits.Drain.Value())
	_ = inner.SetDeadline(drainDeadline)
	_ = local.SetDeadline(drainDeadline)
	timer := time.NewTimer(service.config.Limits.Drain.Value())
	defer timer.Stop()
	var second copyResult
	select {
	case second = <-results:
	case <-timer.C:
	case <-ctx.Done():
	}
	_ = inner.Close()
	_ = local.Close()

	if first.err != nil && !closedConnection(first.err) {
		return first.err
	}
	if second.err != nil && !closedConnection(second.err) {
		return second.err
	}
	return nil
}

func closedConnection(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}
