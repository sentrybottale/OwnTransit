//go:build darwin || linux

package pairruntime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

const exporterLabel = "EXPORTER-OwnTransit-paired-lease-v1"

var leafFromDER = x509.ParseCertificate

// authenticate performs fresh inner mTLS before creating any authorization
// lease. The exporter binds grants to this exact TLS session and route.
func authenticate(ctx context.Context, raw net.Conn, profile *tls.Config, scope Scope, receiver bool, policy leasewire.Options) (*leasewire.Conn, error) {
	if ctx == nil || raw == nil || profile == nil {
		return nil, ErrState
	}
	if _, _, _, err := scope.ids(); err != nil {
		raw.Close()
		return nil, err
	}
	if profile.MinVersion != tls.VersionTLS13 || profile.MaxVersion != tls.VersionTLS13 || profile.InsecureSkipVerify || profile.VerifyConnection == nil || len(profile.NextProtos) != 1 || profile.NextProtos[0] != leasewire.ALPN || !profile.SessionTicketsDisabled || profile.ClientSessionCache != nil {
		raw.Close()
		return nil, ErrState
	}
	t := tls.Client(raw, profile)
	local, peer := scope.ClientID, scope.ReceiverID
	if receiver {
		if profile.ClientAuth != tls.RequireAndVerifyClientCert {
			raw.Close()
			return nil, ErrState
		}
		t = tls.Server(raw, profile)
		local, peer = peer, local
	}
	handshake, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := t.HandshakeContext(handshake)
	cancel()
	if err != nil {
		raw.Close()
		return nil, err
	}
	state := t.ConnectionState()
	if state.DidResume || state.NegotiatedProtocol != leasewire.ALPN || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		raw.Close()
		return nil, ErrState
	}
	binding, err := state.ExportKeyingMaterial(exporterLabel, []byte(scope.RouteID), 32)
	if err != nil {
		raw.Close()
		return nil, err
	}
	l, err := leasewire.Wrap(ctx, t, leasewire.Context{PairID: scope.RouteID, LocalID: local, PeerID: peer, SessionBinding: binding}, policy)
	if err != nil {
		raw.Close()
		return nil, err
	}
	// Active credential expiry is independent of application IO and lease renewal.
	expires := state.PeerCertificates[0].NotAfter
	for _, cert := range profile.Certificates {
		if len(cert.Certificate) == 0 {
			l.Close()
			return nil, ErrState
		}
		own, err := leafFromDER(cert.Certificate[0])
		if err != nil {
			l.Close()
			return nil, err
		}
		if own.NotAfter.Before(expires) {
			expires = own.NotAfter
		}
	}
	go func() {
		timer := time.NewTimer(time.Until(expires))
		defer timer.Stop()
		select {
		case <-timer.C:
			l.Close()
		case <-l.Done():
		}
	}()
	readyCtx, readyCancel := context.WithTimeout(ctx, 10*time.Second)
	defer readyCancel()
	if err := l.WaitReady(readyCtx); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

func ClientSession(ctx context.Context, raw net.Conn, profile *tls.Config, scope Scope, policy leasewire.Options) (*leasewire.Conn, error) {
	l, err := authenticate(ctx, raw, profile, scope, false, policy)
	if err != nil {
		return nil, err
	}
	_ = l.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.ReadReady(l); err != nil {
		l.Close()
		return nil, err
	}
	_ = l.SetReadDeadline(time.Time{})
	return l, nil
}

// ServeSession never accepts a target from a caller, configuration or the wire.
func ServeSession(ctx context.Context, raw net.Conn, profile *tls.Config, scope Scope, policy leasewire.Options) error {
	return serveSession(ctx, raw, profile, scope, policy, (&net.Dialer{Timeout: 5 * time.Second}).DialContext)
}

func serveSession(ctx context.Context, raw net.Conn, profile *tls.Config, scope Scope, policy leasewire.Options, dial func(context.Context, string, string) (net.Conn, error)) error {
	l, err := authenticate(ctx, raw, profile, scope, true, policy)
	if err != nil {
		return err
	}
	defer l.Close()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	go func() {
		select {
		case <-l.Done():
			cancel()
		case <-dialCtx.Done():
		}
	}()
	ssh, err := dial(dialCtx, "tcp4", config.ConnectorSSHTarget)
	if err != nil {
		return err
	}
	defer ssh.Close()
	go func() { <-l.Done(); ssh.Close() }()
	// Recheck after the dial; a lock may have won while the dial was completing.
	if err := l.WaitReady(ctx); err != nil {
		return err
	}
	_ = l.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := protocol.WriteReady(l); err != nil {
		return err
	}
	_ = l.SetWriteDeadline(time.Time{})
	return CopyStream(l, ssh, ssh)
}

// CopyStream ends the old carrier on either copy completion or cancellation.
// It never reconnects or replays bytes. The caller retains ownership of its
// input/output (normally OpenSSH's pipes).
func CopyStream(carrier *leasewire.Conn, input io.Reader, output io.Writer) error {
	defer carrier.Close()
	finished := make(chan error, 2)
	go func() { _, err := io.Copy(carrier, input); finished <- err }()
	go func() { _, err := io.Copy(output, carrier); finished <- err }()
	select {
	case err := <-finished:
		return err
	case <-carrier.Done():
		return carrier.Err()
	}
}
