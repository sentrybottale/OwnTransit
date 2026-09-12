package pairrelay

import (
	"context"
	"net"
	"time"

	"github.com/sentrybottale/owntransit/internal/transport"
)

// The transport retains the service/session context, not a short-lived dial
// context. A separate pending guard bounds preface, outer TLS and READY reads,
// including silent peers and partial-frame trickling. It grants no authority.
type pendingOpen struct {
	raw      net.Conn
	deadline time.Time
	timer    *time.Timer
}

func guardPendingOpen(ctx context.Context, raw net.Conn, budget time.Duration) (*pendingOpen, error) {
	if budget <= 0 {
		return nil, ErrProtocol
	}
	deadline := time.Now().Add(budget)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := raw.SetDeadline(deadline); err != nil {
		return nil, ErrUnavailable
	}
	p := &pendingOpen{raw: raw, deadline: deadline}
	// Abort the underlying carrier, never a TLS graceful-close handshake.
	p.timer = time.AfterFunc(time.Until(deadline), func() { _ = transport.Abort(raw) })
	return p, nil
}

func (p *pendingOpen) promote() error {
	// Stop must win before handing the connection to inner TLS/SSH. If the timer
	// already fired, do not return a connection it could asynchronously close.
	if !p.timer.Stop() || !time.Now().Before(p.deadline) {
		_ = transport.Abort(p.raw)
		return ErrPendingTimeout
	}
	if err := p.raw.SetDeadline(time.Time{}); err != nil {
		_ = transport.Abort(p.raw)
		return ErrUnavailable
	}
	return nil
}
