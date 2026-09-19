//go:build darwin || linux

package pairruntime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/transport"
)

// Fault injection is local to real WebSocket/mTLS/SSH fixtures. No live host,
// host firewall, protocol check or production timer is modified.
type outageDialer struct {
	mu          sync.Mutex
	dial        pairrelay.DialFunc
	offline     bool
	failures    int
	connections []net.Conn
}

func (d *outageDialer) connect(ctx context.Context, url string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.offline {
		d.failures++
		return nil, pairrelay.ErrTransport
	}
	c, err := d.dial(ctx, url)
	if err == nil {
		d.connections = append(d.connections, c)
	}
	return c, err
}
func (d *outageDialer) disconnect() {
	d.mu.Lock()
	d.offline = true
	connections := d.connections
	d.connections = nil
	d.mu.Unlock()
	for _, c := range connections {
		_ = transport.Abort(c)
	}
}
func (d *outageDialer) reconnect() {
	d.mu.Lock()
	d.offline = false
	d.mu.Unlock()
}
func (d *outageDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.failures
}

func TestNetworkDisconnectRecoversWithoutTargetRestartOrNewIdentity(t *testing.T) {
	f := newIntegrated(t)
	network := &outageDialer{dial: f.dial}
	f.dial = network.connect
	stop, done := f.start(t)
	defer stop()
	f.pair(t)
	f.assertSSH(t)
	identity := func() clientRecord {
		root, err := securefs.OpenRoot(f.clientPath)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s, err := readClient(root)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := identity()
	for cycle := 0; cycle < 2; cycle++ {
		old, release := f.open(t)
		network.disconnect()
		select {
		case <-old.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("broken old session stayed open")
		}
		release()
		initialFailures := network.count()
		eventually(t, func() bool { return network.count() > initialFailures })
		// Two Target loops may retry, but neither may hammer admission at 5Hz.
		startFailures := network.count()
		time.Sleep(2200 * time.Millisecond)
		if network.count()-startFailures > 6 {
			t.Fatal("outage caused a rapid reconnect loop")
		}
		select {
		case <-done:
			t.Fatal("network loss exited Target worker")
		default:
		}
		network.reconnect()
		f.assertSSH(t) // Same worker and pairing, fresh authenticated SSH stream.
		if _, err := old.Write([]byte("must not replay")); err == nil {
			t.Fatal("old carrier revived")
		}
	}
	after := identity()
	if !bytes.Equal(before.Pairing, after.Pairing) || !bytes.Equal(before.Keys.Outer, after.Keys.Outer) || !bytes.Equal(before.Keys.Inner, after.Keys.Inner) || before.Origin != after.Origin {
		t.Fatal("network recovery changed client identity")
	}
	for _, path := range []string{f.clientPath, f.serverPath} {
		p, err := ReadPolicy(path)
		if err != nil || p.Locked {
			t.Fatal("network loss created an alarm")
		}
	}
	// An explicit alarm during an outage still terminates the worker. Restoring
	// networking must not turn the alarm into a recoverable connectivity event.
	network.disconnect()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := SetLocked(ctx, f.serverPath, true, true); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("alarm blocked behind retry")
	}
	network.reconnect()
	if p, err := ReadPolicy(f.serverPath); err != nil || !p.Locked {
		t.Fatal("alarm lost after reconnect")
	}
	if _, err := Admission(f.serverPath); err == nil {
		t.Fatal("alarm admitted reconnect")
	}
}

func TestClientRateLimitWaitRetainsPairingAndCanBeCancelled(t *testing.T) {
	f := newIntegrated(t)
	stop, _ := f.start(t)
	defer stop()
	f.pair(t)
	var attempts int
	dial := func(context.Context, string) (net.Conn, error) { attempts++; return nil, pairrelay.ErrRateLimited }
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c, release, err := OpenClient(ctx, f.clientPath, dial)
	if c != nil || release != nil || !errors.Is(err, pairrelay.ErrRateLimited) || attempts != 1 {
		t.Fatalf("429 wait failed to bound/cancel attempts: %d, %v", attempts, err)
	}
	if p, err := ReadPolicy(f.clientPath); err != nil || p.Locked {
		t.Fatal("rate limit created alarm")
	}
	f.assertSSH(t)
}

func TestPairedTargetStartsOfflineAndRecoversWithoutAnotherRestart(t *testing.T) {
	f := newIntegrated(t)
	network := &outageDialer{dial: f.dial}
	f.dial = network.connect
	stop, done := f.start(t)
	f.pair(t)
	stopShortFixture(t, stop, done)
	network.disconnect()
	stop, done = f.start(t)
	defer stop()
	eventually(t, func() bool { return network.count() > 0 })
	select {
	case <-done:
		t.Fatal("offline startup exited the retained Target")
	default:
	}
	network.reconnect()
	f.assertSSH(t)
}

func TestClientOpeningDeadlineDoesNotKillPromotedStream(t *testing.T) {
	f := newIntegrated(t)
	stop, _ := f.start(t)
	defer stop()
	f.pair(t)
	f.assertSSH(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, release, err := openClient(ctx, f.clientPath, f.dial, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	defer c.Close()
	time.Sleep(2200 * time.Millisecond)
	select {
	case <-c.Done():
		t.Fatal("opening deadline killed promoted connection")
	default:
	}
	// A bounded opening failure reports timeout, not a fictitious user cancel.
	dial := func(context.Context, string) (net.Conn, error) { return nil, pairrelay.ErrTransport }
	failed, closeFailed, err := openClient(ctx, f.clientPath, dial, 50*time.Millisecond)
	if failed != nil || closeFailed != nil || !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatal("opening timeout was misclassified", err)
	}
}
