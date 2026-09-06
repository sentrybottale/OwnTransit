package pairrelay

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestPendingWaiterExpiryAndClaimedOwnership(t *testing.T) {
	for _, pairing := range []bool{false, true} {
		for _, ending := range []string{"pending-expiry", "finished", "relay-close"} {
			t.Run(ending+map[bool]string{false: "-runtime", true: "-pairing"}[pairing], func(t *testing.T) {
				f := newRelayFixture(t)
				defer f.relay.Close()
				local, remote := net.Pipe()
				defer local.Close()
				defer remote.Close()
				key := routeKey{receiver: f.descriptor.ReceiverID, route: f.descriptor.RouteID}
				claims := TokenClaims{ReceiverID: key.receiver, RouteID: key.route, Limits: RouteLimits{PendingPairings: 1, PendingCarriers: 1}}
				leg := &waitingLeg{connection: local, claims: claims, expires: time.Now().Add(50 * time.Millisecond), done: make(chan error, 1)}
				if err := f.relay.enqueueLeg(key, leg, pairing); err != nil {
					t.Fatal(err)
				}
				if ending != "pending-expiry" {
					if got, err := f.relay.takeLeg(key, pairing, claims); err != nil || got != leg {
						t.Fatal("leg was not promoted")
					}
				}
				done := make(chan error, 1)
				go func() { done <- f.relay.waitLeg(key, leg, pairing) }()
				if ending == "pending-expiry" {
					select {
					case err := <-done:
						if !errors.Is(err, ErrUnavailable) {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("pending waiter did not expire")
					}
				} else {
					select {
					case <-done:
						t.Fatal("pending timer terminated claimed connection")
					case <-time.After(100 * time.Millisecond):
					}
					want := error(io.EOF)
					if ending == "finished" {
						f.relay.finishLeg(leg, nil)
					} else {
						f.relay.Close()
						want = ErrAlreadyClosed
					}
					select {
					case err := <-done:
						if !errors.Is(err, want) {
							t.Fatal(err)
						}
					case <-time.After(time.Second):
						t.Fatal("claimed waiter did not release")
					}
				}
				f.relay.mu.Lock()
				defer f.relay.mu.Unlock()
				if f.relay.runtimePending != 0 || f.relay.pairingPending != 0 || len(f.relay.runtimePerRoute) != 0 || len(f.relay.pairingPerRoute) != 0 {
					t.Fatal("pending capacity leaked")
				}
			})
		}
	}
}

func TestWaiterPromotionAndExpiryAreExclusive(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	key := routeKey{receiver: f.descriptor.ReceiverID, route: f.descriptor.RouteID}
	claims := TokenClaims{ReceiverID: key.receiver, RouteID: key.route, Limits: RouteLimits{PendingCarriers: 1}}
	for n := 0; n < 100; n++ {
		local, remote := net.Pipe()
		leg := &waitingLeg{connection: local, claims: claims, expires: time.Now().Add(time.Minute), done: make(chan error, 1)}
		if err := f.relay.enqueueLeg(key, leg, false); err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var removed bool
		var claimed *waitingLeg
		go func() { defer wg.Done(); <-start; removed = f.relay.removeLeg(key, leg, false) }()
		go func() { defer wg.Done(); <-start; claimed, _ = f.relay.takeLeg(key, false, claims) }()
		close(start)
		wg.Wait()
		local.Close()
		remote.Close()
		if removed == (claimed != nil) {
			t.Fatal("promotion and expiry did not have exactly one owner")
		}
	}
}

func TestPromotedSessionRetainsTokenAndLifetimeBounds(t *testing.T) {
	f := newRelayFixture(t)
	defer f.relay.Close()
	first := TokenClaims{ExpiresUnix: f.now.Add(time.Hour).Unix(), Limits: RouteLimits{SessionLifetime: time.Hour}}
	second := first
	second.Limits.SessionLifetime = time.Minute
	if got := f.relay.sessionExpiry(first, second); !got.Equal(f.now.Add(time.Minute)) {
		t.Fatal("promotion ignored per-route session lifetime")
	}
	second.ExpiresUnix = f.now.Add(10 * time.Second).Unix()
	if got := f.relay.sessionExpiry(first, second); !got.Equal(time.Unix(second.ExpiresUnix, 0)) {
		t.Fatal("promotion extended token validity")
	}
}
