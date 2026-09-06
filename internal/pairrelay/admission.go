package pairrelay

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

const maxAdmissionPeers = 256

type admissionPeer struct {
	tokens            float64
	updated, timeSeen time.Time
	active            int
}
type admissionGuard struct {
	mu     sync.Mutex
	peers  map[netip.Addr]*admissionPeer
	global admissionPeer
	active int
}

func refill(p *admissionPeer, now time.Time, rate, burst float64) {
	if p.updated.IsZero() {
		p.tokens = burst
	} else {
		p.tokens = min(burst, p.tokens+max(0, now.Sub(p.updated).Seconds())*rate)
	}
	p.updated = now
}

// Only the actual TCP peer is used. Behind a reverse proxy/NAT its clients
// share a bucket; spoofable forwarding headers never create quota identities.
func (a *admissionGuard) acquire(remote string, now time.Time) (func(), bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return nil, false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return nil, false
	}
	ip = ip.Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.peers == nil {
		a.peers = make(map[netip.Addr]*admissionPeer)
	}
	refill(&a.global, now, 64, 128)
	if a.active >= 32 || a.global.tokens < 1 {
		return nil, false
	}
	p := a.peers[ip]
	if p == nil {
		for k, v := range a.peers {
			if v.active == 0 && now.Sub(v.timeSeen) > time.Minute {
				delete(a.peers, k)
			}
		}
		if len(a.peers) >= maxAdmissionPeers {
			return nil, false
		}
		p = &admissionPeer{}
		a.peers[ip] = p
	}
	refill(p, now, 16, 64)
	p.timeSeen = now
	if p.active >= 8 || p.tokens < 1 {
		return nil, false
	}
	p.tokens--
	a.global.tokens--
	p.active++
	a.active++
	var once sync.Once
	return func() { once.Do(func() { a.mu.Lock(); defer a.mu.Unlock(); p.active--; a.active-- }) }, true
}

type admissionConnection struct {
	net.Conn
	release func()
}

func releaseAdmission(c net.Conn) {
	if a, ok := c.(*admissionConnection); ok {
		a.release()
	}
}
