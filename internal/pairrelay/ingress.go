package pairrelay

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ProxyPeerHeader belongs only to the private HTTP hop from the selected
// reverse proxy. Managed routes overwrite it with the original TCP peer.
// It selects an availability bucket, never TLS, route or endpoint authority.
const ProxyPeerHeader = "OwnTransit-Peer-IP"

// IngressMode is selected by the local relay integration, never by a request.
// The private-bridge mode is only for the loopback-published relay container.
type IngressMode uint8

const (
	IngressDirect IngressMode = iota
	IngressLoopbackProxy
	IngressPrivateProxy
)

func (relay *Relay) admissionPeer(request *http.Request) (string, bool) {
	if relay == nil || request == nil {
		return "", false
	}
	if relay.config.Ingress == IngressDirect {
		// Ordinary forwarding headers, including the private-hop header on a
		// direct listener, cannot select another client's quota.
		return request.RemoteAddr, true
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return "", false
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return "", false
	}
	peer = peer.Unmap()
	if !peer.IsLoopback() && !(relay.config.Ingress == IngressPrivateProxy && peer.IsPrivate()) {
		return "", false
	}
	if relay.config.Ingress != IngressLoopbackProxy && relay.config.Ingress != IngressPrivateProxy {
		return "", false
	}
	var values []string
	keys := 0
	for key, next := range request.Header {
		if strings.EqualFold(key, ProxyPeerHeader) {
			keys++
			values = append(values, next...)
		}
	}
	if keys == 0 {
		// Old selected routes still work with their original shared bucket.
		// Managed setup upgrades the route before claiming source fairness.
		return request.RemoteAddr, true
	}
	if keys != 1 || len(values) != 1 || len(values[0]) > 39 {
		return "", false
	}
	original, err := netip.ParseAddr(values[0])
	if err != nil || original.Zone() != "" || original.String() != values[0] {
		return "", false
	}
	// Dual-stack proxies can render an IPv4 TCP peer as an IPv4-mapped IPv6
	// address. Both forms must spend the same IPv4 bucket.
	original = original.Unmap()
	if original.IsUnspecified() || original.IsMulticast() {
		return "", false
	}
	return net.JoinHostPort(original.String(), "0"), true
}
