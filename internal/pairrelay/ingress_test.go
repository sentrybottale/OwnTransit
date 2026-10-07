package pairrelay

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestProxyAdmissionMetadataIsBoundedAndPrivate(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   IngressMode
		remote string
		header http.Header
		want   string
	}{
		{"direct ignores metadata", IngressDirect, "192.0.2.1:1234", http.Header{ProxyPeerHeader: {"198.51.100.1"}}, "192.0.2.1:1234"},
		{"old route keeps shared bucket", IngressLoopbackProxy, "127.0.0.1:1234", nil, "127.0.0.1:1234"},
		{"ordinary forwarding ignored", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{"X-Forwarded-For": {"198.51.100.1"}}, "127.0.0.1:1234"},
		{"canonical IPv4", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1"}}, "192.0.2.1:0"},
		{"canonical IPv6", IngressLoopbackProxy, "[::1]:1234", http.Header{ProxyPeerHeader: {"2001:db8::1"}}, "[2001:db8::1]:0"},
		{"container bridge", IngressPrivateProxy, "10.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1"}}, "192.0.2.1:0"},
		{"public immediate peer", IngressPrivateProxy, "192.0.2.1:1234", http.Header{ProxyPeerHeader: {"198.51.100.1"}}, ""},
		{"native private peer", IngressLoopbackProxy, "10.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1"}}, ""},
		{"duplicate values", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1", "198.51.100.1"}}, ""},
		{"duplicate casing", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1"}, "owntransit-peer-ip": {"198.51.100.1"}}, ""},
		{"address list", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1,198.51.100.1"}}, ""},
		{"port", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"192.0.2.1:443"}}, ""},
		{"whitespace", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {" 192.0.2.1"}}, ""},
		{"mapped IPv4 shares IPv4 identity", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"::ffff:192.0.2.1"}}, "192.0.2.1:0"},
		{"noncanonical mapped IPv4", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"::ffff:c000:201"}}, ""},
		{"noncanonical IPv6", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"2001:0db8::1"}}, ""},
		{"zone", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"fe80::1%eth0"}}, ""},
		{"unspecified", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"0.0.0.0"}}, ""},
		{"multicast", IngressLoopbackProxy, "127.0.0.1:1234", http.Header{ProxyPeerHeader: {"ff02::1"}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			relay := &Relay{config: RelayConfig{Ingress: test.mode}}
			peer, ok := relay.admissionPeer(&http.Request{RemoteAddr: test.remote, Header: test.header})
			if ok != (test.want != "") || peer != test.want {
				t.Fatalf("admission peer = %q, %v; want %q", peer, ok, test.want)
			}
		})
	}
}

func TestMappedProxyPeerCannotDoubleItsQuota(t *testing.T) {
	relay := &Relay{config: RelayConfig{Ingress: IngressLoopbackProxy}}
	now := time.Now()
	for index := range 9 {
		ip := "192.0.2.1"
		if index%2 == 1 {
			ip = "::ffff:192.0.2.1"
		}
		peer, ok := relay.admissionPeer(&http.Request{RemoteAddr: "127.0.0.1:1234", Header: http.Header{ProxyPeerHeader: {ip}}})
		if !ok {
			t.Fatal("valid dual-stack proxy peer rejected")
		}
		release, admitted := relay.admission.acquire(peer, now)
		if admitted != (index < 8) {
			t.Fatal("mapped address changed the source quota")
		}
		if admitted {
			defer release()
		}
	}
}

// The two clients have distinct real loopback source addresses, but both
// arrive at the relay through the same reverse-proxy TCP address. The proxy
// overwrites even a client-supplied private-hop header before forwarding.
func TestProxyStalledPeerCannotBlockAnotherPeer(t *testing.T) {
	for _, mode := range []IngressMode{IngressDirect, IngressLoopbackProxy} {
		t.Run(map[IngressMode]string{IngressDirect: "original shared bucket reproduces outage", IngressLoopbackProxy: "source buckets preserve other client"}[mode], func(t *testing.T) {
			fixture := newRelayFixture(t)
			fixture.relay.config.Ingress = mode
			defer fixture.relay.Close()
			backend := httptest.NewServer(fixture.relay)
			defer backend.Close()
			upstream, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(upstream)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				host, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					http.Error(w, "bad peer", http.StatusBadRequest)
					return
				}
				r.Header.Del(ProxyPeerHeader)
				r.Header.Set(ProxyPeerHeader, host)
				proxy.ServeHTTP(w, r)
			}))
			defer front.Close()
			client := func(ip string) *http.Client {
				transport := &http.Transport{DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}).DialContext}
				t.Cleanup(transport.CloseIdleConnections)
				return &http.Client{Transport: transport}
			}
			attacker := client("127.0.0.2")
			legitimate := client("127.0.0.3")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			dial := func(client *http.Client) (*websocket.Conn, *http.Response, error) {
				return websocket.Dial(ctx, front.URL+Path, &websocket.DialOptions{HTTPClient: client, Subprotocols: []string{WebSocketSubprotocol}, HTTPHeader: http.Header{ProxyPeerHeader: {"127.0.0.3"}, "X-Forwarded-For": {"127.0.0.3"}}})
			}
			for range 8 {
				ws, _, err := dial(attacker)
				if err != nil {
					t.Fatal(err)
				}
				defer ws.CloseNow()
			}
			ws, response, err := dial(attacker)
			if err == nil {
				ws.CloseNow()
				t.Fatal("source exceeded eight stalled connections")
			}
			if response == nil || response.StatusCode != http.StatusTooManyRequests {
				t.Fatal("wrong source quota rejection")
			}
			ws, response, err = dial(legitimate)
			if mode == IngressDirect {
				if err == nil {
					ws.CloseNow()
					t.Fatal("original shared bucket did not reproduce outage")
				}
				if response == nil || response.StatusCode != http.StatusTooManyRequests {
					t.Fatal("wrong original shared quota rejection")
				}
				return
			}
			if err != nil {
				t.Fatal("second source was blocked by stalled first source:", err)
			}
			defer ws.CloseNow()
			stream := websocket.NetConn(ctx, ws, websocket.MessageBinary)
			if err := writeWireFrame(stream, kindFetchServerInfo, nil, 0); err != nil {
				t.Fatal(err)
			}
			frame, err := readWireFrame(stream, maxServerInfoBytes)
			if err != nil || frame.kind != kindServerInfo {
				t.Fatal("legitimate public operation failed:", err)
			}
		})
	}
}
