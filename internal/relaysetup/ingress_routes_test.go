package relaysetup

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestProxyRoutesHardenRecognizedExistingRoute(t *testing.T) {
	for _, test := range []struct {
		name, other, old, header string
		edit                     func([]byte, string, int) (RouteEdit, error)
	}{
		{"nginx", "server { listen 443 ssl; server_name other.example; location / { return 200 other; } }\n", "server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection upgrade; } location / { return 200 selected; } }\n", nginxPeerHeader, NginxRouteForPort},
		{"caddy", "other.example {\n respond other\n}\n", "relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19088\n }\n handle {\n respond selected\n }\n}\n", caddyPeerHeader, CaddyRouteForPort},
		{"apache", "<VirtualHost *:443>\n ServerName other.example\n DocumentRoot /srv/other\n</VirtualHost>\n", "<VirtualHost *:443>\n ServerName relay.example\n ProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19088/connects\"\n DocumentRoot /srv/selected\n</VirtualHost>\n", apachePeerBlock, ApacheRouteForPort},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := []byte(test.other + test.old)
			edit, err := test.edit(before, "relay.example", 19088)
			if err != nil || edit.Reused || !edit.Exists || !bytes.Equal(edit.Before, before) || !bytes.HasPrefix(edit.After, []byte(test.other)) || !bytes.Contains(edit.After, []byte(test.header)) {
				t.Fatalf("existing selected route did not receive its original-peer overwrite: %v", err)
			}
			if !bytes.Equal(before, []byte(test.other+test.old)) {
				t.Fatal("route adapter mutated input")
			}
			again, err := test.edit(edit.After, "relay.example", 19088)
			if err != nil || !again.Reused || !again.Exists || !bytes.Equal(again.After, edit.After) {
				t.Fatalf("peer-header reconciliation was not idempotent: %v", err)
			}
		})
	}
}

func TestProxyRoutesRejectUnverifiedPeerHeaderWriters(t *testing.T) {
	for _, test := range []struct {
		name  string
		edit  func([]byte, string, int) (RouteEdit, error)
		input string
	}{
		{"nginx-client-derived", NginxRouteForPort, `server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_set_header OwnTransit-Peer-IP $http_x_forwarded_for; } }`},
		{"nginx-realip-rewritten", NginxRouteForPort, `server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_set_header OwnTransit-Peer-IP $remote_addr; } }`},
		{"nginx-missing-value", NginxRouteForPort, `server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_set_header OwnTransit-Peer-IP; } }`},
		{"nginx-duplicate-case", NginxRouteForPort, `server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_set_header OwnTransit-Peer-IP $realip_remote_addr; proxy_set_header owntransit-peer-ip $realip_remote_addr; } }`},
		{"nginx-uninspected-include", NginxRouteForPort, `server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; include /etc/nginx/other-headers.conf; } }`},
		{"caddy-client-derived", CaddyRouteForPort, "relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19088 {\n header_up OwnTransit-Peer-IP {client_ip}\n }\n }\n}\n"},
		{"caddy-appended", CaddyRouteForPort, "relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19088 {\n header_up +OwnTransit-Peer-IP {remote_host}\n }\n }\n}\n"},
		{"caddy-duplicate-case", CaddyRouteForPort, "relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19088 {\n header_up OwnTransit-Peer-IP {remote_host}\n header_up owntransit-peer-ip {remote_host}\n }\n }\n}\n"},
		{"caddy-malformed", CaddyRouteForPort, "relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19088 {\n header_up OwnTransit-Peer-IP\n }\n }\n}\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			edit, err := test.edit([]byte(test.input), "relay.example", 19088)
			if !errors.Is(err, ErrRoute) || edit.Reused || len(edit.After) != 0 {
				t.Fatal("unverified private-hop header was accepted")
			}
		})
	}
	base := "<VirtualHost *:443>\n ServerName relay.example\n ProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19088/connects\"\n" + apachePeerBlock + "</VirtualHost>\n"
	for _, input := range []string{
		strings.Replace(base, "CONN_REMOTE_ADDR", "REMOTE_ADDR", 1),
		strings.Replace(base, "RequestHeader unset", "RequestHeader add", 1),
		strings.Replace(base, `"expr=%{CONN_REMOTE_ADDR}"`, `"expr=%{HTTP:X-Forwarded-For}"`, 1),
		strings.Replace(base, "RequestHeader unset "+proxyPeerHeader, "RequestHeader unset "+proxyPeerHeader+"\n RequestHeader unset owntransit-peer-ip", 1),
		strings.Replace(base, apachePeerBlock, apachePeerBlock+apachePeerBlock, 1),
		strings.Replace(base, apachePeerBlock, "\n RequestHeader set OwnTransit-Peer-IP 192.0.2.1\n"+apachePeerBlock, 1),
		strings.Replace(base, `RequestHeader set Connection "upgrade"`, `RequestHeader set Connection "expr=%{HTTP:Connection}"`, 1),
		strings.Replace(base, `RequestHeader set Connection "upgrade"`, "", 1),
		strings.Replace(base, apachePeerBlock, apachePeerBlock+"\n requestheader set connection \"expr=%{HTTP:Connection}\"\n", 1),
	} {
		if edit, err := ApacheRouteForPort([]byte(input), "relay.example", 19088); !errors.Is(err, ErrRoute) || edit.Reused || len(edit.After) != 0 {
			t.Fatal("unverified Apache private-hop header was accepted")
		}
	}
}

func TestNginxPeerHeaderKeepsInheritedCarrierHeaders(t *testing.T) {
	before := []byte(`http { proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection upgrade; server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://127.0.0.1:19088/connects; } } }`)
	edit, err := NginxRouteForPort(before, "relay.example", 19088)
	if err != nil || edit.Reused || !edit.Exists || !bytes.Contains(edit.After, []byte(nginxCarrierHeaders)) || !bytes.Contains(edit.After, []byte(nginxPeerHeader)) {
		t.Fatal("first local proxy header lost the inherited WebSocket upgrade contract", err)
	}
	if again, err := NginxRouteForPort(edit.After, "relay.example", 19088); err != nil || !again.Reused || !bytes.Equal(again.After, edit.After) {
		t.Fatal("inherited WebSocket header reconciliation was not idempotent", err)
	}
}
