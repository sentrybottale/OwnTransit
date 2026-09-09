package relaysetup

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

var portRouteAdapters = []struct {
	name    string
	legacy  func([]byte, string) (RouteEdit, error)
	forPort func([]byte, string, int) (RouteEdit, error)
	first   string
	second  string
	alias   string
}{
	{
		name: "nginx", legacy: NginxRoute, forPort: NginxRouteForPort,
		first:  "server { listen 443 ssl; server_name first.example; location / { try_files $uri /index.html; } }\n",
		second: "server { listen 443 ssl; server_name second.example; location / { try_files $uri /index.html; } }\n",
		alias:  "server { listen 443 ssl; server_name first.example second.example; }\n",
	},
	{
		name: "caddy", legacy: CaddyRoute, forPort: CaddyRouteForPort,
		first:  "first.example {\n handle {\n file_server\n }\n}\n",
		second: "second.example {\n handle {\n file_server\n }\n}\n",
		alias:  "first.example, second.example {\n handle {\n file_server\n }\n}\n",
	},
	{
		name: "apache", legacy: ApacheRoute, forPort: ApacheRouteForPort,
		first:  "<VirtualHost *:443>\n ServerName first.example\n DocumentRoot /srv/first\n</VirtualHost>\n",
		second: "<VirtualHost *:443>\n ServerName second.example\n DocumentRoot /srv/second\n</VirtualHost>\n",
		alias:  "<VirtualHost *:443>\n ServerName first.example\n ServerAlias second.example\n</VirtualHost>\n",
	},
}

func TestAllAdaptersClassifyOnlyDefiniteLoopbackPortConflicts(t *testing.T) {
	for _, adapter := range portRouteAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			first, err := adapter.forPort([]byte(adapter.alias), "first.example", 19087)
			if err != nil {
				t.Fatal(err)
			}
			for _, hostname := range []string{"first.example", "second.example"} {
				if _, err := adapter.forPort(first.After, hostname, 19088); !errors.Is(err, ErrRoutePortConflict) || !errors.Is(err, ErrRoute) {
					t.Fatalf("definite aliased port conflict was not classified: %v", err)
				}
			}
			for _, target := range []string{"other.example:19087", "127.0.0.1:$port", "127.0.0.1:019087", "127.0.0.1:65536"} {
				unsafe := bytes.ReplaceAll(first.After, []byte("127.0.0.1:19087"), []byte(target))
				if _, err := adapter.forPort(unsafe, "first.example", 19088); !errors.Is(err, ErrRoute) || errors.Is(err, ErrRoutePortConflict) {
					t.Fatal("unknown/dynamic target became a recoverable port conflict")
				}
			}
		})
	}
}

func TestOtherAdaptersDoNotClassifyAmbiguousRoutesAsPortConflicts(t *testing.T) {
	for _, input := range []string{
		"relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19087\n reverse_proxy 127.0.0.1:19088\n }\n}\n",
		"relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19087\n }\n handle /connects {\n reverse_proxy 127.0.0.1:19088\n }\n}\n",
		"relay.example {\n handle /connects {\n reverse_proxy 127.0.0.1:19087\n }\n handle /connects* {\n respond blocked\n }\n}\n",
		"relay.example {\n @other {\n path /connects\n }\n handle /connects {\n reverse_proxy 127.0.0.1:19087\n }\n}\n",
		"relay.example {\n route {\n handle {\n rewrite * /connects\n }\n }\n handle /connects {\n reverse_proxy 127.0.0.1:19087\n }\n}\n",
	} {
		if _, err := CaddyRouteForPort([]byte(input), "relay.example", 19089); !errors.Is(err, ErrRoute) || errors.Is(err, ErrRoutePortConflict) {
			t.Fatal("ambiguous Caddy route became a port conflict")
		}
	}
	for _, content := range []string{
		"ProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19087/connects\"\nProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19088/connects\"",
		"<If true>\nProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19087/connects\"\n</If>",
		"ProxyPassMatch \"^/connects$\" \"ws://127.0.0.1:19087/connects\"\nRedirect /connects https://other.example",
	} {
		input := []byte("<VirtualHost *:443>\nServerName relay.example\n" + content + "\n</VirtualHost>\n")
		if _, err := ApacheRouteForPort(input, "relay.example", 19089); !errors.Is(err, ErrRoute) || errors.Is(err, ErrRoutePortConflict) {
			t.Fatal("ambiguous Apache route became a port conflict")
		}
	}
}

func TestRoutePortsPreserveIndependentSitesAndDefault(t *testing.T) {
	for _, adapter := range portRouteAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			input := []byte(adapter.first + adapter.second)
			legacy, err := adapter.legacy(input, "first.example")
			if err != nil {
				t.Fatal(err)
			}
			defaultPort, err := adapter.forPort(input, "first.example", 9087)
			if err != nil || !bytes.Equal(defaultPort.After, legacy.After) || defaultPort.Reused != legacy.Reused {
				t.Fatalf("default route changed: %v", err)
			}
			first, err := adapter.forPort(input, "first.example", 19087)
			if err != nil || first.Reused || !bytes.HasSuffix(first.After, []byte(adapter.second)) {
				t.Fatalf("first route changed the second site: %v", err)
			}
			firstSite := append([]byte(nil), first.After[:len(first.After)-len(adapter.second)]...)
			second, err := adapter.forPort(first.After, "second.example", 19088)
			if err != nil || second.Reused || !bytes.HasPrefix(second.After, firstSite) {
				t.Fatalf("second route changed the first site: %v", err)
			}
			for hostname, port := range map[string]int{"first.example": 19087, "second.example": 19088} {
				again, err := adapter.forPort(second.After, hostname, port)
				if err != nil || !again.Reused || !bytes.Equal(again.After, second.After) {
					t.Fatalf("selected route was not reused exactly: %v", err)
				}
				upstream := []byte(fmt.Sprintf("127.0.0.1:%d", port))
				if bytes.Count(second.After, upstream) != 1 {
					t.Fatalf("missing or duplicate selected loopback upstream %s", upstream)
				}
			}
			if !bytes.Equal(input, []byte(adapter.first+adapter.second)) {
				t.Fatal("adapter mutated input")
			}
		})
	}
}

func TestRoutePortsRejectWrongPortAndAliasedSite(t *testing.T) {
	for _, adapter := range portRouteAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			for _, input := range []string{adapter.first, adapter.alias} {
				first, err := adapter.forPort([]byte(input), "first.example", 19087)
				if err != nil {
					t.Fatal(err)
				}
				before := append([]byte(nil), first.After...)
				for _, hostname := range []string{"first.example", "second.example"} {
					edit, err := adapter.forPort(first.After, hostname, 19088)
					if err == nil || edit.Reused || len(edit.After) != 0 || !bytes.Equal(first.After, before) {
						t.Fatalf("another instance's route was selected or rewritten for %s", hostname)
					}
				}
			}
		})
	}
}

func TestRoutePortsRejectInvalidBoundsBeforeEditing(t *testing.T) {
	for _, adapter := range portRouteAdapters {
		t.Run(adapter.name, func(t *testing.T) {
			input := []byte(adapter.first)
			for _, port := range []int{-1, 0, 1, 1023, 65536, 1 << 30} {
				edit, err := adapter.forPort(input, "first.example", port)
				if err == nil || edit.Reused || len(edit.Before) != 0 || len(edit.After) != 0 || !bytes.Equal(input, []byte(adapter.first)) {
					t.Fatalf("invalid port %d produced an edit", port)
				}
			}
			for _, port := range []int{1024, 65535} {
				edit, err := adapter.forPort(input, "first.example", port)
				if err != nil || !bytes.Contains(edit.After, []byte(fmt.Sprintf("127.0.0.1:%d", port))) {
					t.Fatalf("valid boundary port %d rejected: %v", port, err)
				}
			}
		})
	}
}
