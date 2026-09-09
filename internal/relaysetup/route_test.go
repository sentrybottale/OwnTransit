package relaysetup

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestURLSelectsOnlyPublicHTTPSConnects(t *testing.T) {
	for _, in := range []string{"relay.example", "https://relay.example/connects", "wss://relay.example/connects", "https://RELAY.example:443"} {
		out, e := PublicURL(in)
		if e != nil || out != "wss://relay.example/connects" {
			t.Fatalf("%q => %q, %v", in, out, e)
		}
	}
	for _, in := range []string{"", "http://relay.example", "wss://user:pass@relay.example/connects", "wss://127.0.0.1/connects", "wss://relay.example:8443/connects", "wss://relay.example/admin", "wss://relay.example/connects?secret=1", "wss://relay.example/%63onnects"} {
		if _, e := PublicURL(in); e == nil {
			t.Fatalf("accepted %q", in)
		}
	}
}

func TestNginxLargeUnrelatedGeoFragmentDoesNotSelectASite(t *testing.T) {
	// A generated geo include can exceed the site AST's token budget while
	// remaining within the bounded configuration-file size. It has no blocks.
	data := []byte(strings.Repeat("192.0.2.0/24 1;\n", 66756))
	before := append([]byte(nil), data...)
	edit, err := NginxRouteForPort(data, "relay.example", 19088)
	if !errors.Is(err, ErrNoSite) || edit.Reused || len(edit.After) != 0 || !bytes.Equal(data, before) {
		t.Fatalf("unrelated geo include became a site error or edit: %v", err)
	}
}

func TestNginxLargeOrMalformedSiteStillFailsClosed(t *testing.T) {
	large := strings.Repeat("192.0.2.0/24 1;\n", 66756)
	for _, data := range []string{
		large + `server { listen 443 ssl; server_name relay.example; }`,
		large + `ser\ver { listen 443 ssl; server_name relay.example; }`,
		large + `"server" { listen 443 ssl; server_name relay.example; }`,
		large + `geo $blocked {`,
		large + `"unterminated`,
		strings.Repeat("geo $value {", 34) + strings.Repeat("}", 34),
		strings.Repeat(" ", maxConfigBytes+1),
	} {
		edit, err := NginxRouteForPort([]byte(data), "relay.example", 19088)
		if !errors.Is(err, ErrRoute) || len(edit.After) != 0 || edit.Reused {
			t.Fatal("streaming fragment classification bypassed the site parser bounds")
		}
	}
}

func TestNginxControlPanelRouteReusedWithoutChangingWebsite(t *testing.T) {
	data := []byte(`server {
  listen 80;
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name www.relay.example;
  include /etc/nginx/security/edge-guard.conf;
  return 301 https://relay.example$request_uri;
}
server {
  listen 80;
  listen 443 quic;
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name relay.example alias.relay.example;
  root /srv/selected;
  include /etc/nginx/security/edge-guard.conf;
  if ($scheme != "https") { rewrite ^ https://$host$request_uri permanent; }
  location ^~ /.well-known/acme-challenge/ {
    types { }
    try_files $uri =404;
    limit_except GET { deny all; }
  }
  location = /connects {
    access_log off;
    limit_conn selected_relay_per_peer 16;
    client_max_body_size 1k;
    proxy_pass http://127.0.0.1:19088/connects;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Cookie "";
    proxy_set_header Authorization "";
    proxy_pass_request_body off;
    proxy_next_upstream off;
    proxy_buffering off;
    proxy_read_timeout 1d;
  }
  location / { proxy_pass http://127.0.0.1:8080; }
  if (-f $request_filename) { break; }
}
server {
  listen 8080;
  server_name relay.example alias.relay.example;
  include /etc/nginx/global_settings;
  if ($backend_denied) { return 403; }
  location ~ \.php$ { fastcgi_param PHP_VALUE "memory_limit=512M;
display_errors=off;"; }
}
`)
	for _, hostname := range []string{"relay.example", "alias.relay.example"} {
		edit, err := NginxRouteForPort(data, hostname, 19088)
		if err != nil || !edit.Reused || !bytes.Equal(edit.Before, data) || !bytes.Equal(edit.After, data) {
			t.Fatalf("selected control-panel route was not reused exactly: %v", err)
		}
		if edit, err := NginxRouteForPort(data, hostname, 19089); err == nil || len(edit.After) != 0 || edit.Reused {
			t.Fatal("aliased website allowed a different relay port")
		}
	}
	duplicate := append(append([]byte(nil), data...), []byte(`server { listen 443 ssl; server_name relay.example; }`)...)
	if _, err := NginxRouteForPort(duplicate, "relay.example", 19088); !errors.Is(err, ErrRoute) {
		t.Fatal("multiple HTTPS owners were accepted")
	}
}

func TestNginxRouteReuseRejectsCompetingOrRedirectedExactLocations(t *testing.T) {
	for _, locations := range []string{
		`location = /connects { proxy_pass http://127.0.0.1:19088/connects; } location = /connects { proxy_pass http://127.0.0.1:19089/connects; }`,
		`location = /connects { proxy_pass http://127.0.0.1:19088/connects; } location /connects { proxy_pass http://127.0.0.1:19089; }`,
		`location = /connects { proxy_pass http://127.0.0.1:19088/connects; proxy_pass http://127.0.0.1:19089/connects; }`,
		`location = /connects { proxy_pass ""; proxy_pass http://127.0.0.1:19088/connects; }`,
		`location = /connects { proxy_pass http://127.0.0.1:19088/connects; return 301 https://other.example; }`,
		`location = /connects { proxy_pass http://127.0.0.1:19088/connects; if ($blocked) { return 403; } }`,
	} {
		data := []byte(`server { listen 443 ssl; server_name relay.example; ` + locations + ` }`)
		if edit, err := NginxRouteForPort(data, "relay.example", 19088); !errors.Is(err, ErrRoute) || len(edit.After) != 0 || edit.Reused {
			t.Fatal("competing or overridden exact location was reused")
		}
	}
}

func TestNginxFragmentDetectionSeparatesQuotedDelimitersFromGrammar(t *testing.T) {
	for _, fragment := range []string{
		`log_format json escape=json '{' '"method":"$request_method"' '}' ';';`,
		`map $value $result { default "server {"; }`,
		`map $value $result { default \{; other \}; third \;; }`,
		"# server { listen 443 ssl; server_name relay.example; }\n192.0.2.0/24 1;\n",
	} {
		if edit, err := NginxRouteForPort([]byte(fragment), "relay.example", 19088); !errors.Is(err, ErrNoSite) || len(edit.After) != 0 {
			t.Fatalf("quoted/comment text became server grammar: %v", err)
		}
		withSite := []byte(fragment + ` server { listen 443 ssl; server_name relay.example; set $brace "{"; set $semicolon ";"; location = /connects { proxy_pass http://127.0.0.1:19088/connects; } }`)
		edit, err := NginxRouteForPort(withSite, "relay.example", 19088)
		if err != nil || !edit.Reused || !bytes.Equal(edit.After, withSite) {
			t.Fatalf("quoted delimiters changed selected site ownership: %v", err)
		}
	}
	for _, keyword := range []string{`"server"`, `ser\ver`} {
		data := []byte(keyword + ` { listen 443 ssl; server_name relay.example; }`)
		if _, err := NginxRouteForPort(data, "relay.example", 19088); err != nil {
			t.Fatal("normalized server keyword was skipped by fragment detection")
		}
	}
}

func TestNginxPortConflictRequiresOneExactLiteralLoopbackTarget(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:19089", "http://127.0.0.1:19089/connects"} {
		data := []byte(`server { listen 443 ssl; server_name relay.example alias.example; location = /connects { proxy_pass ` + target + `; } }`)
		for _, hostname := range []string{"relay.example", "alias.example"} {
			if _, err := NginxRouteForPort(data, hostname, 19088); !errors.Is(err, ErrRoutePortConflict) || !errors.Is(err, ErrRoute) {
				t.Fatal("definite different-port conflict was not classified")
			}
		}
	}
	for _, directives := range []string{
		`proxy_pass http://127.0.0.1:$port/connects;`,
		`proxy_pass http://127.0.0.1:019089/connects;`,
		`proxy_pass http://127.0.0.1:19089/elsewhere;`,
		`proxy_pass http://127.0.0.1:19089/connects?other=1;`,
		`proxy_pass http://127.0.0.1:80/connects;`,
		`proxy_pass http://127.0.0.1:65536/connects;`,
		`proxy_pass http://other.example:19089/connects;`,
		`proxy_pass http://127.0.0.1:19089/connects; proxy_pass http://127.0.0.1:19090/connects;`,
		`proxy_pass http://127.0.0.1:19089/connects; return 403;`,
	} {
		data := []byte(`server { listen 443 ssl; server_name relay.example; location = /connects { ` + directives + ` } }`)
		if _, err := NginxRouteForPort(data, "relay.example", 19088); !errors.Is(err, ErrRoute) || errors.Is(err, ErrRoutePortConflict) {
			t.Fatal("unsafe route was downgraded to a recoverable port conflict")
		}
	}
}

func TestCaddyQuotedDelimitersRemainDirectiveArguments(t *testing.T) {
	data := []byte("relay.example {\n header X-Brace \"{\"\n handle {\n respond \"}\"\n }\n}\n")
	edit, err := CaddyRouteForPort(data, "relay.example", 19088)
	if err != nil || edit.Reused || !bytes.Contains(edit.After, []byte("respond \"}\"")) {
		t.Fatalf("shared lexer treated quoted Caddy values as delimiters: %v", err)
	}
	again, err := CaddyRouteForPort(edit.After, "relay.example", 19088)
	if err != nil || !again.Reused || !bytes.Equal(again.After, edit.After) {
		t.Fatal("Caddy quoted delimiter route was not reused exactly")
	}
}

func TestNginxSelectedSiteOnlyAndExactReuse(t *testing.T) {
	other := `server { listen 443 ssl; server_name other.example; location / { proxy_pass http://127.0.0.1:8080; } }`
	target := `server { listen 443 ssl; server_name relay.example www.relay.example; set $sample "quoted } { # data"; location / { try_files $uri ${uri}/ /index.php?$args; } }`
	input := []byte(other + "\n" + target + "\n")
	edit, e := NginxRoute(input, "relay.example")
	if e != nil {
		t.Fatal(e)
	}
	if edit.Reused || !bytes.HasPrefix(edit.After, []byte(other+"\n")) || bytes.Count(edit.After, []byte("location = /connects")) != 1 {
		t.Fatal("changed wrong site or failed exact routing")
	}
	again, e := NginxRoute(edit.After, "relay.example")
	if e != nil || !again.Reused || !bytes.Equal(again.After, edit.After) {
		t.Fatal("existing route was not reused")
	}
}

func TestNginxAmbiguousOrConflictingSitesAreNotChanged(t *testing.T) {
	for _, data := range []string{
		`server { listen 443 ssl; server_name other.example; }`,
		`server { listen 80; server_name relay.example; }`,
		strings.Repeat(`server { listen 443 ssl; server_name relay.example; }`, 2),
		`server { listen 443 ssl; server_name relay.example; location = /connects { proxy_pass http://another.example; } }`,
		`server { listen 443 ssl; server_name relay.example; return 301 https://other.example; }`,
		`server { listen 443 ssl; server_name relay.example;`,
	} {
		if _, e := NginxRoute([]byte(data), "relay.example"); e == nil {
			t.Fatalf("accepted unsafe/ambiguous config: %q", data)
		}
	}
}

func TestOtherProxyAdaptersKeepOtherSitesAndReuse(t *testing.T) {
	for _, test := range []struct {
		name          string
		edit          func([]byte, string) (RouteEdit, error)
		before, other string
	}{
		{"caddy", CaddyRoute, "{\n email operator@example.invalid\n}\nother.example {\n respond \"other site\"\n}\nrelay.example {\n handle {\n file_server\n }\n}\n", "other.example {\n respond \"other site\"\n}"},
		{"apache", ApacheRoute, "<VirtualHost *:443>\n ServerName other.example\n DocumentRoot /srv/other\n</VirtualHost>\n<VirtualHost *:443>\n ServerName relay.example\n DocumentRoot /srv/selected\n</VirtualHost>\n", "<VirtualHost *:443>\n ServerName other.example\n DocumentRoot /srv/other\n</VirtualHost>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			edited, e := test.edit([]byte(test.before), "relay.example")
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Contains(edited.After, []byte(test.other)) {
				t.Fatal("other site changed")
			}
			again, e := test.edit(edited.After, "relay.example")
			if e != nil || !again.Reused || !bytes.Equal(again.After, edited.After) {
				t.Fatal("route was not reused")
			}
			if _, e := test.edit([]byte(test.before), "missing.example"); e == nil {
				t.Fatal("selected missing site")
			}
		})
	}
}
