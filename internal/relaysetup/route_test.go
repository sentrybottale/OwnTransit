package relaysetup

import (
	"bytes"
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
