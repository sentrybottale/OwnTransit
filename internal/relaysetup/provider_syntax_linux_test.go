//go:build linux

package relaysetup

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRealProviderConfigurationSyntax(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable provider fixture only")
	}
	if _, err := os.Stat("/owntransit-provider-fixture"); err != nil {
		t.Skip("disposable provider fixture only")
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if out, err := exec.Command("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=relay.example", "-keyout", key, "-out", cert).CombinedOutput(); err != nil {
		t.Fatalf("fixture certificate: %v %s", err, out)
	}
	nginx := []byte("events {}\nhttp {\nserver { listen 443 ssl; server_name other.example; ssl_certificate " + cert + "; ssl_certificate_key " + key + "; location / { return 200 other; } }\nserver { listen 443 ssl; server_name relay.example; ssl_certificate " + cert + "; ssl_certificate_key " + key + "; location / { return 200 selected; } }\n}\n")
	edit, err := NginxRoute(nginx, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, edit.After, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/sbin/nginx", "-t", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("nginx rejected route: %v %s", err, out)
	}
	caddy := []byte("other.example {\n respond other\n}\nrelay.example {\n respond selected\n}\n")
	edit, err = CaddyRoute(caddy, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, edit.After, 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/caddy", "validate", "--config", path, "--adapter", "caddyfile").CombinedOutput(); err != nil {
		t.Fatalf("caddy rejected route: %v %s", err, out)
	}
	apache := []byte("<VirtualHost *:443>\n ServerName other.example\n DocumentRoot /var/www/html\n</VirtualHost>\n<VirtualHost *:443>\n ServerName relay.example\n DocumentRoot /var/www/html\n</VirtualHost>\n")
	edit, err = ApacheRoute(apache, "relay.example")
	if err != nil {
		t.Fatal(err)
	}
	path = "/etc/apache2/sites-enabled/owntransit-fixture.conf"
	if err := os.WriteFile(path, edit.After, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	if out, err := exec.Command("/usr/sbin/apache2ctl", "-t").CombinedOutput(); err != nil {
		t.Fatalf("apache rejected route: %v %s", err, out)
	}
}
