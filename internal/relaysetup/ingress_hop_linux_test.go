//go:build linux

package relaysetup

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealApacheAndCaddyPeerHeaderConnectionNomination(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable provider fixture only")
	}
	if _, err := os.Stat("/owntransit-provider-fixture"); err != nil {
		t.Skip("disposable provider fixture only")
	}
	for _, provider := range []string{"apache", "caddy"} {
		t.Run(provider, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(r.Header.Values(proxyPeerHeader))
			}))
			defer backend.Close()
			_, upstreamPort, err := net.SplitHostPort(backend.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			upstream, err := strconv.Atoi(upstreamPort)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := listener.Addr().(*net.TCPAddr).Port
			_ = listener.Close()
			dir := t.TempDir()
			path := filepath.Join(dir, "provider.conf")
			var edit RouteEdit
			var program string
			var arguments []string
			if provider == "apache" {
				config := "ServerRoot " + dir + "\nPidFile " + filepath.Join(dir, "apache.pid") + "\nServerName relay.example\nListen 127.0.0.1:" + strconv.Itoa(port) + "\n"
				for _, module := range []string{"mpm_event", "authz_core", "proxy", "proxy_http", "proxy_wstunnel", "headers"} {
					config += "LoadModule " + module + "_module /usr/lib/apache2/modules/mod_" + module + ".so\n"
				}
				config += "User www-data\nGroup www-data\nErrorLog " + filepath.Join(dir, "error.log") + "\nLogLevel error\n<Location />\nRequire all granted\n</Location>\n<VirtualHost 127.0.0.1:443>\nServerName relay.example\n</VirtualHost>\n"
				edit, err = ApacheRouteForPort([]byte(config), "relay.example", upstream)
				// Keep the selected HTTPS-site adapter output, changing only the
				// fixture's listen port. HTTP is sufficient to test hop headers.
				edit.After = []byte(strings.ReplaceAll(string(edit.After), "127.0.0.1:443", "127.0.0.1:"+strconv.Itoa(port)))
				program, arguments = "/usr/sbin/apache2", []string{"-f", path, "-DFOREGROUND"}
			} else {
				edit, err = CaddyRouteForPort([]byte("relay.example {\n}\n"), "relay.example", upstream)
				edit.After = []byte("{\nadmin off\nauto_https off\n}\n" + strings.Replace(string(edit.After), "relay.example", "http://relay.example:"+strconv.Itoa(port), 1))
				program, arguments = "/usr/bin/caddy", []string{"run", "--config", path, "--adapter", "caddyfile"}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, edit.After, 0600); err != nil {
				t.Fatal(err)
			}
			process := exec.Command(program, arguments...)
			process.Env = append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Join(dir, "config"), "XDG_DATA_HOME="+filepath.Join(dir, "data"))
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = process.Process.Signal(syscall.SIGTERM)
				done := make(chan error, 1)
				go func() { done <- process.Wait() }()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					_ = process.Process.Kill()
					<-done
				}
			})
			address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for {
				connection, err := net.DialTimeout("tcp4", address, 50*time.Millisecond)
				if err == nil {
					_ = connection.Close()
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("fixture provider did not listen")
				case <-time.After(20 * time.Millisecond):
				}
			}
			dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
			transport := &http.Transport{DialContext: dialer.DialContext}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			for _, connection := range []string{"Upgrade", "Upgrade, OwnTransit-Peer-IP"} {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/connects", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Host = "relay.example"
				request.Header.Set("Connection", connection)
				request.Header.Set("Upgrade", "websocket")
				request.Header.Set("Sec-WebSocket-Protocol", "owntransit.carrier.v2")
				request.Header.Add(proxyPeerHeader, "198.51.100.1")
				request.Header.Add(proxyPeerHeader, "198.51.100.2")
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				var peers []string
				err = json.NewDecoder(response.Body).Decode(&peers)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != http.StatusOK || len(peers) != 1 || peers[0] != "127.0.0.2" {
					t.Fatalf("%s lost original peer with Connection %q: status=%d peers=%v error=%v", provider, connection, response.StatusCode, peers, err)
				}
			}
		})
	}
}
