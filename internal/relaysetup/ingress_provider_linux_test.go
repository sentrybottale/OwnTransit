//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Exercise the real provider's overwrite semantics with both attacker-chosen
// duplicate headers and ambient RealIP rewriting enabled. The backend sees
// precisely one original TCP-peer address for each independently bound source.
func TestRealNginxPeerHeaderOverwrite(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("disposable provider fixture only")
	}
	if _, err := os.Stat("/owntransit-provider-fixture"); err != nil {
		t.Skip("disposable provider fixture only")
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(r.Header.Values(proxyPeerHeader))
	}))
	defer backend.Close()
	_, portString, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if out, err := exec.Command("/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=relay.example", "-keyout", key, "-out", cert).CombinedOutput(); err != nil {
		t.Fatalf("fixture certificate: %v %s", err, out)
	}
	config := []byte("pid " + filepath.Join(dir, "nginx.pid") + ";\nerror_log " + filepath.Join(dir, "error.log") + ";\nevents {}\nhttp { access_log off; server { listen 127.0.0.1:443 ssl; server_name relay.example; ssl_certificate " + cert + "; ssl_certificate_key " + key + "; ssl_protocols TLSv1.3; set_real_ip_from 127.0.0.0/8; real_ip_header X-Forwarded-For; real_ip_recursive on; } }\n")
	edit, err := NginxRouteForPort(config, "relay.example", port)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(path, edit.After, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	process := exec.Command("/usr/sbin/nginx", "-c", path, "-p", dir, "-g", "daemon off;")
	process.Stdout, process.Stderr = &output, &output
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Signal(syscall.SIGQUIT)
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			_ = process.Process.Kill()
			<-done
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		connection, err := net.DialTimeout("tcp4", "127.0.0.1:443", 50*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("fixture nginx did not listen: %v", ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	for _, source := range []string{"127.0.0.2", "127.0.0.3"} {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(source)}}
		transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "relay.example", InsecureSkipVerify: true}}
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1/connects", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add(proxyPeerHeader, "198.51.100.1")
		request.Header.Add(proxyPeerHeader, "198.51.100.2")
		request.Header.Set("X-Forwarded-For", "192.0.2.99")
		request.Header.Set("Connection", "Upgrade, OwnTransit-Peer-IP")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var peers []string
		err = json.NewDecoder(response.Body).Decode(&peers)
		_ = response.Body.Close()
		transport.CloseIdleConnections()
		if err != nil || response.StatusCode != http.StatusOK || len(peers) != 1 || peers[0] != source {
			t.Fatalf("nginx did not replace spoofed headers with the original TCP peer: status=%d peers=%v error=%v", response.StatusCode, peers, err)
		}
	}
}
