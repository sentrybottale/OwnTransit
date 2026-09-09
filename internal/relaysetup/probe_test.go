package relaysetup

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
)

type adminProbeFixtureConnection struct{ net.Conn }

func (adminProbeFixtureConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}
}

func TestAdminProbeOnlyClassifiesAuthenticatedForbidden(t *testing.T) {
	for _, scenario := range []string{"public", "forbidden", "unauthorized", "not-found", "server-error", "redirect", "bad-websocket", "wrong-subprotocol", "tls12", "untrusted-cert", "wrong-hostname", "private-dns", "mixed-dns", "dns-error", "dial-error"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Now()
			ca, err := pki.NewCA("OwnTransit probe fixture", now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			host := "relay.example"
			if scenario == "wrong-hostname" {
				host = "other.example"
			}
			leaf, err := pki.IssueLeaf(ca, host, x509.ExtKeyUsageServerAuth, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
			if err != nil {
				t.Fatal(err)
			}
			var relay *pairrelay.Relay
			if scenario == "public" {
				key := make([]byte, 32)
				if _, err := rand.Read(key); err != nil {
					t.Fatal(err)
				}
				relay, err = pairrelay.NewRelay(pairrelay.RelayConfig{TokenKey: key, RelayTLS: pairrelay.TLSMaterial{Certificate: certificate, CAPEM: ca.CertPEM, ServerName: host}, VerifyAdvertisement: func([]byte, time.Time) (pairrelay.Descriptor, error) {
					return pairrelay.Descriptor{}, pairrelay.ErrProtocol
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer relay.Close()
			}
			var requests atomic.Int64
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/connects" || r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-WebSocket-Protocol") != pairrelay.WebSocketSubprotocol {
					t.Error("unexpected administrative request")
				}
				switch scenario {
				case "public":
					relay.ServeHTTP(w, r)
				case "unauthorized":
					w.WriteHeader(http.StatusUnauthorized)
				case "not-found":
					w.WriteHeader(http.StatusNotFound)
				case "server-error":
					w.WriteHeader(http.StatusBadGateway)
				case "redirect":
					w.Header().Set("Location", "https://other.example/connects")
					w.WriteHeader(http.StatusFound)
				case "bad-websocket":
					w.WriteHeader(http.StatusOK)
				case "wrong-subprotocol":
					ws, e := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"unrelated"}})
					if e == nil {
						ws.CloseNow()
					}
				default:
					w.WriteHeader(http.StatusForbidden)
				}
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
			if scenario == "tls12" {
				server.TLS.MinVersion = tls.VersionTLS12
				server.TLS.MaxVersion = tls.VersionTLS12
			}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			if scenario != "untrusted-cert" {
				roots.AppendCertsFromPEM(ca.CertPEM)
			}
			network := adminProbeNetwork{roots: roots, lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				if scenario == "dns-error" {
					return nil, errors.New("fixture DNS failure")
				}
				if scenario == "private-dns" {
					return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
				}
				if scenario == "mixed-dns" {
					return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("10.0.0.1")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
			}, dial: func(ctx context.Context, kind, address string) (net.Conn, error) {
				if kind != "tcp" || address != "192.0.2.1:443" {
					t.Error("probe did not pin the validated address")
				}
				if scenario == "dial-error" {
					return nil, errors.New("fixture dial failure")
				}
				connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
				if err != nil {
					return nil, err
				}
				return adminProbeFixtureConnection{connection}, nil
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			info, err := adminProbeWithNetwork(ctx, "wss://relay.example/connects", network)
			if scenario == "public" {
				if err != nil || info.ServerName != host || len(info.CAPEM) == 0 || info.LeafSPKISHA256 == "" {
					t.Fatal("valid public relay probe failed", err)
				}
				return
			}
			if errors.Is(err, errProbeForbidden) != (scenario == "forbidden") {
				t.Fatalf("wrong probe classification: %v", err)
			}
			if err == nil || info.ServerName != "" || len(info.CAPEM) != 0 || info.LeafSPKISHA256 != "" {
				t.Fatal("failed probe fabricated relay identity")
			}
			if scenario == "redirect" && requests.Load() != 1 {
				t.Fatal("probe followed redirect")
			}
		})
	}
}
