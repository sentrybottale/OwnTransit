package connector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
)

type connectorFixture struct {
	service               *Service
	value                 config.Connector
	local                 *countingLocalDialer
	relayServerTLS        *tls.Config
	authorizedClientTLS   *tls.Config
	rotatedKeyClientTLS   *tls.Config
	wrongBindingClientTLS *tls.Config
	wrongEKUClientTLS     *tls.Config
	connectorRoots        *x509.CertPool
	connectorServerName   string
	innerClientCA         pki.Material
	innerConnector        pki.Material
}

func newConnectorFixture(t *testing.T) connectorFixture {
	t.Helper()
	now := time.Now().UTC()
	validity := 24 * time.Hour
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	otherRoute, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	const credentialEpoch uint64 = 1

	relayCA := mustCA(t, "relay CA", now, validity)
	innerClientCA := mustCA(t, "client CA", now, validity)
	innerConnectorCA := mustCA(t, "connector CA", now, validity)
	relayServer := mustLeaf(t, relayCA, config.RelayDNSName, x509.ExtKeyUsageServerAuth, now, validity)
	outerConnector := mustLeaf(t, relayCA, config.OuterConnectorDNSName(route), x509.ExtKeyUsageClientAuth, now, validity)
	connectorName := config.CapabilityConnectorDNSName(connectorID, route)
	innerConnector := mustLeaf(t, innerConnectorCA, connectorName, x509.ExtKeyUsageServerAuth, now, validity)
	clientName := config.ClientCapabilityDNSName(clientID, connectorID, route, credentialEpoch)
	authorizedClient := mustLeaf(t, innerClientCA, clientName, x509.ExtKeyUsageClientAuth, now, validity)
	rotatedKeyClient := mustLeaf(t, innerClientCA, clientName, x509.ExtKeyUsageClientAuth, now, validity)
	wrongBindingClient := mustLeaf(t, innerClientCA, config.ClientCapabilityDNSName(clientID, connectorID, otherRoute, credentialEpoch), x509.ExtKeyUsageClientAuth, now, validity)
	wrongEKUClient := mustLeaf(t, innerClientCA, clientName, x509.ExtKeyUsageServerAuth, now, validity)

	directory := t.TempDir()
	relayCAPath := writePEM(t, directory, "relay-ca.pem", relayCA.CertPEM)
	innerClientCAPath := writePEM(t, directory, "inner-client-ca.pem", innerClientCA.CertPEM)
	innerConnectorCAPath := writePEM(t, directory, "inner-connector-ca.pem", innerConnectorCA.CertPEM)
	relayCert, relayKey := writeMaterial(t, directory, "relay", relayServer)
	outerCert, outerKey := writeMaterial(t, directory, "outer-connector", outerConnector)
	innerConnectorCert, innerConnectorKey := writeMaterial(t, directory, "inner-connector", innerConnector)
	authorizedCert, authorizedKey := writeMaterial(t, directory, "authorized-client", authorizedClient)
	rotatedKeyCert, rotatedKeyKey := writeMaterial(t, directory, "rotated-key-client", rotatedKeyClient)
	wrongBindingCert, wrongBindingKey := writeMaterial(t, directory, "wrong-binding-client", wrongBindingClient)
	wrongEKUCert, wrongEKUKey := writeMaterial(t, directory, "wrong-eku-client", wrongEKUClient)

	relayPin := mustPin(t, relayServer.Certificate)
	connectorPin := mustPin(t, innerConnector.Certificate)
	value := config.Connector{
		RelayURL:             "ws://127.0.0.1/connects",
		AllowInsecureCarrier: true,
		InstallationID:       connectorID.String(),
		RouteID:              route.String(),
		InnerProfile:         config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: outerCert, KeyFile: outerKey, CAFile: relayCAPath,
			ServerName: config.RelayDNSName, SPKIPins: []string{relayPin},
			IssuerCAFile: relayCAPath, LocalDNSName: config.OuterConnectorDNSName(route),
		},
		InnerTLS: config.ConnectorInnerTLS{
			CertFile: innerConnectorCert, KeyFile: innerConnectorKey,
			ClientCAFiles: []string{innerClientCAPath}, ServerName: connectorName,
			IssuerCAFile: innerConnectorCAPath, LocalDNSName: connectorName,
		},
		SSHTarget: fixedSSHTarget,
		Limits: config.ConnectorLimits{
			Pending: 2, Active: 2,
			ConnectTimeout: config.Duration(250 * time.Millisecond),
			Handshake:      config.Duration(time.Second),
			LocalDial:      config.Duration(250 * time.Millisecond),
			Drain:          config.Duration(100 * time.Millisecond),
			ReconnectMin:   config.Duration(10 * time.Millisecond),
			ReconnectMax:   config.Duration(40 * time.Millisecond),
		},
	}
	local := &countingLocalDialer{err: errors.New("unexpected local dial")}
	service, err := New(value, WithCarrierDialer(errorCarrierDialer{}), WithLocalDialer(local))
	if err != nil {
		t.Fatalf("New connector: %v", err)
	}

	relayPeers := map[string]identity.PinSet{}
	outerHash, err := identity.HashSPKI(outerConnector.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	relayPeers[config.OuterConnectorDNSName(route)] = identity.PinSet{outerHash: {}}
	relayServerTLS, err := tlsprofile.Server(config.ServerTLS{
		CertFile: relayCert, KeyFile: relayKey, ClientCAFile: relayCAPath,
	}, config.RelayDNSName, config.RelayALPN, relayPeers)
	if err != nil {
		t.Fatalf("relay server TLS: %v", err)
	}

	makeClientTLS := func(certFile, keyFile string) *tls.Config {
		profile, err := tlsprofile.Client(config.ClientTLS{
			CertFile: certFile, KeyFile: keyFile, CAFile: innerConnectorCAPath,
			ServerName: connectorName, SPKIPins: []string{connectorPin},
		}, "", config.CapabilityInnerALPN)
		if err != nil {
			t.Fatalf("inner client TLS: %v", err)
		}
		return profile
	}
	connectorRoots, err := identity.LoadCertPool(innerConnectorCAPath)
	if err != nil {
		t.Fatal(err)
	}
	wrongEKUPair, err := identity.LoadKeyPair(wrongEKUCert, wrongEKUKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongEKUClientTLS := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{wrongEKUPair}, RootCAs: connectorRoots,
		ServerName: connectorName, NextProtos: []string{config.CapabilityInnerALPN},
	}
	return connectorFixture{
		service:               service,
		value:                 value,
		local:                 local,
		relayServerTLS:        relayServerTLS,
		authorizedClientTLS:   makeClientTLS(authorizedCert, authorizedKey),
		rotatedKeyClientTLS:   makeClientTLS(rotatedKeyCert, rotatedKeyKey),
		wrongBindingClientTLS: makeClientTLS(wrongBindingCert, wrongBindingKey),
		wrongEKUClientTLS:     wrongEKUClientTLS,
		connectorRoots:        connectorRoots,
		connectorServerName:   connectorName,
		innerClientCA:         innerClientCA,
		innerConnector:        innerConnector,
	}
}

func mustCA(t *testing.T, name string, now time.Time, validity time.Duration) pki.Material {
	t.Helper()
	material, err := pki.NewCA(name, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func mustLeaf(t *testing.T, ca pki.Material, name string, usage x509.ExtKeyUsage, now time.Time, validity time.Duration) pki.Material {
	t.Helper()
	material, err := pki.IssueLeaf(ca, name, usage, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func writeMaterial(t *testing.T, directory, name string, material pki.Material) (string, string) {
	t.Helper()
	return writePEM(t, directory, name+".pem", material.CertPEM), writePEM(t, directory, name+".key", material.KeyPEM)
}

func writePEM(t *testing.T, directory, name string, contents []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustPin(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	pin, err := identity.SPKIPin(cert)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

type errorCarrierDialer struct{}

func (errorCarrierDialer) Dial(context.Context) (net.Conn, error) {
	return nil, errors.New("test carrier unavailable")
}

type singleCarrierDialer struct {
	mu   sync.Mutex
	conn net.Conn
	err  error
}

func (dialer *singleCarrierDialer) Dial(context.Context) (net.Conn, error) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	connection := dialer.conn
	dialer.conn = nil
	if connection == nil {
		if dialer.err != nil {
			return nil, dialer.err
		}
		return nil, errors.New("test carrier already consumed")
	}
	return connection, nil
}

type countingLocalDialer struct {
	calls   atomic.Int32
	mu      sync.Mutex
	network string
	address string
	conn    net.Conn
	err     error
}

func (dialer *countingLocalDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	dialer.calls.Add(1)
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	dialer.network = network
	dialer.address = address
	connection := dialer.conn
	dialer.conn = nil
	if connection != nil {
		return connection, nil
	}
	return nil, dialer.err
}

func (dialer *countingLocalDialer) target() (string, string) {
	dialer.mu.Lock()
	defer dialer.mu.Unlock()
	return dialer.network, dialer.address
}

type innerResult struct {
	ready bool
	err   error
}

func runInnerServer(service *Service, connection net.Conn) <-chan innerResult {
	result := make(chan innerResult, 1)
	go func() {
		ready, err := service.serveInner(context.Background(), connection, nil)
		connection.Close()
		result <- innerResult{ready: ready, err: err}
	}()
	return result
}
