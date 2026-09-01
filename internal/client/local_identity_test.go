package client

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestNewBindsLegacyOuterAndInnerCertificatesToOneInstallation(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.NewCA("client local test issuer", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	outerID := protocol.ID{1}
	innerID := protocol.ID{2}
	outer, err := pki.IssueLeaf(authority, config.OuterClientDNSName(outerID), x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongInner, err := pki.IssueLeaf(authority, config.ClientDNSName(innerID), x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	matchingInner, err := pki.IssueLeaf(authority, config.ClientDNSName(outerID), x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	issuerFile := writeClientLocalFile(t, directory, "issuer.pem", authority.CertPEM, 0o644)
	outerCert := writeClientLocalFile(t, directory, "outer-cert.pem", outer.CertPEM, 0o644)
	outerKey := writeClientLocalFile(t, directory, "outer-key.pem", outer.KeyPEM, 0o600)
	wrongInnerCert := writeClientLocalFile(t, directory, "wrong-inner-cert.pem", wrongInner.CertPEM, 0o644)
	wrongInnerKey := writeClientLocalFile(t, directory, "wrong-inner-key.pem", wrongInner.KeyPEM, 0o600)
	matchingInnerCert := writeClientLocalFile(t, directory, "matching-inner-cert.pem", matchingInner.CertPEM, 0o644)
	matchingInnerKey := writeClientLocalFile(t, directory, "matching-inner-key.pem", matchingInner.KeyPEM, 0o600)

	route := protocol.RouteID{3}
	pin := identity.FormatSPKIPin(identity.SPKIHash{4})
	value := config.Client{
		RelayURL: "wss://relay.example.com/connects", RouteID: route.String(), InnerProfile: config.InnerProfileLegacyExactPins,
		OuterTLS: config.ClientTLS{
			CertFile: outerCert, KeyFile: outerKey, CAFile: issuerFile,
			ServerName: config.RelayDNSName, SPKIPins: []string{pin},
		},
		InnerTLS: config.ClientTLS{
			CertFile: wrongInnerCert, KeyFile: wrongInnerKey, CAFile: issuerFile,
			ServerName: config.ConnectorDNSName(route), SPKIPins: []string{pin},
		},
		ConnectTimeout: config.Duration(time.Second), HandshakeTimeout: config.Duration(time.Second),
		ReadyTimeout: config.Duration(time.Second), DrainTimeout: config.Duration(time.Second),
	}
	if _, err := New(value, inertCarrierDialer{}); err == nil {
		t.Fatal("New accepted legacy client certificates from different installations")
	}

	value.InnerTLS.CertFile = matchingInnerCert
	value.InnerTLS.KeyFile = matchingInnerKey
	if _, err := New(value, inertCarrierDialer{}); err != nil {
		t.Fatalf("New rejected a matching legacy client identity tuple: %v", err)
	}

	value.InstallationID = outerID.String()
	value.OuterTLS.IssuerCAFile = issuerFile
	value.OuterTLS.LocalDNSName = config.OuterClientDNSName(outerID)
	value.InnerTLS.IssuerCAFile = issuerFile
	value.InnerTLS.LocalDNSName = config.ClientDNSName(outerID)
	if _, err := New(value, inertCarrierDialer{}); err != nil {
		t.Fatalf("New rejected a matching strict client identity tuple: %v", err)
	}
}

func TestNewSelectsRouteCapabilityIdentityAndALPN(t *testing.T) {
	now := time.Now().UTC()
	authority, err := pki.NewCA("capability client test issuer", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientID := protocol.ID{7}
	connectorID := protocol.ID{8}
	route := protocol.RouteID{9}
	const epoch uint64 = 3
	outer, err := pki.IssueLeaf(authority, config.OuterClientDNSName(clientID), x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := pki.IssueLeaf(authority, config.ClientCapabilityDNSName(clientID, connectorID, route, epoch), x509.ExtKeyUsageClientAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := pki.IssueLeaf(authority, config.CapabilityConnectorDNSName(connectorID, route), x509.ExtKeyUsageServerAuth, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	issuerFile := writeClientLocalFile(t, directory, "capability-issuer.pem", authority.CertPEM, 0o644)
	outerCert := writeClientLocalFile(t, directory, "capability-outer.pem", outer.CertPEM, 0o644)
	outerKey := writeClientLocalFile(t, directory, "capability-outer.key", outer.KeyPEM, 0o600)
	innerCert := writeClientLocalFile(t, directory, "capability-inner.pem", inner.CertPEM, 0o644)
	innerKey := writeClientLocalFile(t, directory, "capability-inner.key", inner.KeyPEM, 0o600)
	connectorPin, err := identity.SPKIPin(connector.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	value := config.Client{
		RelayURL: "wss://relay.example.com/connects", InstallationID: clientID.String(), ConnectorInstallationID: connectorID.String(),
		CredentialEpoch: epoch, RouteID: route.String(), InnerProfile: config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: outerCert, KeyFile: outerKey, CAFile: issuerFile, ServerName: config.RelayDNSName,
			SPKIPins: []string{connectorPin}, IssuerCAFile: issuerFile, LocalDNSName: config.OuterClientDNSName(clientID),
		},
		InnerTLS: config.ClientTLS{
			CertFile: innerCert, KeyFile: innerKey, CAFile: issuerFile, ServerName: config.CapabilityConnectorDNSName(connectorID, route),
			SPKIPins: []string{connectorPin}, IssuerCAFile: issuerFile, LocalDNSName: config.ClientCapabilityDNSName(clientID, connectorID, route, epoch),
		},
		ConnectTimeout: config.Duration(time.Second), HandshakeTimeout: config.Duration(time.Second), ReadyTimeout: config.Duration(time.Second), DrainTimeout: config.Duration(time.Second),
	}
	service, err := New(value, inertCarrierDialer{})
	if err != nil {
		t.Fatalf("New capability client: %v", err)
	}
	if len(service.innerTLS.NextProtos) != 1 || service.innerTLS.NextProtos[0] != config.CapabilityInnerALPN {
		t.Fatalf("inner ALPN = %v, want capability profile", service.innerTLS.NextProtos)
	}

	sentinel := errors.New("active generation changed")
	dialer := &countingClientCarrierDialer{}
	service, err = newService(value, dialer, nil, func() error { return sentinel })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Proxy(context.Background(), strings.NewReader("ssh"), io.Discard); !errors.Is(err, sentinel) {
		t.Fatalf("preflight result = %v, want %v", err, sentinel)
	}
	if dialer.calls != 0 {
		t.Fatalf("carrier dialed %d times before failed final check", dialer.calls)
	}
	if err := service.Probe(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("probe preflight result = %v, want %v", err, sentinel)
	}
	if dialer.calls != 0 {
		t.Fatalf("probe dialed carrier %d times before failed final check", dialer.calls)
	}
}

type inertCarrierDialer struct{}

func (inertCarrierDialer) Dial(context.Context) (net.Conn, error) { return nil, net.ErrClosed }

type countingClientCarrierDialer struct{ calls int }

func (dialer *countingClientCarrierDialer) Dial(context.Context) (net.Conn, error) {
	dialer.calls++
	return nil, net.ErrClosed
}

func writeClientLocalFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
