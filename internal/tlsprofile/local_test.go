package tlsprofile

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
)

func TestClientValidatesStrictLocalCertificateBeforeUse(t *testing.T) {
	name := "client.owntransit.invalid"
	certFile, keyFile, issuerFile, wrongIssuerFile := localFixture(t, name, x509.ExtKeyUsageClientAuth)
	value := config.ClientTLS{
		CertFile: certFile, KeyFile: keyFile, CAFile: issuerFile,
		ServerName: "server.owntransit.invalid", SPKIPins: []string{identity.FormatSPKIPin(identity.SPKIHash{1})},
		IssuerCAFile: issuerFile, LocalDNSName: name,
	}
	if _, err := Client(value, name, config.InnerALPN); err != nil {
		t.Fatalf("strict client profile: %v", err)
	}

	wrongIssuer := value
	wrongIssuer.IssuerCAFile = wrongIssuerFile
	if _, err := Client(wrongIssuer, name, config.InnerALPN); err == nil {
		t.Fatal("client accepted a local certificate under the wrong issuer")
	}

	wrongName := value
	wrongName.LocalDNSName = "other.owntransit.invalid"
	if _, err := Client(wrongName, name, config.InnerALPN); err == nil {
		t.Fatal("client accepted a configured local identity different from its role binding")
	}
}

func TestServerValidatesStrictLocalCertificateBeforeUse(t *testing.T) {
	name := "server.owntransit.invalid"
	certFile, keyFile, issuerFile, wrongIssuerFile := localFixture(t, name, x509.ExtKeyUsageServerAuth)
	peers := map[string]identity.PinSet{
		"client.owntransit.invalid": {identity.SPKIHash{2}: {}},
	}
	value := config.ServerTLS{
		CertFile: certFile, KeyFile: keyFile, ClientCAFile: issuerFile,
		IssuerCAFile: issuerFile, LocalDNSName: name,
	}
	if _, err := Server(value, name, config.InnerALPN, peers); err != nil {
		t.Fatalf("strict server profile: %v", err)
	}
	value.IssuerCAFile = wrongIssuerFile
	if _, err := Server(value, name, config.InnerALPN, peers); err == nil {
		t.Fatal("server accepted a local certificate under the wrong issuer")
	}
}

func TestLegacyLocalProfileCompatibilityStillChecksExactLeaf(t *testing.T) {
	name := "client.owntransit.invalid"
	certFile, keyFile, issuerFile, _ := localFixture(t, name, x509.ExtKeyUsageClientAuth)
	value := config.ClientTLS{
		CertFile: certFile, KeyFile: keyFile, CAFile: issuerFile,
		ServerName: "server.owntransit.invalid", SPKIPins: []string{identity.FormatSPKIPin(identity.SPKIHash{3})},
	}
	if _, err := Client(value, "", config.InnerALPN); err != nil {
		t.Fatalf("legacy structural client profile: %v", err)
	}
	if _, err := Client(value, "other.owntransit.invalid", config.InnerALPN); err == nil {
		t.Fatal("legacy client profile accepted the wrong role-bound local name")
	}

	serverName := "server.owntransit.invalid"
	serverCert, serverKey, serverIssuer, _ := localFixture(t, serverName, x509.ExtKeyUsageServerAuth)
	peers := map[string]identity.PinSet{
		name: {identity.SPKIHash{4}: {}},
	}
	if _, err := Server(config.ServerTLS{
		CertFile: serverCert, KeyFile: serverKey, ClientCAFile: serverIssuer,
	}, serverName, config.InnerALPN, peers); err != nil {
		t.Fatalf("legacy structural server profile: %v", err)
	}
}

func localFixture(t *testing.T, name string, usage x509.ExtKeyUsage) (string, string, string, string) {
	t.Helper()
	now := time.Now().UTC()
	authority, err := pki.NewCA("local test issuer", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.IssueLeaf(authority, name, usage, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	wrongAuthority, err := pki.NewCA("wrong local test issuer", now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := writeLocalFile(t, directory, "leaf-cert.pem", leaf.CertPEM, 0o644)
	keyFile := writeLocalFile(t, directory, "leaf-key.pem", leaf.KeyPEM, 0o600)
	issuerFile := writeLocalFile(t, directory, "issuer.pem", authority.CertPEM, 0o644)
	wrongIssuerFile := writeLocalFile(t, directory, "wrong-issuer.pem", wrongAuthority.CertPEM, 0o644)
	return certFile, keyFile, issuerFile, wrongIssuerFile
}

func writeLocalFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
