// owntransit-poc-certgen creates a complete, isolated development credential set.
// It has no server mode and must never run on a relay host or production target.
package main

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	relayDNSName               = config.RelayDNSName
	defaultConnectorRuntimeDir = "/run/owntransit"
)

type options struct {
	outputDir           string
	relayURL            string
	relayListen         string
	connectorRuntimeDir string
	caValidity          time.Duration
	validity            time.Duration
}

type metadata struct {
	GeneratedAt         string `json:"generated_at"`
	RouteID             string `json:"route_id"`
	ClientID            string `json:"client_id"`
	ConnectorID         string `json:"connector_id"`
	CredentialEpoch     uint64 `json:"credential_epoch"`
	InnerProfile        string `json:"inner_profile"`
	RelayURL            string `json:"relay_url"`
	ConnectorRuntimeDir string `json:"connector_runtime_dir"`
	RelayDNSName        string `json:"relay_dns_name"`
	OuterClientName     string `json:"outer_client_dns_name"`
	OuterConnectorName  string `json:"outer_connector_dns_name"`
	InnerClientName     string `json:"inner_client_dns_name"`
	InnerConnectorName  string `json:"inner_connector_dns_name"`
	RelayServerPin      string `json:"relay_server_spki_sha256"`
	OuterClientPin      string `json:"outer_client_spki_sha256"`
	OuterConnectorPin   string `json:"outer_connector_spki_sha256"`
	InnerClientPin      string `json:"inner_client_spki_sha256"`
	InnerConnectorPin   string `json:"inner_connector_spki_sha256"`
}

func main() {
	var value options
	flag.StringVar(&value.outputDir, "out", "", "new or empty output directory")
	flag.StringVar(&value.relayURL, "relay-url", "", "required carrier ws:// or wss:// URL embedded in development configs")
	flag.StringVar(&value.relayListen, "relay-listen", "", "required numeric relay listen address embedded in the development relay config")
	flag.StringVar(&value.connectorRuntimeDir, "connector-runtime-dir", defaultConnectorRuntimeDir, "absolute runtime directory embedded in connector credential paths")
	flag.DurationVar(&value.caValidity, "ca-validity", 10*365*24*time.Hour, "POC issuer validity")
	flag.DurationVar(&value.validity, "leaf-validity", 30*24*time.Hour, "POC endpoint certificate validity")
	flag.Parse()
	if err := run(value); err != nil {
		fmt.Fprintf(os.Stderr, "owntransit-poc-certgen: %v\n", err)
		os.Exit(1)
	}
}

func run(value options) error {
	if value.outputDir == "" {
		return errors.New("-out is required")
	}
	if value.relayURL == "" {
		return errors.New("-relay-url is required")
	}
	if value.relayListen == "" {
		return errors.New("-relay-listen is required")
	}
	if err := config.ValidateRelayListen(value.relayListen); err != nil {
		return fmt.Errorf("-relay-listen: %w", err)
	}
	if err := validateConnectorRuntimeDir(value.connectorRuntimeDir); err != nil {
		return err
	}
	if value.caValidity <= 0 || value.validity <= 0 || value.validity >= value.caValidity {
		return errors.New("validities must be positive and leaf validity must be shorter than CA validity")
	}
	carrier, err := url.Parse(value.relayURL)
	if err != nil || (carrier.Scheme != "ws" && carrier.Scheme != "wss") {
		return errors.New("-relay-url must be an absolute ws:// or wss:// URL")
	}
	allowInsecure := carrier.Scheme == "ws"
	if err := prepareOutput(value.outputDir); err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	route, err := protocol.NewRouteID()
	if err != nil {
		return err
	}
	clientID, err := protocol.NewID()
	if err != nil {
		return err
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		return err
	}
	const credentialEpoch uint64 = 1

	outerClientName := config.OuterClientDNSName(clientID)
	outerConnectorName := config.OuterConnectorDNSName(route)
	innerClientName := config.ClientCapabilityDNSName(clientID, connectorID, route, credentialEpoch)
	innerConnectorName := config.CapabilityConnectorDNSName(connectorID, route)

	relayCA, err := pki.NewCA("OwnTransit relay-admission POC CA", now, value.caValidity)
	if err != nil {
		return err
	}
	innerClientCA, err := pki.NewCA("OwnTransit route capability development CA", now, value.caValidity)
	if err != nil {
		return err
	}
	innerConnectorCA, err := pki.NewCA("OwnTransit inner-connector development CA", now, value.caValidity)
	if err != nil {
		return err
	}

	relayServer, err := pki.IssueLeaf(relayCA, relayDNSName, x509.ExtKeyUsageServerAuth, now, value.validity)
	if err != nil {
		return err
	}
	outerClient, err := pki.IssueLeaf(relayCA, outerClientName, x509.ExtKeyUsageClientAuth, now, value.validity)
	if err != nil {
		return err
	}
	outerConnector, err := pki.IssueLeaf(relayCA, outerConnectorName, x509.ExtKeyUsageClientAuth, now, value.validity)
	if err != nil {
		return err
	}
	innerClient, err := pki.IssueLeaf(innerClientCA, innerClientName, x509.ExtKeyUsageClientAuth, now, value.validity)
	if err != nil {
		return err
	}
	innerConnector, err := pki.IssueLeaf(innerConnectorCA, innerConnectorName, x509.ExtKeyUsageServerAuth, now, value.validity)
	if err != nil {
		return err
	}

	pins := make(map[string]string)
	for name, material := range map[string]pki.Material{
		"relay":           relayServer,
		"outer-client":    outerClient,
		"outer-connector": outerConnector,
		"inner-client":    innerClient,
		"inner-connector": innerConnector,
	} {
		pin, err := identity.SPKIPin(material.Certificate)
		if err != nil {
			return err
		}
		pins[name] = pin
	}

	for _, directory := range []string{"offline-issuers", "relay", "connector", "client", "operator"} {
		if err := os.Mkdir(filepath.Join(value.outputDir, directory), 0o700); err != nil {
			return fmt.Errorf("create %s: %w", directory, err)
		}
	}

	if err := writeMaterial(value.outputDir, "offline-issuers/relay-admission-ca", relayCA, true); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "offline-issuers/inner-client-ca", innerClientCA, true); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "offline-issuers/inner-connector-ca", innerConnectorCA, true); err != nil {
		return err
	}

	if err := writeMaterial(value.outputDir, "relay/outer-server", relayServer, true); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "relay", "relay-admission-ca-cert.pem"), relayCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "connector/outer-connector", outerConnector, true); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "connector/inner-connector", innerConnector, true); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "connector", "relay-admission-ca-cert.pem"), relayCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "connector", "inner-client-ca-cert.pem"), innerClientCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "connector", "inner-connector-ca-cert.pem"), innerConnectorCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "client/outer-client", outerClient, true); err != nil {
		return err
	}
	if err := writeMaterial(value.outputDir, "client/inner-client", innerClient, true); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "client", "relay-admission-ca-cert.pem"), relayCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "client", "inner-connector-ca-cert.pem"), innerConnectorCA.CertPEM, 0o644); err != nil {
		return err
	}
	if err := writeExclusive(filepath.Join(value.outputDir, "client", "inner-client-ca-cert.pem"), innerClientCA.CertPEM, 0o644); err != nil {
		return err
	}

	relayConfig := config.Relay{
		Listen: value.relayListen, Path: config.RelayPath,
		OuterTLS: config.ServerTLS{
			CertFile: "/run/owntransit/outer-server-cert.pem", KeyFile: "/run/owntransit/outer-server-key.pem",
			ClientCAFile: "/run/owntransit/relay-admission-ca-cert.pem", IssuerCAFile: "/run/owntransit/relay-admission-ca-cert.pem",
			LocalDNSName: relayDNSName,
		},
		Clients: []config.AuthorizedPeer{{DNSName: outerClientName, SPKIPins: []string{pins["outer-client"]}}},
		Routes:  []config.RelayRoute{{RouteID: route.String(), DNSName: outerConnectorName, SPKIPins: []string{pins["outer-connector"]}}},
		Limits: config.RelayLimits{
			CarriersGlobal: 96, OuterHandshakes: 32,
			PendingGlobal: 16, PendingPerRoute: 4, PendingPerClient: config.DefaultRelayPendingPerClient,
			ActiveGlobal: 16, ActivePerRoute: 8, ActivePerClient: config.DefaultRelayActivePerClient,
			Handshake: config.Duration(5 * time.Second), Preface: config.Duration(2 * time.Second),
			Join: config.Duration(10 * time.Second), Drain: config.Duration(5 * time.Second),
			SessionIdle: config.Duration(config.DefaultSessionIdle), SessionLifetime: config.Duration(config.DefaultSessionLifetime),
		},
	}
	connectorConfig := config.Connector{
		RelayURL: value.relayURL, AllowInsecureCarrier: allowInsecure,
		InstallationID: connectorID.String(), RouteID: route.String(), InnerProfile: config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: path.Join(value.connectorRuntimeDir, "outer-connector-cert.pem"), KeyFile: path.Join(value.connectorRuntimeDir, "outer-connector-key.pem"),
			CAFile: path.Join(value.connectorRuntimeDir, "relay-admission-ca-cert.pem"), ServerName: relayDNSName, SPKIPins: []string{pins["relay"]},
			IssuerCAFile: path.Join(value.connectorRuntimeDir, "relay-admission-ca-cert.pem"), LocalDNSName: outerConnectorName,
		},
		InnerTLS: config.ConnectorInnerTLS{
			CertFile: path.Join(value.connectorRuntimeDir, "inner-connector-cert.pem"), KeyFile: path.Join(value.connectorRuntimeDir, "inner-connector-key.pem"),
			ClientCAFiles: []string{path.Join(value.connectorRuntimeDir, "inner-client-ca-cert.pem")}, ServerName: innerConnectorName,
			IssuerCAFile: path.Join(value.connectorRuntimeDir, "inner-connector-ca-cert.pem"), LocalDNSName: innerConnectorName,
		},
		SSHTarget: config.ConnectorSSHTarget,
		Limits:    config.ConnectorLimits{Pending: 4, Active: 8, ActivePerClient: config.DefaultConnectorActivePerClient, ConnectTimeout: config.Duration(5 * time.Second), Handshake: config.Duration(10 * time.Second), LocalDial: config.Duration(time.Second), Drain: config.Duration(5 * time.Second), ReconnectMin: config.Duration(time.Second), ReconnectMax: config.Duration(30 * time.Second), SessionIdle: config.Duration(config.DefaultSessionIdle), SessionLifetime: config.Duration(config.DefaultSessionLifetime)},
	}
	clientConfig := config.Client{
		RelayURL: value.relayURL, AllowInsecureCarrier: allowInsecure,
		InstallationID: clientID.String(), ConnectorInstallationID: connectorID.String(), CredentialEpoch: credentialEpoch,
		RouteID: route.String(), InnerProfile: config.InnerProfileRouteCapability,
		OuterTLS: config.ClientTLS{
			CertFile: "/run/owntransit/outer-client-cert.pem", KeyFile: "/run/owntransit/outer-client-key.pem",
			CAFile: "/run/owntransit/relay-admission-ca-cert.pem", ServerName: relayDNSName, SPKIPins: []string{pins["relay"]},
			IssuerCAFile: "/run/owntransit/relay-admission-ca-cert.pem", LocalDNSName: outerClientName,
		},
		InnerTLS: config.ClientTLS{
			CertFile: "/run/owntransit/inner-client-cert.pem", KeyFile: "/run/owntransit/inner-client-key.pem",
			CAFile: "/run/owntransit/inner-connector-ca-cert.pem", ServerName: innerConnectorName, SPKIPins: []string{pins["inner-connector"]},
			IssuerCAFile: "/run/owntransit/inner-client-ca-cert.pem", LocalDNSName: innerClientName,
		},
		ConnectTimeout: config.Duration(5 * time.Second), HandshakeTimeout: config.Duration(10 * time.Second), ReadyTimeout: config.Duration(10 * time.Second), DrainTimeout: config.Duration(5 * time.Second),
	}
	if err := writeJSON(filepath.Join(value.outputDir, "relay", "config.json"), relayConfig); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(value.outputDir, "connector", "config.json"), connectorConfig); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(value.outputDir, "client", "config.json"), clientConfig); err != nil {
		return err
	}

	record := metadata{
		GeneratedAt: now.Format(time.RFC3339), RouteID: route.String(), ClientID: clientID.String(), ConnectorID: connectorID.String(),
		CredentialEpoch: credentialEpoch, InnerProfile: config.InnerProfileRouteCapability, RelayURL: value.relayURL,
		ConnectorRuntimeDir: value.connectorRuntimeDir,
		RelayDNSName:        relayDNSName, OuterClientName: outerClientName, OuterConnectorName: outerConnectorName,
		InnerClientName: innerClientName, InnerConnectorName: innerConnectorName,
		RelayServerPin: pins["relay"], OuterClientPin: pins["outer-client"], OuterConnectorPin: pins["outer-connector"],
		InnerClientPin: pins["inner-client"], InnerConnectorPin: pins["inner-connector"],
	}
	if err := writeJSON(filepath.Join(value.outputDir, "operator", "metadata.json"), record); err != nil {
		return err
	}

	fmt.Printf("created isolated POC credentials in %s\nroute_id=%s\nclient_id=%s\nconnector_id=%s\n", value.outputDir, route.String(), clientID.String(), connectorID.String())
	return nil
}

func validateConnectorRuntimeDir(value string) error {
	if value == "" {
		return errors.New("-connector-runtime-dir is required")
	}
	if !utf8.ValidString(value) {
		return errors.New("-connector-runtime-dir must be valid UTF-8")
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("-connector-runtime-dir must not contain control characters")
	}
	if !path.IsAbs(value) {
		return errors.New("-connector-runtime-dir must be absolute")
	}
	if path.Clean(value) != value {
		return errors.New("-connector-runtime-dir must be a canonical path")
	}
	if value == "/" {
		return errors.New("-connector-runtime-dir must not be the filesystem root")
	}
	return nil
}

func prepareOutput(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output path must be a real directory")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("read output directory: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("output directory is not empty; refusing to overwrite credentials")
	}
	return os.Chmod(path, 0o700)
}

func writeMaterial(root, base string, material pki.Material, includeKey bool) error {
	if err := writeExclusive(filepath.Join(root, base+"-cert.pem"), material.CertPEM, 0o644); err != nil {
		return err
	}
	if includeKey {
		if err := writeExclusive(filepath.Join(root, base+"-key.pem"), material.KeyPEM, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	encoded = append(encoded, '\n')
	return writeExclusive(path, encoded, 0o600)
}

func writeExclusive(path string, contents []byte, mode fs.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	return nil
}
