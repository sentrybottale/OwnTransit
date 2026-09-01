// Package runtimebundle deterministically renders validated OwnTransit runtime
// files in memory. It never creates directories, writes files, or activates a
// generation.
package runtimebundle

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const (
	configBase            = "config.json"
	outerCertificateBase  = "outer-cert.pem"
	outerPrivateKeyBase   = "outer-key.pem"
	innerCertificateBase  = "inner-cert.pem"
	innerPrivateKeyBase   = "inner-key.pem"
	relayAdmissionCABase  = "relay-admission-ca-cert.pem"
	innerClientCABase     = "inner-client-ca-cert.pem"
	innerClientCANextBase = "inner-client-ca-cert-next.pem"
	innerConnectorCABase  = "inner-connector-ca-cert.pem"
	runtimeFileMode       = fs.FileMode(0o600)
)

// PrivateKeys contains exact canonical PKCS#8 Ed25519 PEM bytes retained by
// the target that created the enrollment request. Relay deployments leave
// InnerPEM empty.
type PrivateKeys struct {
	OuterPEM []byte
	InnerPEM []byte
}

// ConnectorRevocations is locally authenticated, signed-state-rendered
// connector policy. It is invalid for client and relay bundles.
type ConnectorRevocations struct {
	ClientIDs []string
	SPKIPins  []string
}

// VerifierPolicy is an already authenticated lifecycle overlay. It changes
// only verifier inputs in the rendered generation; it cannot select a route,
// target, endpoint identity, or private key. Empty verifier lists retain the
// signed deployment values for initial enrollment compatibility.
type VerifierPolicy struct {
	CapabilityClientRoots []string
	RelayServerSPKIPins   []string
	ConnectorSPKIPins     []string
	RelayClients          []config.AuthorizedPeer
	RelayRoutes           []config.RelayRoute
	Revocations           ConnectorRevocations
}

// File is one immutable generation member. Contents owns its byte slice. Every
// file is private to the runtime owner, including public certificates, because
// lifecycle recovery requires exact mode checks inside a 0700 generation.
type File struct {
	Path     string
	Mode     fs.FileMode
	Contents []byte
}

type generationPaths struct {
	config            string
	outerCertificate  string
	outerPrivateKey   string
	innerCertificate  string
	innerPrivateKey   string
	relayAdmissionCA  string
	innerClientCA     string
	innerClientCANext string
	innerConnectorCA  string
}

// Render revalidates an already activation-authorized deployment and renders
// an ordered, write-free generation. Render is deliberately not an activation
// gate: the caller must first authenticate and bind the deployment with the
// enrollment/lifecycle VerifyForApply flow and must transactionally install the
// returned files afterwards.
func Render(deployment enrollment.Deployment, generationDirectory string, keys PrivateKeys, revocations ConnectorRevocations, now time.Time) ([]File, error) {
	return RenderWithPolicy(deployment, generationDirectory, keys, VerifierPolicy{Revocations: revocations}, now)
}

// RenderWithPolicy renders a signed verifier-first lifecycle overlay together
// with the deployment. Exactly two capability roots are possible only while
// the connector config's explicit rotation marker is true.
func RenderWithPolicy(deployment enrollment.Deployment, generationDirectory string, keys PrivateKeys, policy VerifierPolicy, now time.Time) ([]File, error) {
	paths, err := derivePaths(generationDirectory)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, errors.New("runtimebundle: explicit validation time is required")
	}
	if err := deployment.Validate(now); err != nil {
		return nil, fmt.Errorf("runtimebundle: deployment: %w", err)
	}
	if deployment.Role != enrollment.RoleConnector && (len(policy.Revocations.ClientIDs) != 0 || len(policy.Revocations.SPKIPins) != 0 || len(policy.CapabilityClientRoots) != 0) {
		return nil, errors.New("runtimebundle: connector revocations are invalid for this role")
	}
	if len(policy.Revocations.ClientIDs) > config.MaxCapabilityRevocations ||
		len(policy.Revocations.SPKIPins) > config.MaxCapabilityRevocations-len(policy.Revocations.ClientIDs) {
		return nil, fmt.Errorf("runtimebundle: connector revocations exceed combined limit %d", config.MaxCapabilityRevocations)
	}
	if err := validatePolicyRoleFields(deployment.Role, policy); err != nil {
		return nil, err
	}

	outerCertificate, outerCertificatePEM, err := parseExactCertificate([]byte(deployment.OuterCertificate), "outer certificate")
	if err != nil {
		return nil, err
	}
	outerKeyPEM, outerSPKI, err := validatePrivateKey(keys.OuterPEM, outerCertificate, "outer private key")
	if err != nil {
		return nil, err
	}

	var innerCertificatePEM, innerKeyPEM []byte
	if deployment.Role == enrollment.RoleRelay {
		if deployment.InnerCertificate != "" || len(keys.InnerPEM) != 0 {
			return nil, errors.New("runtimebundle: relay must not contain an inner certificate or private key")
		}
	} else {
		innerCertificate, encoded, parseErr := parseExactCertificate([]byte(deployment.InnerCertificate), "inner certificate")
		if parseErr != nil {
			return nil, parseErr
		}
		innerCertificatePEM = encoded
		var innerSPKI []byte
		innerKeyPEM, innerSPKI, err = validatePrivateKey(keys.InnerPEM, innerCertificate, "inner private key")
		if err != nil {
			return nil, err
		}
		if bytes.Equal(outerSPKI, innerSPKI) {
			return nil, errors.New("runtimebundle: outer and inner private keys must be distinct")
		}
	}

	_, relayCAPEM, err := parseExactCertificate([]byte(deployment.Trust.RelayAdmissionCA), "relay admission CA")
	if err != nil {
		return nil, err
	}
	clientRoots := policy.CapabilityClientRoots
	if len(clientRoots) == 0 {
		clientRoots = []string{deployment.Trust.InnerClientCA}
	}
	innerClientCAPEMs := make([][]byte, len(clientRoots))
	for index, root := range clientRoots {
		certificate, encoded, parseErr := parseExactCertificate([]byte(root), fmt.Sprintf("inner client CA %d", index))
		if parseErr != nil || !exactRootProfile(certificate) {
			return nil, fmt.Errorf("runtimebundle: inner client CA %d is not an exact root profile", index)
		}
		innerClientCAPEMs[index] = encoded
		if index > 0 && bytes.Equal(innerClientCAPEMs[index-1], encoded) {
			return nil, errors.New("runtimebundle: capability client roots must be distinct")
		}
	}
	if deployment.Role == enrollment.RoleConnector && (len(innerClientCAPEMs) < 1 || len(innerClientCAPEMs) > config.MaxCapabilityClientCAs) {
		return nil, errors.New("runtimebundle: connector capability root count is invalid")
	}
	if deployment.Role != enrollment.RoleConnector && len(policy.CapabilityClientRoots) != 0 {
		return nil, errors.New("runtimebundle: capability root policy is connector-only")
	}
	_, innerConnectorCAPEM, err := parseExactCertificate([]byte(deployment.Trust.InnerConnectorCA), "inner connector CA")
	if err != nil {
		return nil, err
	}

	configuration, err := renderConfiguration(deployment, paths, policy)
	if err != nil {
		return nil, err
	}
	files := []File{
		newFile(paths.config, configuration),
		newFile(paths.outerCertificate, outerCertificatePEM),
		newFile(paths.outerPrivateKey, outerKeyPEM),
		newFile(paths.relayAdmissionCA, relayCAPEM),
	}
	if deployment.Role != enrollment.RoleRelay {
		files = append(files,
			newFile(paths.innerCertificate, innerCertificatePEM),
			newFile(paths.innerPrivateKey, innerKeyPEM),
			newFile(paths.innerClientCA, innerClientCAPEMs[0]),
			newFile(paths.innerConnectorCA, innerConnectorCAPEM),
		)
		if deployment.Role == enrollment.RoleConnector && len(innerClientCAPEMs) == 2 {
			files = append(files, newFile(paths.innerClientCANext, innerClientCAPEMs[1]))
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

// RebaseVerifiedFiles copies only the active runtime material from an already
// manifest-verified private generation and renders a configuration whose paths
// name the read-only runtime namespace. Request bytes, deployment inputs,
// journals, policies, future credentials and retained rollback records are not
// members of the returned set.
//
// The caller remains responsible for binding source to an authenticated record
// and for publishing the result transactionally. This function does not read
// paths or write files.
func RebaseVerifiedFiles(role enrollment.Role, source map[string][]byte, generationDirectory string) ([]File, error) {
	paths, err := derivePaths(generationDirectory)
	if err != nil {
		return nil, err
	}
	configuration, expected, err := rebaseConfiguration(role, source[configBase], paths)
	if err != nil {
		return nil, err
	}
	result := make([]File, 0, len(expected))
	for _, name := range expected {
		contents := source[name]
		if name == configBase {
			contents = configuration
		}
		if len(contents) == 0 || int64(len(contents)) > secureRuntimeFileLimit {
			return nil, fmt.Errorf("runtimebundle: verified runtime file %q is absent or exceeds its bound", name)
		}
		result = append(result, newFile(filepath.Join(generationDirectory, name), contents))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

const secureRuntimeFileLimit = 4 << 20

func rebaseConfiguration(role enrollment.Role, encoded []byte, paths generationPaths) ([]byte, []string, error) {
	expected := []string{configBase, outerCertificateBase, outerPrivateKeyBase, relayAdmissionCABase}
	var value any
	switch role {
	case enrollment.RoleClient:
		configuration, err := config.ParseClient(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: parse verified client config: %w", err)
		}
		configuration.CarrierCAFile = ""
		configuration.OuterTLS.CertFile = paths.outerCertificate
		configuration.OuterTLS.KeyFile = paths.outerPrivateKey
		configuration.OuterTLS.CAFile = paths.relayAdmissionCA
		configuration.OuterTLS.IssuerCAFile = paths.relayAdmissionCA
		configuration.InnerTLS.CertFile = paths.innerCertificate
		configuration.InnerTLS.KeyFile = paths.innerPrivateKey
		configuration.InnerTLS.CAFile = paths.innerConnectorCA
		configuration.InnerTLS.IssuerCAFile = paths.innerClientCA
		if err := configuration.Validate(); err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: rebased client config: %w", err)
		}
		value = configuration
		expected = append(expected, innerCertificateBase, innerPrivateKeyBase, innerClientCABase, innerConnectorCABase)
	case enrollment.RoleConnector:
		configuration, err := config.ParseConnector(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: parse verified connector config: %w", err)
		}
		configuration.CarrierCAFile = ""
		configuration.OuterTLS.CertFile = paths.outerCertificate
		configuration.OuterTLS.KeyFile = paths.outerPrivateKey
		configuration.OuterTLS.CAFile = paths.relayAdmissionCA
		configuration.OuterTLS.IssuerCAFile = paths.relayAdmissionCA
		configuration.InnerTLS.CertFile = paths.innerCertificate
		configuration.InnerTLS.KeyFile = paths.innerPrivateKey
		configuration.InnerTLS.IssuerCAFile = paths.innerConnectorCA
		configuration.InnerTLS.ClientCAFiles = []string{paths.innerClientCA}
		if configuration.InnerTLS.ClientCARotation {
			configuration.InnerTLS.ClientCAFiles = append(configuration.InnerTLS.ClientCAFiles, paths.innerClientCANext)
			expected = append(expected, innerClientCANextBase)
		}
		if err := configuration.Validate(); err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: rebased connector config: %w", err)
		}
		value = configuration
		expected = append(expected, innerCertificateBase, innerPrivateKeyBase, innerClientCABase, innerConnectorCABase)
	case enrollment.RoleRelay:
		configuration, err := config.ParseRelay(encoded)
		if err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: parse verified relay config: %w", err)
		}
		if configuration.Listen != enrollment.PackagedRelayListen {
			return nil, nil, errors.New("runtimebundle: relay listen does not match the packaged container contract")
		}
		configuration.OuterTLS.CertFile = paths.outerCertificate
		configuration.OuterTLS.KeyFile = paths.outerPrivateKey
		configuration.OuterTLS.ClientCAFile = paths.relayAdmissionCA
		configuration.OuterTLS.IssuerCAFile = paths.relayAdmissionCA
		if err := configuration.Validate(); err != nil {
			return nil, nil, fmt.Errorf("runtimebundle: rebased relay config: %w", err)
		}
		value = configuration
	default:
		return nil, nil, errors.New("runtimebundle: unsupported verified runtime role")
	}
	sort.Strings(expected)
	encodedValue, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, nil, fmt.Errorf("runtimebundle: encode rebased config: %w", err)
	}
	return append(encodedValue, '\n'), expected, nil
}

func derivePaths(directory string) (generationPaths, error) {
	if directory == "" || !utf8.ValidString(directory) || strings.IndexFunc(directory, unicode.IsControl) >= 0 ||
		!filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Dir(directory) == directory {
		return generationPaths{}, errors.New("runtimebundle: generation directory must be an absolute canonical non-root path")
	}
	join := func(base string) string { return filepath.Join(directory, base) }
	return generationPaths{
		config: join(configBase), outerCertificate: join(outerCertificateBase), outerPrivateKey: join(outerPrivateKeyBase),
		innerCertificate: join(innerCertificateBase), innerPrivateKey: join(innerPrivateKeyBase),
		relayAdmissionCA: join(relayAdmissionCABase), innerClientCA: join(innerClientCABase),
		innerClientCANext: join(innerClientCANextBase), innerConnectorCA: join(innerConnectorCABase),
	}, nil
}

func parseExactCertificate(encoded []byte, name string) (*x509.Certificate, []byte, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(encoded, pem.EncodeToMemory(block)) {
		return nil, nil, fmt.Errorf("runtimebundle: %s must be one canonical headerless CERTIFICATE PEM block", name)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("runtimebundle: parse %s: %w", name, err)
	}
	return certificate, append([]byte(nil), encoded...), nil
}

func exactRootProfile(certificate *x509.Certificate) bool {
	if certificate == nil || !certificate.BasicConstraintsValid || !certificate.IsCA ||
		!certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign ||
		len(certificate.ExtKeyUsage) != 0 || len(certificate.UnknownExtKeyUsage) != 0 ||
		certificate.SignatureAlgorithm != x509.PureEd25519 {
		return false
	}
	return certificate.CheckSignatureFrom(certificate) == nil
}

func validatePolicyRoleFields(role enrollment.Role, policy VerifierPolicy) error {
	switch role {
	case enrollment.RoleConnector:
		if len(policy.ConnectorSPKIPins) != 0 || len(policy.RelayClients) != 0 || len(policy.RelayRoutes) != 0 {
			return errors.New("runtimebundle: connector verifier policy contains another role's fields")
		}
	case enrollment.RoleClient:
		if len(policy.CapabilityClientRoots) != 0 || len(policy.Revocations.ClientIDs) != 0 || len(policy.Revocations.SPKIPins) != 0 ||
			len(policy.RelayClients) != 0 || len(policy.RelayRoutes) != 0 {
			return errors.New("runtimebundle: client verifier policy contains another role's fields")
		}
	case enrollment.RoleRelay:
		if len(policy.CapabilityClientRoots) != 0 || len(policy.Revocations.ClientIDs) != 0 || len(policy.Revocations.SPKIPins) != 0 ||
			len(policy.RelayServerSPKIPins) != 0 || len(policy.ConnectorSPKIPins) != 0 {
			return errors.New("runtimebundle: relay verifier policy contains another role's fields")
		}
	default:
		return errors.New("runtimebundle: unsupported deployment role")
	}
	return nil
}

func capabilityRootPaths(paths generationPaths, explicit int) []string {
	if explicit == 2 {
		return []string{paths.innerClientCA, paths.innerClientCANext}
	}
	return []string{paths.innerClientCA}
}

func firstStrings(preferred, fallback []string) []string {
	if len(preferred) != 0 {
		return append([]string(nil), preferred...)
	}
	return append([]string(nil), fallback...)
}

func firstPeers(preferred, fallback []config.AuthorizedPeer) []config.AuthorizedPeer {
	if len(preferred) != 0 {
		return preferred
	}
	return fallback
}

func firstRoutes(preferred, fallback []config.RelayRoute) []config.RelayRoute {
	if len(preferred) != 0 {
		return preferred
	}
	return fallback
}

func validatePrivateKey(encoded []byte, certificate *x509.Certificate, name string) ([]byte, []byte, error) {
	privateKey, err := signing.ParsePrivate(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("runtimebundle: %s: %w", name, err)
	}
	publicSPKI, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, nil, fmt.Errorf("runtimebundle: marshal %s public key: %w", name, err)
	}
	if certificate == nil || !bytes.Equal(publicSPKI, certificate.RawSubjectPublicKeyInfo) {
		return nil, nil, fmt.Errorf("runtimebundle: %s does not match its deployment leaf", name)
	}
	return append([]byte(nil), encoded...), publicSPKI, nil
}

func renderConfiguration(deployment enrollment.Deployment, paths generationPaths, policy VerifierPolicy) ([]byte, error) {
	var value any
	switch deployment.Role {
	case enrollment.RoleRelay:
		value = config.Relay{
			Listen:                               deployment.RelayListen,
			Path:                                 config.RelayPath,
			EnrollmentAllocationCapabilitySHA256: deployment.Relay.EnrollmentAllocationCapabilitySHA256,
			OuterTLS: config.ServerTLS{
				CertFile: paths.outerCertificate, KeyFile: paths.outerPrivateKey, ClientCAFile: paths.relayAdmissionCA,
				IssuerCAFile: paths.relayAdmissionCA, LocalDNSName: deployment.OuterDNSName,
			},
			Clients: cloneAuthorizedPeers(firstPeers(policy.RelayClients, deployment.Relay.Clients)),
			Routes:  cloneRelayRoutes(firstRoutes(policy.RelayRoutes, deployment.Relay.Routes)),
			Limits:  defaultRelayLimits(),
		}
		if err := value.(config.Relay).Validate(); err != nil {
			return nil, fmt.Errorf("runtimebundle: rendered relay config: %w", err)
		}
	case enrollment.RoleConnector:
		value = config.Connector{
			RelayURL: deployment.RelayURL, InstallationID: deployment.InstallationID, RouteID: deployment.RouteID,
			InnerProfile: config.InnerProfileRouteCapability,
			OuterTLS: config.ClientTLS{
				CertFile: paths.outerCertificate, KeyFile: paths.outerPrivateKey, CAFile: paths.relayAdmissionCA,
				ServerName: config.RelayDNSName, SPKIPins: firstStrings(policy.RelayServerSPKIPins, deployment.Connector.RelayServerPins),
				IssuerCAFile: paths.relayAdmissionCA, LocalDNSName: deployment.OuterDNSName,
			},
			InnerTLS: config.ConnectorInnerTLS{
				CertFile: paths.innerCertificate, KeyFile: paths.innerPrivateKey,
				ClientCAFiles: capabilityRootPaths(paths, len(policy.CapabilityClientRoots)), IssuerCAFile: paths.innerConnectorCA,
				LocalDNSName: deployment.InnerDNSName, ServerName: deployment.InnerDNSName,
				ClientCARotation:   len(policy.CapabilityClientRoots) == 2,
				RevokedClientIDs:   append([]string(nil), policy.Revocations.ClientIDs...),
				RevokedClientSPKIs: append([]string(nil), policy.Revocations.SPKIPins...),
			},
			SSHTarget: config.ConnectorSSHTarget,
			Limits:    defaultConnectorLimits(),
		}
		if err := value.(config.Connector).Validate(); err != nil {
			return nil, fmt.Errorf("runtimebundle: rendered connector config: %w", err)
		}
	case enrollment.RoleClient:
		value = config.Client{
			RelayURL: deployment.RelayURL, InstallationID: deployment.InstallationID,
			ConnectorInstallationID: deployment.ConnectorInstallationID, CredentialEpoch: deployment.CredentialEpoch,
			RouteID: deployment.RouteID, InnerProfile: config.InnerProfileRouteCapability,
			OuterTLS: config.ClientTLS{
				CertFile: paths.outerCertificate, KeyFile: paths.outerPrivateKey, CAFile: paths.relayAdmissionCA,
				ServerName: config.RelayDNSName, SPKIPins: firstStrings(policy.RelayServerSPKIPins, deployment.Client.RelayServerPins),
				IssuerCAFile: paths.relayAdmissionCA, LocalDNSName: deployment.OuterDNSName,
			},
			InnerTLS: config.ClientTLS{
				CertFile: paths.innerCertificate, KeyFile: paths.innerPrivateKey, CAFile: paths.innerConnectorCA,
				ServerName: deployment.Client.ConnectorDNSName, SPKIPins: firstStrings(policy.ConnectorSPKIPins, deployment.Client.ConnectorSPKIPins),
				IssuerCAFile: paths.innerClientCA, LocalDNSName: deployment.InnerDNSName,
			},
			ConnectTimeout: config.Duration(5 * time.Second), HandshakeTimeout: config.Duration(10 * time.Second),
			ReadyTimeout: config.Duration(10 * time.Second), DrainTimeout: config.Duration(5 * time.Second),
		}
		if err := value.(config.Client).Validate(); err != nil {
			return nil, fmt.Errorf("runtimebundle: rendered client config: %w", err)
		}
	default:
		return nil, errors.New("runtimebundle: unsupported deployment role")
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("runtimebundle: encode config: %w", err)
	}
	return append(encoded, '\n'), nil
}

func defaultRelayLimits() config.RelayLimits {
	return config.RelayLimits{
		CarriersGlobal: 96, OuterHandshakes: 32,
		PendingGlobal: 16, PendingPerRoute: 4, PendingPerClient: config.DefaultRelayPendingPerClient,
		ActiveGlobal: 16, ActivePerRoute: 8, ActivePerClient: config.DefaultRelayActivePerClient,
		Handshake: config.Duration(5 * time.Second), Preface: config.Duration(2 * time.Second),
		Join: config.Duration(10 * time.Second), Drain: config.Duration(5 * time.Second),
		SessionIdle: config.Duration(config.DefaultSessionIdle), SessionLifetime: config.Duration(config.DefaultSessionLifetime),
	}
}

func defaultConnectorLimits() config.ConnectorLimits {
	return config.ConnectorLimits{
		Pending: 4, Active: 8, ActivePerClient: config.DefaultConnectorActivePerClient,
		ConnectTimeout: config.Duration(5 * time.Second), Handshake: config.Duration(10 * time.Second),
		LocalDial: config.Duration(time.Second), Drain: config.Duration(5 * time.Second),
		ReconnectMin: config.Duration(time.Second), ReconnectMax: config.Duration(30 * time.Second),
		SessionIdle: config.Duration(config.DefaultSessionIdle), SessionLifetime: config.Duration(config.DefaultSessionLifetime),
	}
}

func cloneAuthorizedPeers(values []config.AuthorizedPeer) []config.AuthorizedPeer {
	result := make([]config.AuthorizedPeer, len(values))
	for index, value := range values {
		result[index] = config.AuthorizedPeer{DNSName: value.DNSName, SPKIPins: append([]string(nil), value.SPKIPins...)}
	}
	return result
}

func cloneRelayRoutes(values []config.RelayRoute) []config.RelayRoute {
	result := make([]config.RelayRoute, len(values))
	for index, value := range values {
		result[index] = config.RelayRoute{RouteID: value.RouteID, DNSName: value.DNSName, SPKIPins: append([]string(nil), value.SPKIPins...)}
	}
	return result
}

func newFile(path string, contents []byte) File {
	return File{Path: path, Mode: runtimeFileMode, Contents: append([]byte(nil), contents...)}
}
