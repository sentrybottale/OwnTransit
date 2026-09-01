package enrollment

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const (
	DeploymentSchema           = "owntransit.deployment.v1"
	DeploymentProtocol         = wireprofile.LegacyV1Protocol
	CurrentLifecycleGeneration = 1
	MaxDeploymentValidity      = 90 * 24 * time.Hour
	// PackagedRelayListen is the only listener compatible with the v1
	// rootless-container systemd publish contract. Host exposure remains fixed
	// separately to 127.0.0.1:9087.
	PackagedRelayListen = "0.0.0.0:9087"
)

type Deployment struct {
	Schema                  string                  `json:"schema"`
	Protocol                string                  `json:"protocol"`
	MinimumLifecycle        uint64                  `json:"minimum_lifecycle"`
	Role                    Role                    `json:"role"`
	InstallationID          string                  `json:"installation_id"`
	ConnectorInstallationID string                  `json:"connector_installation_id"`
	RequestNonce            string                  `json:"request_nonce"`
	RequestSHA256           string                  `json:"request_sha256"`
	RequestSequence         uint64                  `json:"request_sequence"`
	DeploymentSequence      uint64                  `json:"deployment_sequence"`
	CredentialEpoch         uint64                  `json:"credential_epoch"`
	Runtime                 RuntimeBinding          `json:"runtime"`
	IssuedUnix              int64                   `json:"issued_unix"`
	ExpiresUnix             int64                   `json:"expires_unix"`
	RouteID                 string                  `json:"route_id"`
	RelayURL                string                  `json:"relay_url,omitempty"`
	RelayListen             string                  `json:"relay_listen,omitempty"`
	OuterDNSName            string                  `json:"outer_dns_name"`
	InnerDNSName            string                  `json:"inner_dns_name,omitempty"`
	OuterCertificate        string                  `json:"outer_certificate_pem"`
	InnerCertificate        string                  `json:"inner_certificate_pem,omitempty"`
	Trust                   Trust                   `json:"trust"`
	Client                  *ClientAuthorization    `json:"client,omitempty"`
	Connector               *ConnectorAuthorization `json:"connector,omitempty"`
	Relay                   *RelayAuthorization     `json:"relay,omitempty"`
}

type Trust struct {
	RelayAdmissionCA string `json:"relay_admission_ca_pem"`
	InnerClientCA    string `json:"inner_client_ca_pem"`
	InnerConnectorCA string `json:"inner_connector_ca_pem"`
}

type ClientAuthorization struct {
	RelayServerPins   []string `json:"relay_server_spki_sha256"`
	ConnectorDNSName  string   `json:"connector_dns_name"`
	ConnectorSPKIPins []string `json:"connector_spki_sha256"`
}

type ConnectorAuthorization struct {
	RelayServerPins           []string `json:"relay_server_spki_sha256"`
	InnerAuthorizationProfile string   `json:"inner_authorization_profile"`
}

type RelayAuthorization struct {
	Clients                              []config.AuthorizedPeer `json:"clients"`
	Routes                               []config.RelayRoute     `json:"routes"`
	EnrollmentAllocationCapabilitySHA256 string                  `json:"enrollment_allocation_capability_sha256,omitempty"`
}

func EncodeDeployment(deployment Deployment) ([]byte, error) {
	if err := deployment.Validate(time.Unix(deployment.IssuedUnix, 0)); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(deployment)
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode deployment: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxPayloadSize {
		return nil, errors.New("enrollment: deployment exceeds payload limit")
	}
	return encoded, nil
}

func parseDeployment(encoded []byte, now time.Time) (Deployment, error) {
	if len(encoded) == 0 || len(encoded) > MaxPayloadSize {
		return Deployment{}, errors.New("enrollment: deployment payload has an invalid size")
	}
	var deployment Deployment
	if err := strictjson.Decode(encoded, &deployment); err != nil {
		return Deployment{}, fmt.Errorf("enrollment: decode deployment: %w", err)
	}
	if err := deployment.Validate(now); err != nil {
		return Deployment{}, err
	}
	return deployment, nil
}

// ParseBoundDeployment is the only activation-safe deployment parser. It
// validates structure and certificates, then binds them to the exact locally
// retained request—including the issuer pins selected before enrollment.
func ParseBoundDeployment(encoded, requestBytes []byte, now time.Time) (Deployment, error) {
	deployment, err := parseDeployment(encoded, now)
	if err != nil {
		return Deployment{}, err
	}
	if err := deployment.ValidateRequestBinding(requestBytes, now); err != nil {
		return Deployment{}, err
	}
	return deployment, nil
}

func (deployment Deployment) Validate(now time.Time) error {
	if deployment.Schema != DeploymentSchema {
		return errors.New("enrollment: unsupported deployment schema")
	}
	if deployment.Protocol != DeploymentProtocol || deployment.MinimumLifecycle == 0 || deployment.MinimumLifecycle > CurrentLifecycleGeneration {
		return errors.New("enrollment: unsupported deployment protocol or lifecycle floor")
	}
	installationID, err := protocol.ParseID(deployment.InstallationID)
	if err != nil || installationID == (protocol.ID{}) {
		return errors.New("enrollment: deployment installation ID is invalid")
	}
	connectorInstallationID, err := protocol.ParseID(deployment.ConnectorInstallationID)
	if err != nil || connectorInstallationID == (protocol.ID{}) {
		return errors.New("enrollment: deployment connector installation ID is invalid")
	}
	nonce, err := protocol.ParseID(deployment.RequestNonce)
	if err != nil || nonce == (protocol.ID{}) || !validSHA256(deployment.RequestSHA256) {
		return errors.New("enrollment: deployment request binding is invalid")
	}
	if deployment.RequestSequence == 0 || deployment.DeploymentSequence == 0 || deployment.CredentialEpoch == 0 {
		return errors.New("enrollment: deployment sequences and epoch must be positive")
	}
	if deployment.IssuedUnix <= 0 || deployment.ExpiresUnix <= deployment.IssuedUnix ||
		deployment.ExpiresUnix-deployment.IssuedUnix > int64(MaxDeploymentValidity/time.Second) ||
		now.Before(time.Unix(deployment.IssuedUnix, 0).Add(-5*time.Minute)) || !now.Before(time.Unix(deployment.ExpiresUnix, 0)) {
		return errors.New("enrollment: deployment is not currently valid")
	}
	if err := deployment.Runtime.Validate(deployment.Role); err != nil {
		return err
	}
	route, err := protocol.ParseRouteID(deployment.RouteID)
	if err != nil || route == (protocol.RouteID{}) {
		return errors.New("enrollment: deployment route ID is invalid")
	}

	relayCA, err := parseCA([]byte(deployment.Trust.RelayAdmissionCA))
	if err != nil {
		return fmt.Errorf("enrollment: relay admission CA: %w", err)
	}
	innerClientCA, err := parseCA([]byte(deployment.Trust.InnerClientCA))
	if err != nil {
		return fmt.Errorf("enrollment: inner client CA: %w", err)
	}
	innerConnectorCA, err := parseCA([]byte(deployment.Trust.InnerConnectorCA))
	if err != nil {
		return fmt.Errorf("enrollment: inner connector CA: %w", err)
	}

	var expectedOuter, expectedInner string
	var outerUsage, innerUsage x509.ExtKeyUsage
	var outerIssuer, innerIssuer *x509.Certificate
	switch deployment.Role {
	case RoleClient:
		expectedOuter = config.OuterClientDNSName(installationID)
		expectedInner = config.ClientCapabilityDNSName(installationID, connectorInstallationID, route, deployment.CredentialEpoch)
		outerUsage, innerUsage = x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageClientAuth
		outerIssuer, innerIssuer = relayCA, innerClientCA
		if deployment.Client == nil || deployment.Connector != nil || deployment.Relay != nil || deployment.RelayListen != "" {
			return errors.New("enrollment: client deployment has invalid role fields")
		}
		if err := validateRelayURL(deployment.RelayURL); err != nil {
			return err
		}
		if deployment.Client.ConnectorDNSName != config.CapabilityConnectorDNSName(connectorInstallationID, route) {
			return errors.New("enrollment: client connector identity does not match route")
		}
		if err := validatePins(deployment.Client.RelayServerPins, deployment.Client.ConnectorSPKIPins); err != nil {
			return err
		}
	case RoleConnector:
		if connectorInstallationID != installationID {
			return errors.New("enrollment: connector deployment does not bind its own installation ID")
		}
		expectedOuter = config.OuterConnectorDNSName(route)
		expectedInner = config.CapabilityConnectorDNSName(installationID, route)
		outerUsage, innerUsage = x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth
		outerIssuer, innerIssuer = relayCA, innerConnectorCA
		if deployment.Connector == nil || deployment.Client != nil || deployment.Relay != nil || deployment.RelayListen != "" {
			return errors.New("enrollment: connector deployment has invalid role fields")
		}
		if err := validateRelayURL(deployment.RelayURL); err != nil {
			return err
		}
		if err := validatePins(deployment.Connector.RelayServerPins); err != nil || deployment.Connector.InnerAuthorizationProfile != config.InnerProfileRouteCapability {
			return errors.New("enrollment: connector capability authorization is empty or invalid")
		}
	case RoleRelay:
		expectedOuter = config.RelayDNSName
		outerUsage, outerIssuer = x509.ExtKeyUsageServerAuth, relayCA
		if deployment.Relay == nil || deployment.Client != nil || deployment.Connector != nil || deployment.RelayURL != "" || deployment.InnerCertificate != "" || deployment.InnerDNSName != "" {
			return errors.New("enrollment: relay deployment has invalid role fields")
		}
		if err := config.ValidateRelayListen(deployment.RelayListen); err != nil {
			return fmt.Errorf("enrollment: relay listen: %w", err)
		}
		if deployment.RelayListen != PackagedRelayListen {
			return errors.New("enrollment: relay listen does not match the packaged container contract")
		}
		if len(deployment.Relay.Clients) != 1 || len(deployment.Relay.Routes) != 1 {
			return errors.New("enrollment: initial relay deployment must contain one client and one route")
		}
		if value := deployment.Relay.EnrollmentAllocationCapabilitySHA256; value != "" && (len(value) != 64 || value != strings.ToLower(value)) {
			return errors.New("enrollment: relay enrollment allocation hash is invalid")
		} else if value != "" {
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) != sha256.Size {
				return errors.New("enrollment: relay enrollment allocation hash is invalid")
			}
		}
		for _, peer := range deployment.Relay.Clients {
			if err := identity.ValidateDNSName(peer.DNSName); err != nil || validatePins(peer.SPKIPins) != nil {
				return errors.New("enrollment: relay client authorization is invalid")
			}
		}
		for _, grant := range deployment.Relay.Routes {
			if grant.RouteID != route.String() || grant.DNSName != config.OuterConnectorDNSName(route) || validatePins(grant.SPKIPins) != nil {
				return errors.New("enrollment: relay route authorization is invalid")
			}
		}
	default:
		return errors.New("enrollment: deployment role is invalid")
	}
	if deployment.OuterDNSName != expectedOuter {
		return errors.New("enrollment: outer identity does not match role")
	}
	outerCertificate, err := validateCertificate([]byte(deployment.OuterCertificate), outerIssuer, expectedOuter, outerUsage, now)
	if err != nil {
		return fmt.Errorf("enrollment: outer certificate: %w", err)
	}
	_ = outerCertificate
	if deployment.Role != RoleRelay {
		if deployment.InnerDNSName != expectedInner || deployment.InnerCertificate == "" {
			return errors.New("enrollment: inner identity does not match role")
		}
		if _, err := validateCertificate([]byte(deployment.InnerCertificate), innerIssuer, expectedInner, innerUsage, now); err != nil {
			return fmt.Errorf("enrollment: inner certificate: %w", err)
		}
	}
	return nil
}

func (deployment Deployment) ValidateRequestBinding(requestBytes []byte, now time.Time) error {
	request, err := ParseRequest(requestBytes, time.Unix(deployment.IssuedUnix, 0))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(requestBytes)
	if deployment.Role != request.Role || deployment.InstallationID != request.InstallationID ||
		deployment.RequestNonce != request.Nonce || deployment.RequestSequence != request.Sequence ||
		deployment.CredentialEpoch != request.Sequence || deployment.RequestSHA256 != hex.EncodeToString(digest[:]) || deployment.Runtime != request.Runtime {
		return errors.New("enrollment: deployment does not bind the exact request")
	}
	switch request.Role {
	case RoleClient:
		if deployment.ConnectorInstallationID != request.ConnectorInstallationID || deployment.RouteID != request.RouteID {
			return errors.New("enrollment: client deployment changed the requested connector capability")
		}
	case RoleConnector:
		if deployment.ConnectorInstallationID != request.InstallationID || deployment.RouteID != request.RouteID {
			return errors.New("enrollment: connector deployment changed its route or installation binding")
		}
	}
	if err := deployment.ValidatePinnedIssuers(request.IssuerPins); err != nil {
		return err
	}
	outerRequest, innerRequest, _, err := requestCSRs(request)
	if err != nil {
		return err
	}
	outerCertificate, err := parseCertificate([]byte(deployment.OuterCertificate))
	if err != nil || !bytes.Equal(outerCertificate.RawSubjectPublicKeyInfo, outerRequest.RawSubjectPublicKeyInfo) {
		return errors.New("enrollment: outer certificate does not match requested key")
	}
	if request.Role != RoleRelay {
		innerCertificate, err := parseCertificate([]byte(deployment.InnerCertificate))
		if err != nil || !bytes.Equal(innerCertificate.RawSubjectPublicKeyInfo, innerRequest.RawSubjectPublicKeyInfo) {
			return errors.New("enrollment: inner certificate does not match requested key")
		}
	}
	return deployment.Validate(now)
}

// ValidatePinnedIssuers proves that roots carried for local rendering are the
// exact issuer certificates selected independently by the target. Trust does
// not originate in the deployment envelope.
func (deployment Deployment) ValidatePinnedIssuers(expected IssuerPins) error {
	if err := expected.Validate(); err != nil {
		return err
	}
	checks := []struct {
		name string
		pem  string
		pin  string
	}{
		{"relay admission CA", deployment.Trust.RelayAdmissionCA, expected.RelayAdmissionCA},
		{"inner client CA", deployment.Trust.InnerClientCA, expected.InnerClientCA},
		{"inner connector CA", deployment.Trust.InnerConnectorCA, expected.InnerConnectorCA},
	}
	for _, check := range checks {
		certificate, err := parseCA([]byte(check.pem))
		if err != nil {
			return fmt.Errorf("enrollment: %s: %w", check.name, err)
		}
		actual, err := pki.CertificatePin(certificate)
		if err != nil || actual != check.pin {
			return fmt.Errorf("enrollment: %s does not match target-pinned issuer", check.name)
		}
	}
	return nil
}

func parseCA(encoded []byte) (*x509.Certificate, error) {
	certificate, err := parseCertificate(encoded)
	if err != nil {
		return nil, err
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
		certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(certificate.ExtKeyUsage) != 0 ||
		len(certificate.UnknownExtKeyUsage) != 0 || certificate.SignatureAlgorithm != x509.PureEd25519 {
		return nil, errors.New("certificate is not an exact OwnTransit root CA profile")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, errors.New("certificate is not a self-signed root CA")
	}
	return certificate, nil
}

func parseCertificate(encoded []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(encoded, pem.EncodeToMemory(block)) {
		return nil, errors.New("certificate must be one headerless CERTIFICATE PEM block")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func validateCertificate(encoded []byte, issuer *x509.Certificate, dnsName string, usage x509.ExtKeyUsage, now time.Time) (*x509.Certificate, error) {
	certificate, err := parseCertificate(encoded)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	pair := tls.Certificate{Certificate: [][]byte{certificate.Raw}, Leaf: certificate}
	if err := identity.ValidateLocalCertificate(pair, roots, dnsName, usage, now); err != nil {
		return nil, err
	}
	return certificate, nil
}

func validateRelayURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != config.RelayPath || parsed.RawPath != "" {
		return errors.New("enrollment: relay URL must be an exact wss URL on the carrier path")
	}
	return nil
}

func validatePins(groups ...[]string) error {
	for _, pins := range groups {
		if len(pins) == 0 || len(pins) > 4 {
			return errors.New("enrollment: pin allowlist must contain 1..4 values")
		}
		if _, err := identity.ParsePinAllowlist(pins); err != nil {
			return err
		}
	}
	return nil
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}
