package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

type Issuers struct {
	RelayAdmission pki.Material
	InnerClient    pki.Material
	InnerConnector pki.Material
}

type RouteApproval struct {
	RelayRequest                         []byte
	ConnectorRequest                     []byte
	ClientRequest                        []byte
	RelayURL                             string
	RelayListen                          string
	EnrollmentAllocationCapabilitySHA256 string
	DeploymentSequence                   uint64
	Now                                  time.Time
	LeafValidity                         time.Duration
	DeploymentValidity                   time.Duration
	Issuers                              Issuers
	DeploymentSigner                     ed25519.PrivateKey
}

type RouteResponses struct {
	RelayDeployment     Deployment
	ConnectorDeployment Deployment
	ClientDeployment    Deployment
	RelayEnvelope       []byte
	ConnectorEnvelope   []byte
	ClientEnvelope      []byte
}

// ApproveInitialRoute is an offline-only, first-sequence three-request
// transaction. It must never be used for rotation: rotation requires existing
// verifier state, overlapping old/new pins, and tombstones rather than the
// single-identity authorization rendered here.
func ApproveInitialRoute(approval RouteApproval) (RouteResponses, error) {
	return approveRoute(approval, true)
}

// ApproveRouteRotation issues fresh target-generated leaves after verifier-
// first policies have already installed overlapping peer pins and, on the
// connector, both route-capability roots. It cannot apply those policies or
// bypass the target's monotonic state checks.
func ApproveRouteRotation(approval RouteApproval) (RouteResponses, error) {
	return approveRoute(approval, false)
}

func approveRoute(approval RouteApproval, initial bool) (RouteResponses, error) {
	now := approval.Now.UTC().Truncate(time.Second)
	if now.IsZero() || approval.DeploymentSequence == 0 || initial && approval.DeploymentSequence != 1 || !initial && approval.DeploymentSequence <= 1 || approval.LeafValidity <= 0 || approval.DeploymentValidity <= 0 ||
		approval.LeafValidity > MaxDeploymentValidity || approval.DeploymentValidity > MaxDeploymentValidity {
		return RouteResponses{}, errors.New("enrollment: approval time, sequence, and validities are required")
	}
	if len(approval.DeploymentSigner) != ed25519.PrivateKeySize {
		return RouteResponses{}, errors.New("enrollment: deployment signer is not Ed25519")
	}
	if err := validateRelayURL(approval.RelayURL); err != nil {
		return RouteResponses{}, err
	}
	if err := config.ValidateRelayListen(approval.RelayListen); err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: relay listen: %w", err)
	}

	relayRequest, err := ParseRequest(approval.RelayRequest, now)
	if err != nil || relayRequest.Role != RoleRelay {
		return RouteResponses{}, errors.New("enrollment: relay request is invalid or has the wrong role")
	}
	connectorRequest, err := ParseRequest(approval.ConnectorRequest, now)
	if err != nil || connectorRequest.Role != RoleConnector {
		return RouteResponses{}, errors.New("enrollment: connector request is invalid or has the wrong role")
	}
	clientRequest, err := ParseRequest(approval.ClientRequest, now)
	if err != nil || clientRequest.Role != RoleClient {
		return RouteResponses{}, errors.New("enrollment: client request is invalid or has the wrong role")
	}
	if err := validateRouteApproval(approval, now, initial, relayRequest, connectorRequest, clientRequest); err != nil {
		return RouteResponses{}, err
	}
	if relayRequest.InstallationID == connectorRequest.InstallationID || relayRequest.InstallationID == clientRequest.InstallationID || connectorRequest.InstallationID == clientRequest.InstallationID {
		return RouteResponses{}, errors.New("enrollment: every physical installation must have a unique ID")
	}
	_, _, route, err := requestCSRs(connectorRequest)
	if err != nil {
		return RouteResponses{}, err
	}
	connectorInstallationID, err := protocol.ParseID(connectorRequest.InstallationID)
	if err != nil || connectorInstallationID == (protocol.ID{}) {
		return RouteResponses{}, errors.New("enrollment: connector installation ID is invalid")
	}
	if clientRequest.RouteID != route.String() || clientRequest.ConnectorInstallationID != connectorRequest.InstallationID {
		return RouteResponses{}, errors.New("enrollment: client capability request does not target this connector route")
	}
	relayOuterRequest, _, _, _ := requestCSRs(relayRequest)
	connectorOuterRequest, connectorInnerRequest, _, _ := requestCSRs(connectorRequest)
	clientOuterRequest, clientInnerRequest, _, _ := requestCSRs(clientRequest)

	relayOuter, err := pki.IssueCSR(approval.Issuers.RelayAdmission, relayOuterRequest, config.RelayDNSName, x509.ExtKeyUsageServerAuth, now, approval.LeafValidity)
	if err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: issue relay outer leaf: %w", err)
	}
	connectorOuterName := config.OuterConnectorDNSName(route)
	connectorOuter, err := pki.IssueCSR(approval.Issuers.RelayAdmission, connectorOuterRequest, connectorOuterName, x509.ExtKeyUsageClientAuth, now, approval.LeafValidity)
	if err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: issue connector outer leaf: %w", err)
	}
	clientID, _ := protocol.ParseID(clientRequest.InstallationID)
	clientOuterName := config.OuterClientDNSName(clientID)
	clientOuter, err := pki.IssueCSR(approval.Issuers.RelayAdmission, clientOuterRequest, clientOuterName, x509.ExtKeyUsageClientAuth, now, approval.LeafValidity)
	if err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: issue client outer leaf: %w", err)
	}
	connectorInnerName := config.CapabilityConnectorDNSName(connectorInstallationID, route)
	connectorInner, err := pki.IssueCSR(approval.Issuers.InnerConnector, connectorInnerRequest, connectorInnerName, x509.ExtKeyUsageServerAuth, now, approval.LeafValidity)
	if err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: issue connector inner leaf: %w", err)
	}
	clientInnerName := config.ClientCapabilityDNSName(clientID, connectorInstallationID, route, clientRequest.Sequence)
	clientInner, err := pki.IssueCSR(approval.Issuers.InnerClient, clientInnerRequest, clientInnerName, x509.ExtKeyUsageClientAuth, now, approval.LeafValidity)
	if err != nil {
		return RouteResponses{}, fmt.Errorf("enrollment: issue client inner leaf: %w", err)
	}

	relayPin, err := identity.SPKIPin(relayOuter.Certificate)
	if err != nil {
		return RouteResponses{}, err
	}
	connectorOuterPin, err := identity.SPKIPin(connectorOuter.Certificate)
	if err != nil {
		return RouteResponses{}, err
	}
	clientOuterPin, err := identity.SPKIPin(clientOuter.Certificate)
	if err != nil {
		return RouteResponses{}, err
	}
	connectorInnerPin, err := identity.SPKIPin(connectorInner.Certificate)
	if err != nil {
		return RouteResponses{}, err
	}
	trust := Trust{
		RelayAdmissionCA: string(approval.Issuers.RelayAdmission.CertPEM),
		InnerClientCA:    string(approval.Issuers.InnerClient.CertPEM),
		InnerConnectorCA: string(approval.Issuers.InnerConnector.CertPEM),
	}
	expires := now.Add(approval.DeploymentValidity)
	for _, certificate := range []*x509.Certificate{relayOuter.Certificate, connectorOuter.Certificate, clientOuter.Certificate, connectorInner.Certificate, clientInner.Certificate} {
		if certificate.NotAfter.Before(expires) {
			expires = certificate.NotAfter
		}
	}
	base := func(request RequestPayload, requestBytes []byte) Deployment {
		digest := sha256.Sum256(requestBytes)
		return Deployment{
			Schema: DeploymentSchema, Protocol: DeploymentProtocol, MinimumLifecycle: CurrentLifecycleGeneration,
			Role: request.Role, InstallationID: request.InstallationID,
			ConnectorInstallationID: connectorRequest.InstallationID, Runtime: request.Runtime,
			RequestNonce: request.Nonce, RequestSHA256: hex.EncodeToString(digest[:]), RequestSequence: request.Sequence,
			DeploymentSequence: approval.DeploymentSequence, CredentialEpoch: request.Sequence,
			IssuedUnix: now.Unix(), ExpiresUnix: expires.Unix(), RouteID: route.String(), Trust: trust,
		}
	}

	relayDeployment := base(relayRequest, approval.RelayRequest)
	relayDeployment.RelayListen = approval.RelayListen
	relayDeployment.OuterDNSName = config.RelayDNSName
	relayDeployment.OuterCertificate = string(relayOuter.CertPEM)
	relayDeployment.Relay = &RelayAuthorization{
		Clients:                              []config.AuthorizedPeer{{DNSName: clientOuterName, SPKIPins: []string{clientOuterPin}}},
		Routes:                               []config.RelayRoute{{RouteID: route.String(), DNSName: connectorOuterName, SPKIPins: []string{connectorOuterPin}}},
		EnrollmentAllocationCapabilitySHA256: approval.EnrollmentAllocationCapabilitySHA256,
	}
	connectorDeployment := base(connectorRequest, approval.ConnectorRequest)
	connectorDeployment.RelayURL = approval.RelayURL
	connectorDeployment.OuterDNSName = connectorOuterName
	connectorDeployment.InnerDNSName = connectorInnerName
	connectorDeployment.OuterCertificate = string(connectorOuter.CertPEM)
	connectorDeployment.InnerCertificate = string(connectorInner.CertPEM)
	connectorDeployment.Connector = &ConnectorAuthorization{
		RelayServerPins: []string{relayPin}, InnerAuthorizationProfile: config.InnerProfileRouteCapability,
	}
	clientDeployment := base(clientRequest, approval.ClientRequest)
	clientDeployment.RelayURL = approval.RelayURL
	clientDeployment.OuterDNSName = clientOuterName
	clientDeployment.InnerDNSName = clientInnerName
	clientDeployment.OuterCertificate = string(clientOuter.CertPEM)
	clientDeployment.InnerCertificate = string(clientInner.CertPEM)
	clientDeployment.Client = &ClientAuthorization{
		RelayServerPins:   []string{relayPin},
		ConnectorDNSName:  connectorInnerName,
		ConnectorSPKIPins: []string{connectorInnerPin},
	}

	return sealRouteResponses(approval, relayRequest, connectorRequest, clientRequest, relayDeployment, connectorDeployment, clientDeployment, now)
}

func validateRouteApproval(approval RouteApproval, now time.Time, initial bool, requests ...RequestPayload) error {
	if len(requests) != 3 {
		return errors.New("enrollment: initial route approval requires exactly three requests")
	}
	pins, issuerSPKIs, err := approvalIssuerPins(approval.Issuers, now)
	if err != nil {
		return err
	}
	signerPublic := approval.DeploymentSigner.Public().(ed25519.PublicKey)
	signerDER, err := x509.MarshalPKIXPublicKey(signerPublic)
	if err != nil {
		return fmt.Errorf("enrollment: marshal deployment signer: %w", err)
	}
	for _, issuerSPKI := range issuerSPKIs {
		if bytes.Equal(issuerSPKI, signerDER) {
			return errors.New("enrollment: deployment signer and issuer keys must be distinct")
		}
	}
	signerKeyID := signing.KeyID(signerPublic)
	seenNonces := make(map[string]struct{}, len(requests))
	seenRecipients := make(map[string]struct{}, len(requests))
	seenKeys := make(map[string]struct{}, 9)
	for _, issuerSPKI := range issuerSPKIs {
		seenKeys[string(issuerSPKI)] = struct{}{}
	}
	seenKeys[string(signerDER)] = struct{}{}
	wantSequence := requests[0].Sequence
	for index, request := range requests {
		if initial && request.Sequence != 1 {
			return errors.New("enrollment: initial approval accepts only first-sequence requests; rotation requires verifier-first state")
		}
		if !initial && (wantSequence <= 1 || request.Sequence != wantSequence) {
			return errors.New("enrollment: rotation requests must share one post-initial credential sequence")
		}
		if request.IssuerPins != pins || request.DeploymentSignerKeyID != signerKeyID {
			return errors.New("enrollment: request bootstrap trust does not match approval authorities")
		}
		if index > 0 && (request.Runtime.ReleaseID != requests[0].Runtime.ReleaseID ||
			request.Runtime.ReleaseSequence != requests[0].Runtime.ReleaseSequence ||
			request.Runtime.Protocol != requests[0].Runtime.Protocol ||
			request.Runtime.LifecycleGeneration != requests[0].Runtime.LifecycleGeneration) {
			return errors.New("enrollment: route participants must bind one compatible release generation")
		}
		if _, duplicate := seenNonces[request.Nonce]; duplicate {
			return errors.New("enrollment: request nonces must be distinct")
		}
		seenNonces[request.Nonce] = struct{}{}
		if _, duplicate := seenRecipients[request.ResponseRecipient]; duplicate {
			return errors.New("enrollment: response recipients must be distinct")
		}
		seenRecipients[request.ResponseRecipient] = struct{}{}
		outer, inner, _, err := requestCSRs(request)
		if err != nil {
			return err
		}
		for _, csr := range []*x509.CertificateRequest{outer, inner} {
			if csr == nil {
				continue
			}
			key := string(csr.RawSubjectPublicKeyInfo)
			if _, duplicate := seenKeys[key]; duplicate {
				return errors.New("enrollment: every issuer, signer, and outer/inner endpoint must use a unique key")
			}
			seenKeys[key] = struct{}{}
		}
	}
	return nil
}

func approvalIssuerPins(issuers Issuers, now time.Time) (IssuerPins, [][]byte, error) {
	values := []struct {
		name     string
		material pki.Material
	}{
		{"relay admission", issuers.RelayAdmission},
		{"inner client", issuers.InnerClient},
		{"inner connector", issuers.InnerConnector},
	}
	var pins IssuerPins
	spkis := make([][]byte, 0, len(values))
	for index, value := range values {
		certificate := value.material.Certificate
		if certificate == nil || value.material.Signer == nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) ||
			!certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero || certificate.MaxPathLen != 0 ||
			certificate.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || len(certificate.ExtKeyUsage) != 0 ||
			len(certificate.UnknownExtKeyUsage) != 0 || certificate.SignatureAlgorithm != x509.PureEd25519 {
			return IssuerPins{}, nil, fmt.Errorf("enrollment: %s issuer has an invalid root profile", value.name)
		}
		if err := certificate.CheckSignatureFrom(certificate); err != nil {
			return IssuerPins{}, nil, fmt.Errorf("enrollment: %s issuer is not self-signed: %w", value.name, err)
		}
		signerDER, err := x509.MarshalPKIXPublicKey(value.material.Signer.Public())
		if err != nil || !bytes.Equal(signerDER, certificate.RawSubjectPublicKeyInfo) {
			return IssuerPins{}, nil, fmt.Errorf("enrollment: %s issuer key does not match certificate", value.name)
		}
		for _, existing := range spkis {
			if bytes.Equal(existing, certificate.RawSubjectPublicKeyInfo) {
				return IssuerPins{}, nil, errors.New("enrollment: issuer keys must be distinct")
			}
		}
		spkis = append(spkis, append([]byte(nil), certificate.RawSubjectPublicKeyInfo...))
		pin, err := pki.CertificatePin(certificate)
		if err != nil {
			return IssuerPins{}, nil, err
		}
		switch index {
		case 0:
			pins.RelayAdmissionCA = pin
		case 1:
			pins.InnerClientCA = pin
		case 2:
			pins.InnerConnectorCA = pin
		}
	}
	if err := pins.Validate(); err != nil {
		return IssuerPins{}, nil, err
	}
	return pins, spkis, nil
}

func sealRouteResponses(
	approval RouteApproval,
	relayRequest, connectorRequest, clientRequest RequestPayload,
	relayDeployment, connectorDeployment, clientDeployment Deployment,
	now time.Time,
) (RouteResponses, error) {
	type item struct {
		request     RequestPayload
		requestRaw  []byte
		deployment  Deployment
		destination *[]byte
	}
	responses := RouteResponses{
		RelayDeployment: relayDeployment, ConnectorDeployment: connectorDeployment, ClientDeployment: clientDeployment,
	}
	items := []item{
		{relayRequest, approval.RelayRequest, relayDeployment, &responses.RelayEnvelope},
		{connectorRequest, approval.ConnectorRequest, connectorDeployment, &responses.ConnectorEnvelope},
		{clientRequest, approval.ClientRequest, clientDeployment, &responses.ClientEnvelope},
	}
	for _, value := range items {
		if err := value.deployment.ValidateRequestBinding(value.requestRaw, now); err != nil {
			return RouteResponses{}, err
		}
		payload, err := EncodeDeployment(value.deployment)
		if err != nil {
			return RouteResponses{}, err
		}
		envelope, err := SealResponse(payload, value.request.ResponseRecipient, approval.DeploymentSigner)
		if err != nil {
			return RouteResponses{}, err
		}
		*value.destination = envelope
	}
	return responses, nil
}
