package enrollment

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	RequestSchema      = "owntransit.enrollment.request.v1"
	MaxRequestSize     = 256 << 10
	MaxRequestValidity = 24 * time.Hour
)

var requestSignatureDomain = []byte("OwnTransit enrollment request v1\x00")

type Role string

const (
	RoleClient    Role = "client"
	RoleConnector Role = "connector"
	RoleRelay     Role = "relay"
)

// RequestPayload contains public enrollment material only. Its private CSR
// keys and response identity remain on the target that creates it.
type RequestPayload struct {
	Schema                  string         `json:"schema"`
	Role                    Role           `json:"role"`
	InstallationID          string         `json:"installation_id"`
	RouteID                 string         `json:"route_id,omitempty"`
	ConnectorInstallationID string         `json:"connector_installation_id,omitempty"`
	Nonce                   string         `json:"nonce"`
	Sequence                uint64         `json:"sequence"`
	CreatedUnix             int64          `json:"created_unix"`
	ExpiresUnix             int64          `json:"expires_unix"`
	ResponseRecipient       string         `json:"response_recipient"`
	IssuerPins              IssuerPins     `json:"issuer_pins"`
	DeploymentSignerKeyID   string         `json:"deployment_signer_key_id"`
	Runtime                 RuntimeBinding `json:"runtime"`
	OuterCSR                string         `json:"outer_csr_pem"`
	InnerCSR                string         `json:"inner_csr_pem,omitempty"`
}

// RuntimeBinding ties credentials and rendered policy to one authenticated
// installed artifact. The target later compares it with durable release state;
// the relay cannot choose a runtime, platform, or connector target.
type RuntimeBinding struct {
	ReleaseID           string `json:"release_id"`
	ReleaseSequence     uint64 `json:"release_sequence"`
	ArtifactSHA256      string `json:"artifact_sha256"`
	OS                  string `json:"os"`
	Arch                string `json:"arch"`
	Role                Role   `json:"role"`
	Protocol            string `json:"protocol"`
	LifecycleGeneration uint64 `json:"lifecycle_generation"`
	ConnectorTarget     string `json:"connector_target,omitempty"`
}

func (binding RuntimeBinding) Validate(expectedRole Role) error {
	releaseID, err := protocol.ParseID(binding.ReleaseID)
	if err != nil || releaseID == (protocol.ID{}) || binding.ReleaseSequence == 0 || !validSHA256(binding.ArtifactSHA256) {
		return errors.New("enrollment: runtime release identity is invalid")
	}
	if binding.Role != expectedRole || binding.Protocol != DeploymentProtocol || binding.LifecycleGeneration != CurrentLifecycleGeneration {
		return errors.New("enrollment: runtime role, protocol, or lifecycle is incompatible")
	}
	switch expectedRole {
	case RoleClient:
		if !((binding.OS == "darwin" && binding.Arch == "arm64") || (binding.OS == "linux" && binding.Arch == "amd64")) || binding.ConnectorTarget != "" {
			return errors.New("enrollment: client runtime platform or target is invalid")
		}
	case RoleConnector:
		if binding.OS != "linux" || binding.Arch != "amd64" || binding.ConnectorTarget != "tcp4/"+config.ConnectorSSHTarget {
			return errors.New("enrollment: connector runtime does not match the compiled linux/amd64 target profile")
		}
	case RoleRelay:
		if binding.OS != "linux" || binding.Arch != "amd64" || binding.ConnectorTarget != "" {
			return errors.New("enrollment: relay runtime platform or target is invalid")
		}
	default:
		return errors.New("enrollment: runtime role is invalid")
	}
	return nil
}

// IssuerPins are bootstrap trust chosen on the target before it exports an
// enrollment request. A signed response may carry the matching public roots
// for rendering, but it cannot choose or replace them.
type IssuerPins struct {
	RelayAdmissionCA string `json:"relay_admission_ca"`
	InnerClientCA    string `json:"inner_client_ca"`
	InnerConnectorCA string `json:"inner_connector_ca"`
}

func (pins IssuerPins) Validate() error {
	for name, value := range map[string]string{
		"relay admission CA": pins.RelayAdmissionCA,
		"inner client CA":    pins.InnerClientCA,
		"inner connector CA": pins.InnerConnectorCA,
	} {
		if _, err := pki.ParseCertificatePin(value); err != nil {
			return fmt.Errorf("enrollment: %s pin: %w", name, err)
		}
	}
	if pins.RelayAdmissionCA == pins.InnerClientCA || pins.RelayAdmissionCA == pins.InnerConnectorCA || pins.InnerClientCA == pins.InnerConnectorCA {
		return errors.New("enrollment: issuer certificate pins must be distinct")
	}
	return nil
}

type signedRequest struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func SignRequest(payload RequestPayload, outerSigner crypto.Signer, now time.Time) ([]byte, error) {
	if outerSigner == nil {
		return nil, errors.New("enrollment: outer CSR signer is required")
	}
	if err := ValidateRequestPayload(payload, now); err != nil {
		return nil, err
	}
	outerRequest, _, _, err := requestCSRs(payload)
	if err != nil {
		return nil, err
	}
	outerPublic, ok := outerRequest.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("enrollment: outer CSR key is not Ed25519")
	}
	signerPublic, ok := outerSigner.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(signerPublic, outerPublic) {
		return nil, errors.New("enrollment: request signer does not match outer CSR")
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode request payload: %w", err)
	}
	signatureInput := append(append([]byte(nil), requestSignatureDomain...), payloadBytes...)
	signature, err := outerSigner.Sign(nil, signatureInput, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("enrollment: sign request: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("enrollment: request signer returned a non-Ed25519 signature")
	}
	encoded, err := json.Marshal(signedRequest{
		Schema:    RequestSchema,
		Payload:   base64.StdEncoding.EncodeToString(payloadBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode signed request: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxRequestSize {
		return nil, errors.New("enrollment: signed request exceeds size limit")
	}
	return encoded, nil
}

func ParseRequest(encoded []byte, now time.Time) (RequestPayload, error) {
	if len(encoded) == 0 || len(encoded) > MaxRequestSize {
		return RequestPayload{}, fmt.Errorf("enrollment: request size must be within 1..%d bytes", MaxRequestSize)
	}
	var envelope signedRequest
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return RequestPayload{}, fmt.Errorf("enrollment: decode signed request: %w", err)
	}
	if envelope.Schema != RequestSchema {
		return RequestPayload{}, errors.New("enrollment: unsupported signed request schema")
	}
	payloadBytes, err := decodeCanonicalBase64(envelope.Payload, "request payload")
	if err != nil {
		return RequestPayload{}, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature, "request signature")
	if err != nil || len(signature) != ed25519.SignatureSize {
		return RequestPayload{}, errors.New("enrollment: request signature is invalid")
	}

	var payload RequestPayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return RequestPayload{}, fmt.Errorf("enrollment: decode request payload: %w", err)
	}
	if err := ValidateRequestPayload(payload, now); err != nil {
		return RequestPayload{}, err
	}
	outerRequest, _, _, err := requestCSRs(payload)
	if err != nil {
		return RequestPayload{}, err
	}
	publicKey, ok := outerRequest.PublicKey.(ed25519.PublicKey)
	if !ok {
		return RequestPayload{}, errors.New("enrollment: outer CSR key is not Ed25519")
	}
	signatureInput := append(append([]byte(nil), requestSignatureDomain...), payloadBytes...)
	if !ed25519.Verify(publicKey, signatureInput, signature) {
		return RequestPayload{}, errors.New("enrollment: request proof of possession failed")
	}
	return payload, nil
}

func ValidateRequestPayload(payload RequestPayload, now time.Time) error {
	if payload.Schema != RequestSchema {
		return errors.New("enrollment: unsupported request payload schema")
	}
	installationID, err := protocol.ParseID(payload.InstallationID)
	if err != nil || installationID == (protocol.ID{}) {
		return errors.New("enrollment: installation_id must be a nonzero canonical ID")
	}
	nonce, err := protocol.ParseID(payload.Nonce)
	if err != nil || nonce == (protocol.ID{}) {
		return errors.New("enrollment: nonce must be a nonzero canonical ID")
	}
	if payload.Sequence == 0 {
		return errors.New("enrollment: sequence must be positive")
	}
	if payload.CreatedUnix <= 0 || payload.ExpiresUnix <= payload.CreatedUnix || payload.ExpiresUnix-payload.CreatedUnix > int64(MaxRequestValidity/time.Second) {
		return errors.New("enrollment: request validity window is invalid")
	}
	created := time.Unix(payload.CreatedUnix, 0)
	expires := time.Unix(payload.ExpiresUnix, 0)
	if now.Before(created.Add(-5*time.Minute)) || !now.Before(expires) {
		return errors.New("enrollment: request is not currently valid")
	}
	recipient, err := age.ParseX25519Recipient(payload.ResponseRecipient)
	if err != nil || recipient.String() != payload.ResponseRecipient {
		return errors.New("enrollment: response_recipient is not a canonical age X25519 recipient")
	}
	if err := payload.IssuerPins.Validate(); err != nil {
		return err
	}
	if err := signing.ValidateKeyID(payload.DeploymentSignerKeyID); err != nil {
		return fmt.Errorf("enrollment: deployment signer key ID: %w", err)
	}
	if err := payload.Runtime.Validate(payload.Role); err != nil {
		return err
	}
	_, _, _, err = requestCSRs(payload)
	return err
}

func requestCSRs(payload RequestPayload) (outer, inner *x509.CertificateRequest, route protocol.RouteID, err error) {
	installationID, parseErr := protocol.ParseID(payload.InstallationID)
	if parseErr != nil {
		return nil, nil, route, errors.New("enrollment: invalid installation ID")
	}
	var outerName, innerName string
	switch payload.Role {
	case RoleClient:
		route, parseErr = protocol.ParseRouteID(payload.RouteID)
		if parseErr != nil || route == (protocol.RouteID{}) {
			return nil, nil, route, errors.New("enrollment: client route_id must be a nonzero canonical route ID")
		}
		connectorID, connectorErr := protocol.ParseID(payload.ConnectorInstallationID)
		if connectorErr != nil || connectorID == (protocol.ID{}) {
			return nil, nil, route, errors.New("enrollment: client connector_installation_id must be a nonzero canonical ID")
		}
		outerName = config.OuterClientDNSName(installationID)
		innerName = config.ClientCapabilityDNSName(installationID, connectorID, route, payload.Sequence)
	case RoleConnector:
		if payload.ConnectorInstallationID != "" {
			return nil, nil, route, errors.New("enrollment: connector request cannot name a different connector installation")
		}
		route, parseErr = protocol.ParseRouteID(payload.RouteID)
		if parseErr != nil || route == (protocol.RouteID{}) {
			return nil, nil, route, errors.New("enrollment: connector route_id must be a nonzero canonical route ID")
		}
		outerName = config.OuterConnectorDNSName(route)
		innerName = config.CapabilityConnectorDNSName(installationID, route)
	case RoleRelay:
		if payload.RouteID != "" || payload.ConnectorInstallationID != "" || payload.InnerCSR != "" {
			return nil, nil, route, errors.New("enrollment: relay request cannot contain route, connector, or inner CSR material")
		}
		outerName = config.RelayDNSName
	default:
		return nil, nil, route, errors.New("enrollment: unsupported target role")
	}
	outer, err = pki.ParseCSR([]byte(payload.OuterCSR), outerName)
	if err != nil {
		return nil, nil, route, fmt.Errorf("enrollment: outer CSR: %w", err)
	}
	if payload.Role == RoleRelay {
		return outer, nil, route, nil
	}
	if payload.InnerCSR == "" {
		return nil, nil, route, errors.New("enrollment: endpoint inner CSR is required")
	}
	inner, err = pki.ParseCSR([]byte(payload.InnerCSR), innerName)
	if err != nil {
		return nil, nil, route, fmt.Errorf("enrollment: inner CSR: %w", err)
	}
	return outer, inner, route, nil
}
