package enrollmentexchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	invitationSchema         = "owntransit.enrollment-invitation.v1"
	invitationEnvelopeSchema = "owntransit.enrollment-invitation-envelope.v1"
	maxInvitationValidity    = 24 * time.Hour

	invitationSignatureDomain = "OwnTransit enrollment invitation v1"
	mailboxCapabilitySize     = 32
	maxExchangeEndpointSize   = 2048
)

// invitation contains tentative public bootstrap facts and limited mailbox
// capabilities. Its self-consistent offline signature detects modification;
// only the separate bidirectional human procedure authenticates the signer
// and turns this transcript into trusted bootstrap input.
//
// It is deliberately unexported until the durable confirmation state machine
// exists. A parsed, self-signed invitation is not an activation capability.
type invitation struct {
	Schema                     string                    `json:"schema"`
	InvitationID               string                    `json:"invitation_id"`
	CreatedUnix                int64                     `json:"created_unix"`
	ExpiresUnix                int64                     `json:"expires_unix"`
	MinimumLifecycle           uint64                    `json:"minimum_lifecycle"`
	Role                       enrollment.Role           `json:"role"`
	RouteID                    string                    `json:"route_id,omitempty"`
	ConnectorInstallationID    string                    `json:"connector_installation_id,omitempty"`
	Runtime                    enrollment.RuntimeBinding `json:"runtime"`
	Trust                      enrollment.Trust          `json:"trust"`
	IssuerPins                 enrollment.IssuerPins     `json:"issuer_pins"`
	DeploymentSignerPublicPEM  string                    `json:"deployment_signer_public_key_pem"`
	DeploymentSignerKeyID      string                    `json:"deployment_signer_key_id"`
	Exchange                   targetExchange            `json:"exchange"`
	RequestEncryptionRecipient string                    `json:"request_encryption_recipient"`
}

// targetExchange is sufficient only for the target to write one request and
// read one response. Complementary administrator capabilities never enter the
// invitation.
type targetExchange struct {
	Endpoint                          string `json:"endpoint"`
	MailboxID                         string `json:"mailbox_id"`
	RequestWriteCapability            string `json:"request_write_capability"`
	ResponseReadCapability            string `json:"response_read_capability"`
	RequestReadCapabilityCommitment   string `json:"request_read_capability_commitment"`
	ResponseWriteCapabilityCommitment string `json:"response_write_capability_commitment"`
}

type invitationEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// tentativeInvitation is signed and structurally valid but deliberately does
// not claim that the embedded signer belongs to the intended administrator.
// The exact Encoded bytes and digest are inputs to the safety phrase.
type tentativeInvitation struct {
	Invitation invitation
	Encoded    []byte
	SHA256     string
}

// signInvitation creates the exact recipient file with the deployment signer.
// The caller must retain an operator receipt separately; this function neither
// publishes the invitation nor supplies human authentication.
func signInvitation(invitation invitation, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("enrollmentexchange: an Ed25519 deployment signer is required")
	}
	if err := invitation.validate(now); err != nil {
		return nil, err
	}
	publicKey, err := signing.ParsePublic([]byte(invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: deployment verifier: %w", err)
	}
	if !bytes.Equal(publicKey, privateKey.Public().(ed25519.PublicKey)) {
		return nil, errors.New("enrollmentexchange: invitation verifier does not match deployment signer")
	}
	payload, err := json.Marshal(invitation)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encode invitation payload: %w", err)
	}
	signature, err := signing.Sign(invitationSignatureDomain, payload, privateKey)
	if err != nil {
		return nil, err
	}
	envelope := invitationEnvelope{
		Schema: invitationEnvelopeSchema, SignerKeyID: invitation.DeploymentSignerKeyID,
		Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encode invitation envelope: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxInvitationSize {
		return nil, errors.New("enrollmentexchange: invitation exceeds its size limit")
	}
	return encoded, nil
}

// parseTentativeInvitation verifies canonical bytes and the embedded offline
// signature. It intentionally returns a tentative value: a malicious party can
// self-sign a different invitation, so activation must remain impossible until
// the exact transcript passes the independent two-way human ceremony.
func parseTentativeInvitation(encoded []byte, now time.Time) (tentativeInvitation, error) {
	if len(encoded) == 0 || len(encoded) > MaxInvitationSize {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation has an invalid size")
	}
	var envelope invitationEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return tentativeInvitation{}, fmt.Errorf("enrollmentexchange: decode invitation envelope: %w", err)
	}
	if envelope.Schema != invitationEnvelopeSchema {
		return tentativeInvitation{}, errors.New("enrollmentexchange: unsupported invitation envelope schema")
	}
	payloadBytes, err := decodeCanonicalBase64(envelope.Payload)
	if err != nil {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation payload is not canonical base64")
	}
	signature, err := decodeCanonicalBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation signature encoding is invalid")
	}
	var invitation invitation
	if err := strictjson.Decode(payloadBytes, &invitation); err != nil {
		return tentativeInvitation{}, fmt.Errorf("enrollmentexchange: decode invitation payload: %w", err)
	}
	canonicalPayload, err := json.Marshal(invitation)
	if err != nil || !bytes.Equal(canonicalPayload, payloadBytes) {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation payload is not canonical JSON")
	}
	if err := invitation.validate(now); err != nil {
		return tentativeInvitation{}, err
	}
	publicKey, err := signing.ParsePublic([]byte(invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return tentativeInvitation{}, fmt.Errorf("enrollmentexchange: deployment verifier: %w", err)
	}
	if envelope.SignerKeyID != invitation.DeploymentSignerKeyID || envelope.SignerKeyID != signing.KeyID(publicKey) {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation signer identity is inconsistent")
	}
	if err := signing.Verify(invitationSignatureDomain, payloadBytes, signature, publicKey); err != nil {
		return tentativeInvitation{}, fmt.Errorf("enrollmentexchange: invitation signature: %w", err)
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return tentativeInvitation{}, err
	}
	canonicalEnvelope = append(canonicalEnvelope, '\n')
	if !bytes.Equal(encoded, canonicalEnvelope) {
		return tentativeInvitation{}, errors.New("enrollmentexchange: invitation envelope is not canonical JSON")
	}
	digest := sha256.Sum256(encoded)
	return tentativeInvitation{
		Invitation: invitation,
		Encoded:    append([]byte(nil), encoded...),
		SHA256:     hex.EncodeToString(digest[:]),
	}, nil
}

// Validate checks only shape, time, cryptographic self-consistency and exact
// role/release binding. It never authenticates the administrator as a human.
func (invitation invitation) validate(now time.Time) error {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || invitation.Schema != invitationSchema {
		return errors.New("enrollmentexchange: invitation time and schema are required")
	}
	invitationID, err := protocol.ParseID(invitation.InvitationID)
	if err != nil || invitationID == (protocol.ID{}) {
		return errors.New("enrollmentexchange: invitation ID is invalid")
	}
	if invitation.CreatedUnix <= 0 || invitation.ExpiresUnix <= invitation.CreatedUnix ||
		invitation.ExpiresUnix-invitation.CreatedUnix > int64(maxInvitationValidity/time.Second) ||
		now.Before(time.Unix(invitation.CreatedUnix, 0).Add(-5*time.Minute)) ||
		!now.Before(time.Unix(invitation.ExpiresUnix, 0)) {
		return errors.New("enrollmentexchange: invitation is not currently valid")
	}
	if invitation.MinimumLifecycle != enrollment.CurrentLifecycleGeneration || invitation.Runtime.LifecycleGeneration < invitation.MinimumLifecycle {
		return errors.New("enrollmentexchange: invitation lifecycle binding is unsupported")
	}
	if invitation.Runtime.Role != invitation.Role {
		return errors.New("enrollmentexchange: invitation runtime role differs from target role")
	}
	if err := invitation.Runtime.Validate(invitation.Role); err != nil {
		return err
	}
	if err := validateRoleBinding(invitation); err != nil {
		return err
	}
	publicKey, err := signing.ParsePublic([]byte(invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return fmt.Errorf("enrollmentexchange: deployment verifier: %w", err)
	}
	if invitation.DeploymentSignerKeyID != signing.KeyID(publicKey) {
		return errors.New("enrollmentexchange: deployment verifier key ID does not match its key")
	}
	if err := enrollment.ValidateBootstrapAuthorities(invitation.Trust, publicKey, now); err != nil {
		return err
	}
	pins, err := enrollment.IssuerPinsFromTrust(invitation.Trust, now)
	if err != nil {
		return err
	}
	if pins != invitation.IssuerPins {
		return errors.New("enrollmentexchange: invitation issuer pins do not match its exact trust roots")
	}
	if err := invitation.Exchange.validate(); err != nil {
		return err
	}
	recipient, err := age.ParseX25519Recipient(invitation.RequestEncryptionRecipient)
	if err != nil || recipient.String() != invitation.RequestEncryptionRecipient {
		return errors.New("enrollmentexchange: request encryption recipient is not canonical age X25519")
	}
	return nil
}

func validateRoleBinding(invitation invitation) error {
	switch invitation.Role {
	case enrollment.RoleRelay:
		if invitation.RouteID != "" || invitation.ConnectorInstallationID != "" {
			return errors.New("enrollmentexchange: relay invitation selects a route or connector")
		}
	case enrollment.RoleConnector:
		if _, err := parseNonzeroRouteID(invitation.RouteID); err != nil || invitation.ConnectorInstallationID != "" {
			return errors.New("enrollmentexchange: connector invitation binding is invalid")
		}
	case enrollment.RoleClient:
		if _, err := parseNonzeroRouteID(invitation.RouteID); err != nil {
			return errors.New("enrollmentexchange: client invitation route is invalid")
		}
		connectorID, err := protocol.ParseID(invitation.ConnectorInstallationID)
		if err != nil || connectorID == (protocol.ID{}) {
			return errors.New("enrollmentexchange: client invitation connector is invalid")
		}
	default:
		return errors.New("enrollmentexchange: invitation role is invalid")
	}
	return nil
}

func parseNonzeroRouteID(value string) (protocol.RouteID, error) {
	parsed, err := protocol.ParseRouteID(value)
	if err != nil || parsed == (protocol.RouteID{}) {
		return protocol.RouteID{}, errors.New("invalid route ID")
	}
	return parsed, nil
}

// Validate rejects URL-borne capabilities and representation aliases before
// any network operation can consume this tentative mailbox description.
func (exchange targetExchange) validate() error {
	if len(exchange.Endpoint) == 0 || len(exchange.Endpoint) > maxExchangeEndpointSize || exchange.Endpoint != strings.ToLower(exchange.Endpoint) {
		return errors.New("enrollmentexchange: exchange endpoint is absent, too large, or noncanonical")
	}
	parsed, err := url.Parse(exchange.Endpoint)
	if err != nil || parsed.Scheme != "wss" || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery || parsed.Opaque != "" || parsed.RawPath != "" ||
		parsed.Path == "" || parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/") || path.Clean(parsed.Path) != parsed.Path || parsed.String() != exchange.Endpoint ||
		parsed.Port() != "" || parsed.Host != parsed.Hostname() || !validPublicExchangeHostname(parsed.Hostname()) {
		return errors.New("enrollmentexchange: exchange endpoint must be one canonical credential-free wss URL")
	}
	mailboxID, err := protocol.ParseID(exchange.MailboxID)
	if err != nil || mailboxID == (protocol.ID{}) {
		return errors.New("enrollmentexchange: mailbox ID is invalid")
	}
	requestWrite, err := parseMailboxCapability(exchange.RequestWriteCapability)
	if err != nil {
		return err
	}
	responseRead, err := parseMailboxCapability(exchange.ResponseReadCapability)
	if err != nil {
		return err
	}
	if bytes.Equal(requestWrite, responseRead) {
		return errors.New("enrollmentexchange: target mailbox capabilities are not independent")
	}
	if !validSHA256Hex(exchange.RequestReadCapabilityCommitment) || !validSHA256Hex(exchange.ResponseWriteCapabilityCommitment) ||
		exchange.RequestReadCapabilityCommitment == exchange.ResponseWriteCapabilityCommitment {
		return errors.New("enrollmentexchange: operator mailbox capability commitments are invalid")
	}
	return nil
}

func validPublicExchangeHostname(hostname string) bool {
	if hostname == "" || len(hostname) > 253 || hostname != strings.ToLower(hostname) || strings.HasSuffix(hostname, ".") {
		return false
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return false
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range label {
			character := label[index]
			if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
				return false
			}
		}
	}
	for _, suffix := range []string{".localhost", ".local", ".internal", ".home.arpa", ".invalid", ".test", ".example", ".onion"} {
		if hostname == strings.TrimPrefix(suffix, ".") || strings.HasSuffix(hostname, suffix) {
			return false
		}
	}
	return true
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range value {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func parseMailboxCapability(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != mailboxCapabilitySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("enrollmentexchange: mailbox capability is not canonical 256-bit base64url")
	}
	return decoded, nil
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("noncanonical base64")
	}
	return decoded, nil
}
