package enrollmentexchange

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	operatorReceiptSchema          = "owntransit.enrollment-operator-receipt.v1"
	operatorReceiptEnvelopeSchema  = "owntransit.enrollment-operator-receipt-envelope.v1"
	operatorReceiptSignatureDomain = "OwnTransit enrollment operator receipt v1"
	MaxOperatorReceiptSize         = 1 << 20
	maxOperatorReferenceSize       = 512
)

// InvitationOptions are all offline, target-specific facts needed to issue a
// recipient invitation and its separate operator receipt. Human references
// remain only in the receipt and never become target-side identity evidence.
type InvitationOptions struct {
	Role                     enrollment.Role
	RouteID                  string
	ConnectorInstallationID  string
	Runtime                  enrollment.RuntimeBinding
	Trust                    enrollment.Trust
	ExchangeEndpoint         string
	Validity                 time.Duration
	IntendedRecipient        string
	IdentityContactReference string
}

type IssuedInvitation struct {
	Invitation          []byte
	OperatorReceipt     []byte
	CourierRegistration []byte
}

type operatorReceiptPayload struct {
	Schema                    string `json:"schema"`
	Invitation                string `json:"invitation"`
	InvitationSHA256          string `json:"invitation_sha256"`
	IntendedRecipient         string `json:"intended_recipient"`
	IdentityContactReference  string `json:"identity_contact_reference"`
	MailboxID                 string `json:"mailbox_id"`
	RequestReadCapability     string `json:"request_read_capability"`
	ResponseWriteCapability   string `json:"response_write_capability"`
	RequestDecryptionIdentity string `json:"request_decryption_identity"`
}

type operatorReceiptEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

type parsedOperatorReceipt struct {
	encoded   []byte
	payload   operatorReceiptPayload
	tentative tentativeInvitation
	operator  operatorExchange
}

// IssueInvitation creates one fresh mailbox, request recipient, signed
// invitation and signed private operator receipt. It performs no publication,
// network I/O, identity authentication or approval.
func IssueInvitation(options InvitationOptions, signer ed25519.PrivateKey, now time.Time) (IssuedInvitation, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(signer) != ed25519.PrivateKeySize || options.Validity <= 0 || options.Validity > maxInvitationValidity {
		return IssuedInvitation{}, errors.New("enrollmentexchange: current time, bounded validity and Ed25519 deployment signer are required")
	}
	if !validOperatorReference(options.IntendedRecipient) || !validOperatorReference(options.IdentityContactReference) {
		return IssuedInvitation{}, errors.New("enrollmentexchange: bounded printable operator identity references are required")
	}
	public := signer.Public().(ed25519.PublicKey)
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return IssuedInvitation{}, fmt.Errorf("enrollmentexchange: marshal deployment verifier: %w", err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	if _, err := signing.ParsePublic(publicPEM); err != nil {
		return IssuedInvitation{}, err
	}
	pins, err := enrollment.IssuerPinsFromTrust(options.Trust, now)
	if err != nil {
		return IssuedInvitation{}, err
	}
	target, operator, requestRecipient, err := newMailboxExchange(options.ExchangeEndpoint)
	if err != nil {
		return IssuedInvitation{}, err
	}
	invitationID, err := protocol.NewID()
	if err != nil {
		return IssuedInvitation{}, fmt.Errorf("enrollmentexchange: generate invitation ID: %w", err)
	}
	inv := invitation{
		Schema: invitationSchema, InvitationID: invitationID.String(),
		CreatedUnix: now.Unix(), ExpiresUnix: now.Add(options.Validity).Unix(),
		MinimumLifecycle: enrollment.CurrentLifecycleGeneration,
		Role:             options.Role, RouteID: options.RouteID, ConnectorInstallationID: options.ConnectorInstallationID,
		Runtime: options.Runtime, Trust: options.Trust, IssuerPins: pins,
		DeploymentSignerPublicPEM: string(publicPEM), DeploymentSignerKeyID: signing.KeyID(public),
		Exchange: target, RequestEncryptionRecipient: requestRecipient,
	}
	invitationBytes, err := signInvitation(inv, signer, now)
	if err != nil {
		return IssuedInvitation{}, err
	}
	receiptBytes, err := signOperatorReceipt(invitationBytes, operator, options.IntendedRecipient, options.IdentityContactReference, signer, now)
	if err != nil {
		return IssuedInvitation{}, err
	}
	registrationBytes, err := signCourierRegistration(invitationBytes, target, operator, signer, now)
	if err != nil {
		return IssuedInvitation{}, err
	}
	return IssuedInvitation{Invitation: invitationBytes, OperatorReceipt: receiptBytes, CourierRegistration: registrationBytes}, nil
}

func signOperatorReceipt(
	invitationBytes []byte,
	operator operatorExchange,
	intendedRecipient, identityReference string,
	signer ed25519.PrivateKey,
	now time.Time,
) ([]byte, error) {
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return nil, err
	}
	if err := operator.validateAgainst(tentative.Invitation.Exchange, tentative.Invitation.RequestEncryptionRecipient); err != nil {
		return nil, err
	}
	if !validOperatorReference(intendedRecipient) || !validOperatorReference(identityReference) {
		return nil, errors.New("enrollmentexchange: operator identity references are invalid")
	}
	payload := operatorReceiptPayload{
		Schema:     operatorReceiptSchema,
		Invitation: base64.StdEncoding.EncodeToString(invitationBytes), InvitationSHA256: tentative.SHA256,
		IntendedRecipient: intendedRecipient, IdentityContactReference: identityReference,
		MailboxID: operator.MailboxID, RequestReadCapability: operator.RequestReadCapability,
		ResponseWriteCapability: operator.ResponseWriteCapability, RequestDecryptionIdentity: operator.RequestDecryptionIdentity,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	signature, err := signing.Sign(operatorReceiptSignatureDomain, payloadBytes, signer)
	if err != nil {
		return nil, err
	}
	envelope := operatorReceiptEnvelope{
		Schema:      operatorReceiptEnvelopeSchema,
		SignerKeyID: tentative.Invitation.DeploymentSignerKeyID,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signature:   base64.StdEncoding.EncodeToString(signature),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxOperatorReceiptSize {
		return nil, errors.New("enrollmentexchange: operator receipt exceeds its size limit")
	}
	return encoded, nil
}

func parseOperatorReceipt(encoded []byte, now time.Time) (parsedOperatorReceipt, error) {
	if len(encoded) == 0 || len(encoded) > MaxOperatorReceiptSize {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt has an invalid size")
	}
	var envelope operatorReceiptEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return parsedOperatorReceipt{}, fmt.Errorf("enrollmentexchange: decode operator receipt envelope: %w", err)
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil {
		return parsedOperatorReceipt{}, err
	}
	canonicalEnvelope = append(canonicalEnvelope, '\n')
	if !bytes.Equal(encoded, canonicalEnvelope) || envelope.Schema != operatorReceiptEnvelopeSchema {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt envelope is noncanonical or unsupported")
	}
	payloadBytes, err := decodeCanonicalBase64(envelope.Payload)
	if err != nil {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt payload is not canonical base64")
	}
	var payload operatorReceiptPayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return parsedOperatorReceipt{}, fmt.Errorf("enrollmentexchange: decode operator receipt payload: %w", err)
	}
	canonicalPayload, err := json.Marshal(payload)
	if err != nil || !bytes.Equal(canonicalPayload, payloadBytes) || payload.Schema != operatorReceiptSchema {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt payload is noncanonical or unsupported")
	}
	invitationBytes, err := decodeSessionBytes(payload.Invitation, MaxInvitationSize, "operator receipt invitation")
	if err != nil {
		return parsedOperatorReceipt{}, err
	}
	tentative, err := parseTentativeInvitation(invitationBytes, now)
	if err != nil {
		return parsedOperatorReceipt{}, err
	}
	if payload.InvitationSHA256 != tentative.SHA256 || envelope.SignerKeyID != tentative.Invitation.DeploymentSignerKeyID ||
		!validOperatorReference(payload.IntendedRecipient) || !validOperatorReference(payload.IdentityContactReference) {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt binding is invalid")
	}
	public, err := signing.ParsePublic([]byte(tentative.Invitation.DeploymentSignerPublicPEM))
	if err != nil {
		return parsedOperatorReceipt{}, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return parsedOperatorReceipt{}, errors.New("enrollmentexchange: operator receipt signature encoding is invalid")
	}
	if err := signing.Verify(operatorReceiptSignatureDomain, payloadBytes, signature, public); err != nil {
		return parsedOperatorReceipt{}, fmt.Errorf("enrollmentexchange: operator receipt signature: %w", err)
	}
	operator := operatorExchange{
		MailboxID: payload.MailboxID, RequestReadCapability: payload.RequestReadCapability,
		ResponseWriteCapability: payload.ResponseWriteCapability, RequestDecryptionIdentity: payload.RequestDecryptionIdentity,
	}
	if err := operator.validateAgainst(tentative.Invitation.Exchange, tentative.Invitation.RequestEncryptionRecipient); err != nil {
		return parsedOperatorReceipt{}, err
	}
	return parsedOperatorReceipt{encoded: append([]byte(nil), encoded...), payload: payload, tentative: tentative, operator: operator}, nil
}

func validOperatorReference(value string) bool {
	if value == "" || len(value) > maxOperatorReferenceSize || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}
