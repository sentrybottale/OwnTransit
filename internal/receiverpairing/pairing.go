//go:build darwin || linux

// Package receiverpairing implements receiver-owned, one-use pairing and
// persistent peer renewal. It has no network listener and never handles SSH.
package receiverpairing

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	Profile = "owntransit-receiver-pairing/1"

	advertisementSchema    = "owntransit.receiver-pairing.advertisement.v1"
	advertEnvelopeSchema   = "owntransit.receiver-pairing.advertisement-envelope.v1"
	codeSchema             = "owntransit.receiver-pairing.code.v1"
	requestSchema          = "owntransit.receiver-pairing.request.v1"
	requestEnvelopeSchema  = "owntransit.receiver-pairing.request-envelope.v1"
	requestCipherSchema    = "owntransit.receiver-pairing.request-ciphertext.v1"
	responseSchema         = "owntransit.receiver-pairing.response.v1"
	responseEnvelopeSchema = "owntransit.receiver-pairing.response-envelope.v1"
	responseCipherSchema   = "owntransit.receiver-pairing.response-ciphertext.v1"
	renewalSchema          = "owntransit.receiver-pairing.renewal.v1"
	renewalEnvelopeSchema  = "owntransit.receiver-pairing.renewal-envelope.v1"
	renewalCipherSchema    = "owntransit.receiver-pairing.renewal-ciphertext.v1"

	advertisementDomain = "OwnTransit receiver pairing advertisement v1"
	requestDomain       = "OwnTransit receiver pairing request v1"
	responseDomain      = "OwnTransit receiver pairing response v1"
	renewalDomain       = "OwnTransit receiver pairing renewal v1"

	codePrefix = "otpair1."
	secretSize = 32

	MaxAdvertisementSize = 128 << 10
	MaxCodeSize          = 4 << 10
	MaxRequestSize       = 1 << 20
	MaxResponseSize      = 1 << 20
	MaxAuthorizationSize = 256 << 10
	MaxAttemptValidity   = 24 * time.Hour
	MaxMessageValidity   = time.Hour
	paddedPlaintextSize  = 512 << 10
	paddedHeaderSize     = 12
)

var paddedMagic = [4]byte{'O', 'T', 'R', 'P'}

// Trust is public material signed into every advertisement. The endpoint CAs
// are receiver-owned; RelayServerSPKI authenticates only the outer relay leg.
type Trust struct {
	RelayServerSPKI     string `json:"relay_server_spki_sha256"`
	OuterEndpointCAPEM  string `json:"outer_endpoint_ca_pem"`
	InnerConnectorCAPEM string `json:"inner_connector_ca_pem"`
	InnerClientCAPEM    string `json:"inner_client_ca_pem"`
}

type AdvertisementInfo struct {
	ReceiverID                  string
	RouteID                     string
	RelayOrigin                 string
	AttemptID                   string
	Trust                       Trust
	ReceiverSigningPublicKeyPEM []byte
	ReceiverAgeRecipient        string
	Expires                     time.Time
}

// VerifyAdvertisement proves signature, canonical encoding, public trust,
// origin, attempt, and expiry. Endpoint trust additionally requires the exact
// advertisement digest carried by the independently transferred private code.
func VerifyAdvertisement(encoded []byte, now time.Time) (AdvertisementInfo, error) {
	payload, _, err := parseAdvertisement(encoded, now.UTC().Truncate(time.Second))
	if err != nil {
		return AdvertisementInfo{}, err
	}
	return AdvertisementInfo{
		ReceiverID: payload.ReceiverID, RouteID: payload.RouteID, RelayOrigin: payload.RelayOrigin,
		AttemptID: payload.AttemptID, Trust: payload.Trust,
		ReceiverSigningPublicKeyPEM: append([]byte(nil), []byte(payload.ReceiverSigningPublic)...),
		ReceiverAgeRecipient:        payload.ReceiverAgeRecipient, Expires: time.Unix(payload.ExpiresUnix, 0).UTC(),
	}, nil
}

// InitializeOptions selects non-secret receiver scope. An empty ReceiverID or
// RouteID is generated from operating-system randomness.
type InitializeOptions struct {
	RootPath        string
	ReceiverID      string
	RouteID         string
	RelayOrigin     string
	RelayServerSPKI string
	Now             time.Time
}

type ReceiverStatus struct {
	ReceiverID           string
	RouteID              string
	RelayOrigin          string
	Generation           uint64
	LocalLocked          bool
	PendingAttemptID     string
	PairedClientID       string
	CredentialGeneration uint64
	PeerLocked           bool
	PeerRevoked          bool
}

type Attempt struct {
	Advertisement []byte
	Code          []byte
	ReceiverID    string
	AttemptID     string
	Expires       time.Time
}

func (Attempt) String() string   { return "receiverpairing.Attempt[PRIVATE CODE REDACTED]" }
func (Attempt) GoString() string { return "receiverpairing.Attempt[PRIVATE CODE REDACTED]" }

func (attempt Attempt) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Advertisement []byte    `json:"advertisement"`
		ReceiverID    string    `json:"receiver_id"`
		AttemptID     string    `json:"attempt_id"`
		Expires       time.Time `json:"expires"`
	}{attempt.Advertisement, attempt.ReceiverID, attempt.AttemptID, attempt.Expires})
}

type CreateRequestOptions struct {
	Advertisement []byte
	Code          []byte
	RelayOrigin   string
	Now           time.Time
	Validity      time.Duration
}

type ClientIdentity struct {
	ReceiverID           string
	RouteID              string
	RelayOrigin          string
	ClientID             string
	CredentialGeneration uint64
}

type PayloadBuilder func(ClientIdentity) ([]byte, error)

// ClientRequest contains only relay-safe ciphertext plus private target-local
// material whose fields are deliberately unexported.
type ClientRequest struct {
	Encrypted []byte
	Material  ClientMaterial
}

type ClientMaterial struct {
	receiverID        string
	routeID           string
	relayOrigin       string
	attemptID         string
	advertisementSHA  string
	clientID          string
	requestSHA        string
	pairingPrivate    []byte
	responseIdentity  string
	receiverPublic    []byte
	receiverRecipient string
	request           []byte
}

func (material ClientMaterial) PairingPrivateKeyPEM() []byte {
	return append([]byte(nil), material.pairingPrivate...)
}

func (ClientMaterial) String() string   { return "receiverpairing.ClientMaterial[REDACTED]" }
func (ClientMaterial) GoString() string { return "receiverpairing.ClientMaterial[REDACTED]" }

func (material ClientMaterial) ResponseIdentity() string { return material.responseIdentity }
func (material ClientMaterial) ClientID() string         { return material.clientID }
func (material ClientMaterial) RequestSHA256() string    { return material.requestSHA }
func (material ClientMaterial) RequestBytes() []byte     { return append([]byte(nil), material.request...) }

type PeerRequest struct {
	Kind                 string
	ReceiverID           string
	RouteID              string
	RelayOrigin          string
	ClientID             string
	PairingPublicKeyPEM  []byte
	PublicPayload        []byte
	CredentialGeneration uint64
	RequestSHA256        string
}

type IssueFunc func(PeerRequest) ([]byte, error)

type ClaimResult struct {
	Response             []byte
	ReceiverID           string
	ClientID             string
	CredentialGeneration uint64
	Idempotent           bool
}

// Pairing is the client-side persistent authentication state. Secret fields
// are intentionally unavailable to generic JSON encoders.
type Pairing struct {
	receiverID        string
	routeID           string
	relayOrigin       string
	clientID          string
	generation        uint64
	pairingPrivate    []byte
	receiverPublic    []byte
	receiverRecipient string
}

func (pairing Pairing) ReceiverID() string           { return pairing.receiverID }
func (pairing Pairing) RouteID() string              { return pairing.routeID }
func (pairing Pairing) RelayOrigin() string          { return pairing.relayOrigin }
func (pairing Pairing) ClientID() string             { return pairing.clientID }
func (pairing Pairing) CredentialGeneration() uint64 { return pairing.generation }
func (pairing Pairing) PairingPrivateKeyPEM() []byte {
	return append([]byte(nil), pairing.pairingPrivate...)
}
func (Pairing) String() string   { return "receiverpairing.Pairing[REDACTED]" }
func (Pairing) GoString() string { return "receiverpairing.Pairing[REDACTED]" }

type OpenResponseResult struct {
	Pairing       Pairing
	Authorization []byte
}

type RenewalRequest struct {
	Encrypted []byte
	Material  RenewalMaterial
}

type RenewalMaterial struct {
	pairing          Pairing
	requestSHA       string
	responseIdentity string
	nextGeneration   uint64
	request          []byte
}

func (RenewalMaterial) String() string   { return "receiverpairing.RenewalMaterial[REDACTED]" }
func (RenewalMaterial) GoString() string { return "receiverpairing.RenewalMaterial[REDACTED]" }
func (material RenewalMaterial) RequestBytes() []byte {
	return append([]byte(nil), material.request...)
}
func (material RenewalMaterial) RequestSHA256() string { return material.requestSHA }

type signedEnvelope struct {
	Schema    string `json:"schema"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type cipherEnvelope struct {
	Schema     string `json:"schema"`
	Ciphertext string `json:"ciphertext"`
}

type advertisementPayload struct {
	Schema                string `json:"schema"`
	Profile               string `json:"profile"`
	ReceiverID            string `json:"receiver_id"`
	RouteID               string `json:"route_id"`
	RelayOrigin           string `json:"relay_origin"`
	AttemptID             string `json:"attempt_id"`
	CreatedUnix           int64  `json:"created_unix"`
	ExpiresUnix           int64  `json:"expires_unix"`
	ReceiverSigningPublic string `json:"receiver_signing_public_key_pem"`
	ReceiverAgeRecipient  string `json:"receiver_request_recipient"`
	Trust                 Trust  `json:"trust"`
}

type codePayload struct {
	Schema              string `json:"schema"`
	ReceiverID          string `json:"receiver_id"`
	AttemptID           string `json:"attempt_id"`
	ExpiresUnix         int64  `json:"expires_unix"`
	AdvertisementSHA256 string `json:"advertisement_sha256"`
	Secret              string `json:"secret"`
}

type requestPayload struct {
	Schema              string `json:"schema"`
	Profile             string `json:"profile"`
	ReceiverID          string `json:"receiver_id"`
	RouteID             string `json:"route_id"`
	RelayOrigin         string `json:"relay_origin"`
	AttemptID           string `json:"attempt_id"`
	AdvertisementSHA256 string `json:"advertisement_sha256"`
	ClientID            string `json:"client_id"`
	Nonce               string `json:"nonce"`
	CreatedUnix         int64  `json:"created_unix"`
	ExpiresUnix         int64  `json:"expires_unix"`
	PairingPublicKeyPEM string `json:"pairing_public_key_pem"`
	ResponseRecipient   string `json:"response_recipient"`
	PublicPayload       string `json:"public_payload"`
	Code                string `json:"private_code"`
}

type responsePayload struct {
	Schema               string `json:"schema"`
	Profile              string `json:"profile"`
	Kind                 string `json:"kind"`
	ReceiverID           string `json:"receiver_id"`
	RouteID              string `json:"route_id"`
	RelayOrigin          string `json:"relay_origin"`
	AttemptID            string `json:"attempt_id,omitempty"`
	ClientID             string `json:"client_id"`
	RequestSHA256        string `json:"request_sha256"`
	PairingPublicKeyPEM  string `json:"pairing_public_key_pem"`
	CredentialGeneration uint64 `json:"credential_generation"`
	IssuedUnix           int64  `json:"issued_unix"`
	ExpiresUnix          int64  `json:"expires_unix"`
	Authorization        string `json:"authorization"`
}

type renewalPayload struct {
	Schema               string `json:"schema"`
	Profile              string `json:"profile"`
	ReceiverID           string `json:"receiver_id"`
	RouteID              string `json:"route_id"`
	RelayOrigin          string `json:"relay_origin"`
	ClientID             string `json:"client_id"`
	Nonce                string `json:"nonce"`
	CredentialGeneration uint64 `json:"credential_generation"`
	CreatedUnix          int64  `json:"created_unix"`
	ExpiresUnix          int64  `json:"expires_unix"`
	PairingPublicKeyPEM  string `json:"pairing_public_key_pem"`
	ResponseRecipient    string `json:"response_recipient"`
	PublicPayload        string `json:"public_payload"`
}

func encodeCanonical(value any, maximum int) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) == 0 || len(encoded) > maximum {
		return nil, errors.New("receiverpairing: encoded value exceeds its bound")
	}
	return encoded, nil
}

func decodeCanonical(encoded []byte, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return errors.New("receiverpairing: encoded value has an invalid size")
	}
	if err := strictjson.Decode(encoded, target); err != nil {
		return fmt.Errorf("receiverpairing: strict decode: %w", err)
	}
	canonical, err := json.Marshal(target)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) {
		return errors.New("receiverpairing: value is not canonical")
	}
	return nil
}

func signPayload(schema, domain string, payload any, private ed25519.PrivateKey, maximum int) ([]byte, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	signature, err := signing.Sign(domain, payloadBytes, private)
	if err != nil {
		return nil, err
	}
	return encodeCanonical(signedEnvelope{
		Schema: schema, Payload: base64.StdEncoding.EncodeToString(payloadBytes),
		Signature: base64.StdEncoding.EncodeToString(signature),
	}, maximum)
}

func openSigned(encoded []byte, envelopeSchema, domain string, public ed25519.PublicKey, maximum int, target any) error {
	var envelope signedEnvelope
	if err := decodeCanonical(encoded, maximum, &envelope); err != nil {
		return err
	}
	if envelope.Schema != envelopeSchema {
		return errors.New("receiverpairing: signed envelope schema is unsupported")
	}
	payload, err := decodeBase64(envelope.Payload)
	if err != nil {
		return err
	}
	signature, err := decodeBase64(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("receiverpairing: signature encoding is invalid")
	}
	if err := signing.Verify(domain, payload, signature, public); err != nil {
		return err
	}
	if err := strictjson.Decode(payload, target); err != nil {
		return fmt.Errorf("receiverpairing: strict signed payload: %w", err)
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, payload) {
		return errors.New("receiverpairing: signed payload is not canonical")
	}
	return nil
}

func sealAge(schema string, plaintext []byte, recipientText string, maximum int) ([]byte, error) {
	recipient, err := age.ParseX25519Recipient(recipientText)
	if err != nil || recipient.String() != recipientText {
		return nil, errors.New("receiverpairing: age recipient is invalid")
	}
	padded, err := padPlaintext(plaintext)
	if err != nil {
		return nil, err
	}
	defer clear(padded)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(padded); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return encodeCanonical(cipherEnvelope{Schema: schema, Ciphertext: base64.StdEncoding.EncodeToString(ciphertext.Bytes())}, maximum)
}

func openAge(encoded []byte, schema, identityText string, maximum int) ([]byte, error) {
	var envelope cipherEnvelope
	if err := decodeCanonical(encoded, maximum, &envelope); err != nil {
		return nil, err
	}
	if envelope.Schema != schema {
		return nil, errors.New("receiverpairing: ciphertext schema is unsupported")
	}
	ciphertext, err := decodeBase64(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	identityValue, err := age.ParseX25519Identity(identityText)
	if err != nil || identityValue.String() != identityText {
		return nil, errors.New("receiverpairing: age identity is invalid")
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identityValue)
	if err != nil {
		return nil, errors.New("receiverpairing: ciphertext authentication failed")
	}
	padded, err := io.ReadAll(io.LimitReader(reader, paddedPlaintextSize+1))
	if err != nil || len(padded) != paddedPlaintextSize {
		return nil, errors.New("receiverpairing: decrypted payload has an invalid size")
	}
	return unpadPlaintext(padded)
}

func padPlaintext(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > paddedPlaintextSize-paddedHeaderSize {
		return nil, errors.New("receiverpairing: plaintext exceeds its padded class")
	}
	result := make([]byte, paddedPlaintextSize)
	copy(result[:4], paddedMagic[:])
	result[4] = 1
	result[8] = byte(uint32(len(plaintext)) >> 24)
	result[9] = byte(uint32(len(plaintext)) >> 16)
	result[10] = byte(uint32(len(plaintext)) >> 8)
	result[11] = byte(len(plaintext))
	copy(result[paddedHeaderSize:], plaintext)
	if _, err := io.ReadFull(rand.Reader, result[paddedHeaderSize+len(plaintext):]); err != nil {
		clear(result)
		return nil, err
	}
	return result, nil
}

func unpadPlaintext(padded []byte) ([]byte, error) {
	if len(padded) != paddedPlaintextSize || !bytes.Equal(padded[:4], paddedMagic[:]) || padded[4] != 1 ||
		padded[5] != 0 || padded[6] != 0 || padded[7] != 0 {
		return nil, errors.New("receiverpairing: padded plaintext header is invalid")
	}
	size := int(uint32(padded[8])<<24 | uint32(padded[9])<<16 | uint32(padded[10])<<8 | uint32(padded[11]))
	if size <= 0 || size > len(padded)-paddedHeaderSize {
		return nil, errors.New("receiverpairing: padded plaintext length is invalid")
	}
	return append([]byte(nil), padded[paddedHeaderSize:paddedHeaderSize+size]...), nil
}

func decodeBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("receiverpairing: value is not canonical base64")
	}
	return decoded, nil
}

func digestText(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func validateID(value string) error {
	id, err := protocol.ParseID(value)
	if err != nil || id == (protocol.ID{}) {
		return errors.New("receiverpairing: identifier is invalid")
	}
	return nil
}

func validateRoute(value string) error {
	route, err := protocol.ParseRouteID(value)
	if err != nil || route == (protocol.RouteID{}) {
		return errors.New("receiverpairing: route is invalid")
	}
	return nil
}

func validateRelayOrigin(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || value != strings.ToLower(value) || parsed.Scheme != "wss" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" ||
		parsed.Path != "/connects" || parsed.String() != value {
		return errors.New("receiverpairing: relay origin must be one canonical wss /connects URL")
	}
	return nil
}

func validateWindow(created, expires int64, now time.Time, maximum time.Duration) error {
	if created <= 0 || expires <= created || expires-created > int64(maximum/time.Second) {
		return errors.New("receiverpairing: validity window is invalid")
	}
	if now.IsZero() || now.Before(time.Unix(created, 0).Add(-5*time.Minute)) || !now.Before(time.Unix(expires, 0)) {
		return errors.New("receiverpairing: value is expired or not yet valid")
	}
	return nil
}

func validateTrust(trust Trust) error {
	if _, err := identity.ParseSPKIPin(trust.RelayServerSPKI); err != nil {
		return errors.New("receiverpairing: relay server pin is invalid")
	}
	for _, encoded := range []string{trust.OuterEndpointCAPEM, trust.InnerConnectorCAPEM, trust.InnerClientCAPEM} {
		if encoded == "" || len(encoded) > 64<<10 {
			return errors.New("receiverpairing: public trust material is absent or too large")
		}
	}
	return nil
}

func parseAdvertisement(encoded []byte, now time.Time) (advertisementPayload, ed25519.PublicKey, error) {
	var envelope signedEnvelope
	if err := decodeCanonical(encoded, MaxAdvertisementSize, &envelope); err != nil {
		return advertisementPayload{}, nil, err
	}
	if envelope.Schema != advertEnvelopeSchema {
		return advertisementPayload{}, nil, errors.New("receiverpairing: advertisement envelope is unsupported")
	}
	payloadBytes, err := decodeBase64(envelope.Payload)
	if err != nil {
		return advertisementPayload{}, nil, err
	}
	var payload advertisementPayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return advertisementPayload{}, nil, err
	}
	canonical, _ := json.Marshal(payload)
	if !bytes.Equal(canonical, payloadBytes) {
		return advertisementPayload{}, nil, errors.New("receiverpairing: advertisement payload is not canonical")
	}
	public, err := signing.ParsePublic([]byte(payload.ReceiverSigningPublic))
	if err != nil {
		return advertisementPayload{}, nil, err
	}
	if err := openSigned(encoded, advertEnvelopeSchema, advertisementDomain, public, MaxAdvertisementSize, &payload); err != nil {
		return advertisementPayload{}, nil, err
	}
	if payload.Schema != advertisementSchema || payload.Profile != Profile || validateID(payload.ReceiverID) != nil ||
		validateRoute(payload.RouteID) != nil || validateRelayOrigin(payload.RelayOrigin) != nil ||
		validateWindow(payload.CreatedUnix, payload.ExpiresUnix, now, MaxAttemptValidity) != nil ||
		validateGeneratedTrust(payload.Trust, public, now) != nil {
		return advertisementPayload{}, nil, errors.New("receiverpairing: advertisement fields are invalid")
	}
	if err := validateID(payload.AttemptID); err != nil {
		return advertisementPayload{}, nil, err
	}
	recipient, err := age.ParseX25519Recipient(payload.ReceiverAgeRecipient)
	if err != nil || recipient.String() != payload.ReceiverAgeRecipient {
		return advertisementPayload{}, nil, errors.New("receiverpairing: receiver age recipient is invalid")
	}
	return payload, public, nil
}

func encodeCode(payload codePayload) ([]byte, error) {
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > MaxCodeSize/2 {
		return nil, errors.New("receiverpairing: code payload is invalid")
	}
	return []byte(codePrefix + base64.RawURLEncoding.EncodeToString(encoded)), nil
}

func parseCode(encoded []byte) (codePayload, error) {
	if len(encoded) <= len(codePrefix) || len(encoded) > MaxCodeSize || !bytes.HasPrefix(encoded, []byte(codePrefix)) {
		return codePayload{}, errors.New("receiverpairing: private code is invalid")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(string(encoded[len(codePrefix):]))
	if err != nil || codePrefix+base64.RawURLEncoding.EncodeToString(payloadBytes) != string(encoded) {
		return codePayload{}, errors.New("receiverpairing: private code is invalid")
	}
	var payload codePayload
	if err := strictjson.Decode(payloadBytes, &payload); err != nil {
		return codePayload{}, errors.New("receiverpairing: private code is invalid")
	}
	canonical, _ := json.Marshal(payload)
	secret, secretErr := base64.RawURLEncoding.DecodeString(payload.Secret)
	if !bytes.Equal(canonical, payloadBytes) || payload.Schema != codeSchema || validateID(payload.ReceiverID) != nil ||
		validateID(payload.AttemptID) != nil || !validDigest(payload.AdvertisementSHA256) || secretErr != nil || len(secret) != secretSize ||
		base64.RawURLEncoding.EncodeToString(secret) != payload.Secret {
		return codePayload{}, errors.New("receiverpairing: private code is invalid")
	}
	return payload, nil
}

func constantDigestEqual(first, second string) bool {
	if len(first) != sha256.Size*2 || len(second) != sha256.Size*2 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}

func randomID() (string, error) {
	value, err := protocol.NewID()
	if err != nil {
		return "", err
	}
	return value.String(), nil
}

func randomSecret() ([]byte, error) {
	value := make([]byte, secretSize)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return nil, err
	}
	return value, nil
}
