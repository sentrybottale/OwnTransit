//go:build darwin || linux

package receiverpairing

import (
	"errors"
	"math"
	"time"

	"filippo.io/age"
	"github.com/sentrybottale/owntransit/internal/signing"
)

// This additive, explicitly versioned extension authenticates a read-only
// generation snapshot. It cannot issue credentials or reopen an expired request.
// Legacy renewal, private state, carrier framing and TLS profiles are unchanged.
const (
	statusProfile          = "owntransit-renewal-status/1"
	statusRequestSchema    = "owntransit.renewal-status.request.v1"
	statusRequestEnvelope  = "owntransit.renewal-status.request-envelope.v1"
	statusRequestCipher    = "owntransit.renewal-status.request-ciphertext.v1"
	statusResponseSchema   = "owntransit.renewal-status.response.v1"
	statusResponseEnvelope = "owntransit.renewal-status.response-envelope.v1"
	statusResponseCipher   = "owntransit.renewal-status.response-ciphertext.v1"
	statusRequestDomain    = "OwnTransit renewal status request v1"
	statusResponseDomain   = "OwnTransit renewal status response v1"
	statusValidity         = time.Minute
)

type renewalStatusPayload struct {
	Schema            string `json:"schema"`
	Profile           string `json:"profile"`
	ReceiverID        string `json:"receiver_id"`
	RouteID           string `json:"route_id"`
	RelayOrigin       string `json:"relay_origin"`
	ClientID          string `json:"client_id"`
	PendingSHA256     string `json:"pending_sha256"`
	KnownGeneration   uint64 `json:"known_generation"`
	Nonce             string `json:"nonce"`
	ResponseRecipient string `json:"response_recipient"`
	CreatedUnix       int64  `json:"created_unix"`
	ExpiresUnix       int64  `json:"expires_unix"`
}

type renewalStatusResponse struct {
	Schema        string `json:"schema"`
	Profile       string `json:"profile"`
	ReceiverID    string `json:"receiver_id"`
	RouteID       string `json:"route_id"`
	RelayOrigin   string `json:"relay_origin"`
	ClientID      string `json:"client_id"`
	QuerySHA256   string `json:"query_sha256"`
	PendingSHA256 string `json:"pending_sha256"`
	Generation    uint64 `json:"generation"`
	IssuedUnix    int64  `json:"issued_unix"`
	ExpiresUnix   int64  `json:"expires_unix"`
}

// RenewalStatusRequest is transient. A restart generates another challenge from
// the unchanged durable pending renewal. No new private-state schema is needed.
type RenewalStatusRequest struct {
	Encrypted        []byte
	material         RenewalMaterial
	responseIdentity string
	requestSHA       string
	createdUnix      int64
	expiresUnix      int64
}

func (RenewalStatusRequest) String() string { return "receiverpairing.RenewalStatusRequest[REDACTED]" }
func (RenewalStatusRequest) GoString() string {
	return "receiverpairing.RenewalStatusRequest[REDACTED]"
}

func CreateRenewalStatus(material RenewalMaterial, origin string, now time.Time) (RenewalStatusRequest, error) {
	now = now.UTC().Truncate(time.Second)
	if validateRenewalMaterial(material) != nil || now.IsZero() || origin != material.pairing.relayOrigin || material.pairing.generation == math.MaxUint64 {
		return RenewalStatusRequest{}, errors.New("receiverpairing: invalid renewal status context")
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return RenewalStatusRequest{}, err
	}
	nonce, err := randomID()
	if err != nil {
		return RenewalStatusRequest{}, err
	}
	p := material.pairing
	req := renewalStatusPayload{Schema: statusRequestSchema, Profile: statusProfile, ReceiverID: p.receiverID, RouteID: p.routeID, RelayOrigin: p.relayOrigin, ClientID: p.clientID, PendingSHA256: material.requestSHA, KnownGeneration: p.generation, Nonce: nonce, ResponseRecipient: id.Recipient().String(), CreatedUnix: now.Unix(), ExpiresUnix: now.Add(statusValidity).Unix()}
	key, err := signing.ParsePrivate(p.pairingPrivate)
	if err != nil {
		return RenewalStatusRequest{}, err
	}
	signed, err := signPayload(statusRequestEnvelope, statusRequestDomain, req, key, MaxRequestSize)
	if err != nil {
		return RenewalStatusRequest{}, err
	}
	wire, err := sealAge(statusRequestCipher, signed, p.receiverRecipient, MaxRequestSize)
	if err != nil {
		return RenewalStatusRequest{}, err
	}
	return RenewalStatusRequest{Encrypted: wire, material: material, responseIdentity: id.String(), requestSHA: digestText(wire), createdUnix: req.CreatedUnix, expiresUnix: req.ExpiresUnix}, nil
}

// RenewalStatus performs no state write, issuance, or SSH dial. The same lock as
// Renew makes the signed snapshot internally consistent. Later commits may make
// it stale; ordinary next-generation validation still arbitrates the next Renew.
func (receiver *Receiver) RenewalStatus(encoded []byte, now time.Time) ([]byte, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(encoded) == 0 || len(encoded) > MaxRequestSize {
		return nil, errors.New("receiverpairing: invalid status query")
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer lock.Close()
	if state.LocalLocked || state.Peer == nil || state.Peer.Locked || state.Peer.Revoked {
		return nil, errors.New("receiverpairing: status is not available")
	}
	secrets, err := readSecrets(root, state, now)
	if err != nil {
		return nil, err
	}
	public, err := signing.ParsePublic([]byte(state.Peer.PairingPublicKeyPEM))
	if err != nil {
		return nil, err
	}
	plain, err := openAge(encoded, statusRequestCipher, secrets.ageIdentity.String(), MaxRequestSize)
	if err != nil {
		return nil, err
	}
	var req renewalStatusPayload
	if err := openSigned(plain, statusRequestEnvelope, statusRequestDomain, public, MaxRequestSize, &req); err != nil {
		return nil, err
	}
	if req.Schema != statusRequestSchema || req.Profile != statusProfile || req.ReceiverID != state.ReceiverID || req.RouteID != state.RouteID || req.RelayOrigin != state.RelayOrigin || req.ClientID != state.Peer.ClientID || !validDigest(req.PendingSHA256) || validateID(req.Nonce) != nil || req.KnownGeneration == 0 || req.KnownGeneration == math.MaxUint64 || validateWindow(req.CreatedUnix, req.ExpiresUnix, now, statusValidity) != nil {
		return nil, errors.New("receiverpairing: invalid signed status query")
	}
	generation := state.Peer.CredentialGeneration
	if generation != req.KnownGeneration && generation != req.KnownGeneration+1 {
		return nil, errors.New("receiverpairing: status generation is outside pending renewal")
	}
	// Use the query's exact window. This also tolerates the ordinary bounded clock
	// skew without minting a response that outlives the requesting client context.
	response := renewalStatusResponse{Schema: statusResponseSchema, Profile: statusProfile, ReceiverID: state.ReceiverID, RouteID: state.RouteID, RelayOrigin: state.RelayOrigin, ClientID: state.Peer.ClientID, QuerySHA256: digestText(encoded), PendingSHA256: req.PendingSHA256, Generation: generation, IssuedUnix: req.CreatedUnix, ExpiresUnix: req.ExpiresUnix}
	signed, err := signPayload(statusResponseEnvelope, statusResponseDomain, response, secrets.signingPrivate, MaxResponseSize)
	if err != nil {
		return nil, err
	}
	return sealAge(statusResponseCipher, signed, req.ResponseRecipient, MaxResponseSize)
}

// RecoverRenewalStatus only prepares a fresh ordinary renewal. Neither the
// snapshot nor any expired authorization is returned as an activation grant.
func RecoverRenewalStatus(encoded []byte, query RenewalStatusRequest, origin string, now time.Time, build PayloadBuilder) (RenewalRequest, error) {
	now = now.UTC().Truncate(time.Second)
	material := query.material
	if validateRenewalMaterial(material) != nil || origin != material.pairing.relayOrigin || !validDigest(query.requestSHA) || digestText(query.Encrypted) != query.requestSHA || validateWindow(query.createdUnix, query.expiresUnix, now, statusValidity) != nil {
		return RenewalRequest{}, errors.New("receiverpairing: invalid status response context")
	}
	public, err := signing.ParsePublic(material.pairing.receiverPublic)
	if err != nil {
		return RenewalRequest{}, err
	}
	plain, err := openAge(encoded, statusResponseCipher, query.responseIdentity, MaxResponseSize)
	if err != nil {
		return RenewalRequest{}, err
	}
	var response renewalStatusResponse
	if err := openSigned(plain, statusResponseEnvelope, statusResponseDomain, public, MaxResponseSize, &response); err != nil {
		return RenewalRequest{}, err
	}
	p := material.pairing
	if response.Schema != statusResponseSchema || response.Profile != statusProfile || response.ReceiverID != p.receiverID || response.RouteID != p.routeID || response.RelayOrigin != p.relayOrigin || response.ClientID != p.clientID || response.QuerySHA256 != query.requestSHA || response.PendingSHA256 != material.requestSHA || response.IssuedUnix != query.createdUnix || response.ExpiresUnix != query.expiresUnix || validateWindow(response.IssuedUnix, response.ExpiresUnix, now, statusValidity) != nil || (response.Generation != p.generation && response.Generation != material.nextGeneration) {
		return RenewalRequest{}, errors.New("receiverpairing: status does not bind the exact pending renewal")
	}
	p.generation = response.Generation
	return CreateRenewalWithPayload(p, origin, now, MaxMessageValidity, build)
}
