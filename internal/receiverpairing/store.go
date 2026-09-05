//go:build darwin || linux

package receiverpairing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math"
	"path/filepath"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const (
	stateSchema = "owntransit.receiver-pairing.state.v1"
	stateFile   = "state.json"
	lockFile    = "state.lock"

	receiverSigningKeyFile   = "receiver-signing-key.pem"
	receiverAgeIdentityFile  = "receiver-age-identity.txt"
	outerCACertFile          = "outer-endpoint-ca-cert.pem"
	outerCAKeyFile           = "outer-endpoint-ca-key.pem"
	innerConnectorCACertFile = "inner-connector-ca-cert.pem"
	innerConnectorCAKeyFile  = "inner-connector-ca-key.pem"
	innerClientCACertFile    = "inner-client-ca-cert.pem"
	innerClientCAKeyFile     = "inner-client-ca-key.pem"

	maxStateSize      = 2 << 20
	maxPrivateKeySize = 16 << 10
	maxAgeIdentity    = 4 << 10
	maxRetiredCodes   = 64
	authorityValidity = 2 * 365 * 24 * time.Hour
)

type Receiver struct {
	rootPath string
}

type attemptRecord struct {
	AttemptID           string `json:"attempt_id"`
	ExpiresUnix         int64  `json:"expires_unix"`
	Advertisement       string `json:"advertisement"`
	AdvertisementSHA256 string `json:"advertisement_sha256"`
	CodeSHA256          string `json:"code_sha256"`
}

type peerRecord struct {
	Authorization            []byte `json:"authorization"`
	ClientID                 string `json:"client_id"`
	PairingPublicKeyPEM      string `json:"pairing_public_key_pem"`
	AttemptID                string `json:"attempt_id"`
	InitialRequestSHA256     string `json:"initial_request_sha256"`
	InitialResponse          string `json:"initial_response"`
	CredentialGeneration     uint64 `json:"credential_generation"`
	Locked                   bool   `json:"locked"`
	Revoked                  bool   `json:"revoked"`
	LastRenewalRequestSHA256 string `json:"last_renewal_request_sha256,omitempty"`
	LastRenewalResponse      string `json:"last_renewal_response,omitempty"`
}

// PeerAuthorization returns the public issuance result committed atomically
// with the peer binding. It contains no endpoint private key. A forwarding
// worker must never read the authority store directly.
func (receiver *Receiver) PeerAuthorization() ([]byte, error) {
	root, err := securefs.OpenRoot(receiver.rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil {
		return nil, err
	}
	if state.Peer == nil {
		return nil, nil
	}
	if len(state.Peer.Authorization) == 0 || len(state.Peer.Authorization) > MaxAuthorizationSize {
		return nil, errors.New("receiverpairing: invalid committed authorization")
	}
	return append([]byte(nil), state.Peer.Authorization...), nil
}

type stateRecord struct {
	Schema            string         `json:"schema"`
	Profile           string         `json:"profile"`
	Generation        uint64         `json:"generation"`
	ReceiverID        string         `json:"receiver_id"`
	RouteID           string         `json:"route_id"`
	RelayOrigin       string         `json:"relay_origin"`
	RelayServerSPKI   string         `json:"relay_server_spki_sha256"`
	LocalLocked       bool           `json:"local_locked"`
	Attempt           *attemptRecord `json:"attempt,omitempty"`
	Peer              *peerRecord    `json:"peer,omitempty"`
	RetiredCodeSHA256 []string       `json:"retired_code_sha256"`
}

type receiverSecrets struct {
	signingPrivate  ed25519.PrivateKey
	signingPublic   []byte
	ageIdentity     *age.X25519Identity
	trust           Trust
	outerIssuer     pki.Material
	connectorIssuer pki.Material
	clientIssuer    pki.Material
}

type AuthorityMaterial struct {
	OuterEndpoint  pki.Material
	InnerConnector pki.Material
	InnerClient    pki.Material
}

func (AuthorityMaterial) String() string   { return "receiverpairing.AuthorityMaterial[REDACTED]" }
func (AuthorityMaterial) GoString() string { return "receiverpairing.AuthorityMaterial[REDACTED]" }

func Initialize(options InitializeOptions) (ReceiverStatus, error) {
	now := options.Now.UTC().Truncate(time.Second)
	if now.IsZero() || options.RootPath == "" || filepath.Clean(options.RootPath) != options.RootPath || !filepath.IsAbs(options.RootPath) {
		return ReceiverStatus{}, errors.New("receiverpairing: canonical private root and current time are required")
	}
	if err := validateRelayOrigin(options.RelayOrigin); err != nil {
		return ReceiverStatus{}, err
	}
	if err := identityPin(options.RelayServerSPKI); err != nil {
		return ReceiverStatus{}, err
	}
	receiverID := options.ReceiverID
	if receiverID == "" {
		var err error
		receiverID, err = randomID()
		if err != nil {
			return ReceiverStatus{}, err
		}
	}
	if err := validateID(receiverID); err != nil {
		return ReceiverStatus{}, err
	}
	routeID := options.RouteID
	if routeID == "" {
		route, err := protocol.NewRouteID()
		if err != nil {
			return ReceiverStatus{}, err
		}
		routeID = route.String()
	}
	if err := validateRoute(routeID); err != nil {
		return ReceiverStatus{}, err
	}
	signingPair, err := signing.Generate()
	if err != nil {
		return ReceiverStatus{}, err
	}
	ageIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return ReceiverStatus{}, err
	}
	outerCA, err := pki.NewCA("OwnTransit receiver "+receiverID+" outer endpoint CA", now, authorityValidity)
	if err != nil {
		return ReceiverStatus{}, err
	}
	innerConnectorCA, err := pki.NewCA("OwnTransit receiver "+receiverID+" inner connector CA", now, authorityValidity)
	if err != nil {
		return ReceiverStatus{}, err
	}
	innerClientCA, err := pki.NewCA("OwnTransit receiver "+receiverID+" inner client CA", now, authorityValidity)
	if err != nil {
		return ReceiverStatus{}, err
	}
	trust := Trust{
		RelayServerSPKI: options.RelayServerSPKI, OuterEndpointCAPEM: string(outerCA.CertPEM),
		InnerConnectorCAPEM: string(innerConnectorCA.CertPEM), InnerClientCAPEM: string(innerClientCA.CertPEM),
	}
	if err := validateGeneratedTrust(trust, signingPair.Public, now); err != nil {
		return ReceiverStatus{}, err
	}
	state := stateRecord{
		Schema: stateSchema, Profile: Profile, Generation: 1, ReceiverID: receiverID,
		RouteID: routeID, RelayOrigin: options.RelayOrigin, RelayServerSPKI: options.RelayServerSPKI,
		RetiredCodeSHA256: []string{},
	}
	encodedState, err := encodeState(state)
	if err != nil {
		return ReceiverStatus{}, err
	}
	root, err := securefs.CreateRoot(options.RootPath)
	if err != nil {
		return ReceiverStatus{}, err
	}
	defer root.Close()
	files := []struct {
		name string
		data []byte
	}{
		{receiverSigningKeyFile, signingPair.PrivatePEM},
		{receiverAgeIdentityFile, []byte(ageIdentity.String() + "\n")},
		{outerCACertFile, outerCA.CertPEM}, {outerCAKeyFile, outerCA.KeyPEM},
		{innerConnectorCACertFile, innerConnectorCA.CertPEM}, {innerConnectorCAKeyFile, innerConnectorCA.KeyPEM},
		{innerClientCACertFile, innerClientCA.CertPEM}, {innerClientCAKeyFile, innerClientCA.KeyPEM},
	}
	for _, file := range files {
		if err := root.CreateExclusive(file.name, file.data, 0o600); err != nil {
			return ReceiverStatus{}, err
		}
	}
	if err := root.CreateExclusive(stateFile, encodedState, 0o600); err != nil {
		return ReceiverStatus{}, err
	}
	return statusFromState(state), nil
}

func Open(rootPath string) (*Receiver, error) {
	if rootPath == "" || filepath.Clean(rootPath) != rootPath || !filepath.IsAbs(rootPath) {
		return nil, errors.New("receiverpairing: private root path is invalid")
	}
	root, err := securefs.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil {
		return nil, err
	}
	if _, err := readSecrets(root, state, time.Now().UTC()); err != nil {
		return nil, err
	}
	return &Receiver{rootPath: rootPath}, nil
}

func (receiver *Receiver) Status() (ReceiverStatus, error) {
	root, err := securefs.OpenRoot(receiver.rootPath)
	if err != nil {
		return ReceiverStatus{}, err
	}
	defer root.Close()
	state, err := readState(root)
	if err != nil {
		return ReceiverStatus{}, err
	}
	return statusFromState(state), nil
}

// RuntimeSnapshot reads one atomic state record. Public issuer material is
// immutable for this receiver, so readers do not contend with the claim lock.
func (receiver *Receiver) RuntimeSnapshot(now time.Time) (ReceiverStatus, Trust, []byte, error) {
	root, err := securefs.OpenRoot(receiver.rootPath)
	if err != nil {
		return ReceiverStatus{}, Trust{}, nil, err
	}
	defer root.Close()
	s, err := readState(root)
	if err != nil {
		return ReceiverStatus{}, Trust{}, nil, err
	}
	secrets, err := readSecrets(root, s, now)
	if err != nil {
		return ReceiverStatus{}, Trust{}, nil, err
	}
	var authorization []byte
	if s.Peer != nil {
		authorization = append([]byte(nil), s.Peer.Authorization...)
	}
	return statusFromState(s), secrets.trust, authorization, nil
}

// LoadPrivateAuthority is an explicit secret-bearing operation for the
// privileged issuer callback. These keys must never enter runtime or relay
// state.
func (receiver *Receiver) LoadPrivateAuthority(now time.Time) (AuthorityMaterial, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return AuthorityMaterial{}, err
	}
	defer root.Close()
	defer lock.Close()
	secrets, err := readSecrets(root, state, now.UTC().Truncate(time.Second))
	if err != nil {
		return AuthorityMaterial{}, err
	}
	return AuthorityMaterial{OuterEndpoint: secrets.outerIssuer, InnerConnector: secrets.connectorIssuer, InnerClient: secrets.clientIssuer}, nil
}

func (receiver *Receiver) PublicTrust(now time.Time) (Trust, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return Trust{}, err
	}
	defer root.Close()
	defer lock.Close()
	secrets, err := readSecrets(root, state, now.UTC().Truncate(time.Second))
	if err != nil {
		return Trust{}, err
	}
	return secrets.trust, nil
}

func (receiver *Receiver) CurrentAdvertisement(now time.Time) ([]byte, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer lock.Close()
	if state.Attempt == nil {
		return nil, errors.New("receiverpairing: no pending pairing attempt")
	}
	encoded, err := decodeBase64(state.Attempt.Advertisement)
	if err != nil {
		return nil, err
	}
	info, err := VerifyAdvertisement(encoded, now)
	if err != nil || info.ReceiverID != state.ReceiverID || info.AttemptID != state.Attempt.AttemptID {
		return nil, errors.New("receiverpairing: pending advertisement is invalid")
	}
	return encoded, nil
}

func (receiver *Receiver) CreateAttempt(now time.Time, validity time.Duration) (Attempt, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || validity <= 0 || validity > MaxAttemptValidity {
		return Attempt{}, errors.New("receiverpairing: bounded attempt validity and current time are required")
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return Attempt{}, err
	}
	defer root.Close()
	defer lock.Close()
	if state.LocalLocked {
		return Attempt{}, errors.New("receiverpairing: receiver is locally locked")
	}
	if state.Peer != nil {
		return Attempt{}, errors.New("receiverpairing: receiver already has a paired peer")
	}
	if state.Attempt != nil && now.Unix() < state.Attempt.ExpiresUnix {
		return Attempt{}, errors.New("receiverpairing: a pairing attempt is already pending")
	}
	if state.Generation == math.MaxUint64 {
		return Attempt{}, errors.New("receiverpairing: state generation is exhausted")
	}
	if state.Attempt != nil {
		state.RetiredCodeSHA256 = appendRetiredCode(state.RetiredCodeSHA256, state.Attempt.CodeSHA256)
	}
	secrets, err := readSecrets(root, state, now)
	if err != nil {
		return Attempt{}, err
	}
	attemptID, err := randomID()
	if err != nil {
		return Attempt{}, err
	}
	expires := now.Add(validity)
	advertisementPayload := advertisementPayload{
		Schema: advertisementSchema, Profile: Profile, ReceiverID: state.ReceiverID, RouteID: state.RouteID,
		RelayOrigin: state.RelayOrigin, AttemptID: attemptID, CreatedUnix: now.Unix(), ExpiresUnix: expires.Unix(),
		ReceiverSigningPublic: string(secrets.signingPublic), ReceiverAgeRecipient: secrets.ageIdentity.Recipient().String(), Trust: secrets.trust,
	}
	advertisement, err := signPayload(advertEnvelopeSchema, advertisementDomain, advertisementPayload, secrets.signingPrivate, MaxAdvertisementSize)
	if err != nil {
		return Attempt{}, err
	}
	secret, err := randomSecret()
	if err != nil {
		return Attempt{}, err
	}
	defer clear(secret)
	code, err := encodeCode(codePayload{
		Schema: codeSchema, ReceiverID: state.ReceiverID, AttemptID: attemptID, ExpiresUnix: expires.Unix(),
		AdvertisementSHA256: digestText(advertisement), Secret: base64.RawURLEncoding.EncodeToString(secret),
	})
	if err != nil {
		return Attempt{}, err
	}
	state.Generation++
	state.Attempt = &attemptRecord{
		AttemptID: attemptID, ExpiresUnix: expires.Unix(), Advertisement: base64.StdEncoding.EncodeToString(advertisement),
		AdvertisementSHA256: digestText(advertisement), CodeSHA256: digestText(code),
	}
	if err := writeState(root, state); err != nil {
		clear(code)
		return Attempt{}, err
	}
	return Attempt{Advertisement: advertisement, Code: code, ReceiverID: state.ReceiverID, AttemptID: attemptID, Expires: expires}, nil
}

func (receiver *Receiver) CancelAttempt() (ReceiverStatus, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return ReceiverStatus{}, err
	}
	defer root.Close()
	defer lock.Close()
	if state.Attempt == nil {
		return ReceiverStatus{}, errors.New("receiverpairing: no pending pairing attempt")
	}
	if state.Generation == math.MaxUint64 {
		return ReceiverStatus{}, errors.New("receiverpairing: state generation is exhausted")
	}
	state.RetiredCodeSHA256 = appendRetiredCode(state.RetiredCodeSHA256, state.Attempt.CodeSHA256)
	state.Attempt = nil
	state.Generation++
	if err := writeState(root, state); err != nil {
		return ReceiverStatus{}, err
	}
	return statusFromState(state), nil
}

func (receiver *Receiver) SetLocalLocked(locked bool) (ReceiverStatus, error) {
	return receiver.updateState(func(state *stateRecord) error {
		state.LocalLocked = locked
		return nil
	})
}

func (receiver *Receiver) SetPeerLocked(locked bool) (ReceiverStatus, error) {
	return receiver.updateState(func(state *stateRecord) error {
		if state.Peer == nil {
			return errors.New("receiverpairing: no paired peer")
		}
		if state.Peer.Revoked && !locked {
			return errors.New("receiverpairing: revoked peer cannot be unlocked")
		}
		state.Peer.Locked = locked
		return nil
	})
}

func (receiver *Receiver) RevokePeer() (ReceiverStatus, error) {
	return receiver.updateState(func(state *stateRecord) error {
		if state.Peer == nil {
			return errors.New("receiverpairing: no paired peer")
		}
		state.Peer.Locked, state.Peer.Revoked = true, true
		return nil
	})
}

func (receiver *Receiver) updateState(change func(*stateRecord) error) (ReceiverStatus, error) {
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return ReceiverStatus{}, err
	}
	defer root.Close()
	defer lock.Close()
	if state.Generation == math.MaxUint64 {
		return ReceiverStatus{}, errors.New("receiverpairing: state generation is exhausted")
	}
	if err := change(&state); err != nil {
		return ReceiverStatus{}, err
	}
	state.Generation++
	if err := writeState(root, state); err != nil {
		return ReceiverStatus{}, err
	}
	return statusFromState(state), nil
}

func (receiver *Receiver) lockedState() (*securefs.Root, *securefs.Lock, stateRecord, error) {
	if receiver == nil || receiver.rootPath == "" {
		return nil, nil, stateRecord{}, errors.New("receiverpairing: receiver is unavailable")
	}
	root, err := securefs.OpenRoot(receiver.rootPath)
	if err != nil {
		return nil, nil, stateRecord{}, err
	}
	lock, err := root.TryLock(lockFile)
	if err != nil {
		root.Close()
		return nil, nil, stateRecord{}, err
	}
	state, err := readState(root)
	if err != nil {
		lock.Close()
		root.Close()
		return nil, nil, stateRecord{}, err
	}
	return root, lock, state, nil
}

func readSecrets(root *securefs.Root, state stateRecord, now time.Time) (receiverSecrets, error) {
	privatePEM, err := root.ReadFile(receiverSigningKeyFile, maxPrivateKeySize)
	if err != nil {
		return receiverSecrets{}, err
	}
	private, err := signing.ParsePrivate(privatePEM)
	if err != nil {
		return receiverSecrets{}, err
	}
	publicDER, err := signingPublicPEM(private.Public().(ed25519.PublicKey))
	if err != nil {
		return receiverSecrets{}, err
	}
	ageBytes, err := root.ReadFile(receiverAgeIdentityFile, maxAgeIdentity)
	if err != nil || len(ageBytes) < 2 || ageBytes[len(ageBytes)-1] != '\n' {
		return receiverSecrets{}, errors.New("receiverpairing: receiver age identity is invalid")
	}
	ageIdentity, err := age.ParseX25519Identity(string(ageBytes[:len(ageBytes)-1]))
	if err != nil {
		return receiverSecrets{}, errors.New("receiverpairing: receiver age identity is invalid")
	}
	outerIssuer, err := readIssuer(root, outerCACertFile, outerCAKeyFile, now)
	if err != nil {
		return receiverSecrets{}, err
	}
	innerConnectorIssuer, err := readIssuer(root, innerConnectorCACertFile, innerConnectorCAKeyFile, now)
	if err != nil {
		return receiverSecrets{}, err
	}
	innerClientIssuer, err := readIssuer(root, innerClientCACertFile, innerClientCAKeyFile, now)
	if err != nil {
		return receiverSecrets{}, err
	}
	trust := Trust{
		RelayServerSPKI: state.RelayServerSPKI, OuterEndpointCAPEM: string(outerIssuer.CertPEM),
		InnerConnectorCAPEM: string(innerConnectorIssuer.CertPEM), InnerClientCAPEM: string(innerClientIssuer.CertPEM),
	}
	if err := validateGeneratedTrust(trust, private.Public().(ed25519.PublicKey), now); err != nil {
		return receiverSecrets{}, err
	}
	return receiverSecrets{
		signingPrivate: private, signingPublic: publicDER, ageIdentity: ageIdentity, trust: trust,
		outerIssuer: outerIssuer, connectorIssuer: innerConnectorIssuer, clientIssuer: innerClientIssuer,
	}, nil
}

func readIssuer(root *securefs.Root, certificateFile, keyFile string, now time.Time) (pki.Material, error) {
	certificate, err := root.ReadFile(certificateFile, 64<<10)
	if err != nil {
		return pki.Material{}, err
	}
	privateKey, err := root.ReadFile(keyFile, maxPrivateKeySize)
	if err != nil {
		return pki.Material{}, err
	}
	issuer, err := pki.ParseIssuer(certificate, privateKey, now)
	if err != nil {
		return pki.Material{}, errors.New("receiverpairing: receiver authority material is invalid")
	}
	return issuer, nil
}

func validateGeneratedTrust(trust Trust, signer ed25519.PublicKey, now time.Time) error {
	if err := validateTrust(trust); err != nil {
		return err
	}
	return enrollment.ValidateBootstrapAuthorities(enrollment.Trust{
		RelayAdmissionCA: trust.OuterEndpointCAPEM, InnerConnectorCA: trust.InnerConnectorCAPEM, InnerClientCA: trust.InnerClientCAPEM,
	}, signer, now)
}

func identityPin(value string) error {
	_, err := identity.ParseSPKIPin(value)
	if err != nil {
		return errors.New("receiverpairing: relay server pin is invalid")
	}
	return nil
}

func signingPublicPEM(public ed25519.PublicKey) ([]byte, error) {
	// Generate canonical public encoding through the existing signing parser's
	// inverse representation without introducing a second key format.
	der, err := x509MarshalPublic(public)
	if err != nil {
		return nil, err
	}
	return pemPublic(der), nil
}

func encodeState(state stateRecord) ([]byte, error) {
	if err := state.validate(); err != nil {
		return nil, err
	}
	return encodeCanonical(state, maxStateSize)
}

func readState(root *securefs.Root) (stateRecord, error) {
	encoded, err := root.ReadFile(stateFile, maxStateSize)
	if err != nil {
		return stateRecord{}, err
	}
	var state stateRecord
	if err := decodeCanonical(encoded, maxStateSize, &state); err != nil {
		return stateRecord{}, err
	}
	if err := state.validate(); err != nil {
		return stateRecord{}, err
	}
	return state, nil
}

func writeState(root *securefs.Root, state stateRecord) error {
	encoded, err := encodeState(state)
	if err != nil {
		return err
	}
	return root.ReplaceFile(stateFile, encoded, 0o600)
}

func (state stateRecord) validate() error {
	if state.Schema != stateSchema || state.Profile != Profile || state.Generation == 0 || validateID(state.ReceiverID) != nil ||
		validateRoute(state.RouteID) != nil || validateRelayOrigin(state.RelayOrigin) != nil || len(state.RetiredCodeSHA256) > maxRetiredCodes {
		return errors.New("receiverpairing: durable state is invalid")
	}
	if err := identityPin(state.RelayServerSPKI); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(state.RetiredCodeSHA256))
	for _, digest := range state.RetiredCodeSHA256 {
		if !validDigest(digest) {
			return errors.New("receiverpairing: retired code digest is invalid")
		}
		if _, duplicate := seen[digest]; duplicate {
			return errors.New("receiverpairing: retired code digest is duplicated")
		}
		seen[digest] = struct{}{}
	}
	if state.Attempt != nil && state.Peer != nil {
		return errors.New("receiverpairing: pending and paired state conflict")
	}
	if state.Attempt != nil {
		advertisement, err := decodeBase64(state.Attempt.Advertisement)
		if err != nil || validateID(state.Attempt.AttemptID) != nil || state.Attempt.ExpiresUnix <= 0 ||
			!constantDigestEqual(digestText(advertisement), state.Attempt.AdvertisementSHA256) || !validDigest(state.Attempt.CodeSHA256) {
			return errors.New("receiverpairing: pending attempt state is invalid")
		}
	}
	if state.Peer != nil {
		peer := state.Peer
		public, err := signing.ParsePublic([]byte(peer.PairingPublicKeyPEM))
		if err != nil || len(public) != ed25519.PublicKeySize || validateID(peer.ClientID) != nil || validateID(peer.AttemptID) != nil ||
			!validDigest(peer.InitialRequestSHA256) || peer.CredentialGeneration == 0 {
			return errors.New("receiverpairing: paired peer state is invalid")
		}
		if _, err := decodeBase64(peer.InitialResponse); err != nil {
			return errors.New("receiverpairing: stored initial response is invalid")
		}
		if peer.Revoked && !peer.Locked {
			return errors.New("receiverpairing: revoked peer must remain locked")
		}
		if (peer.LastRenewalRequestSHA256 == "") != (peer.LastRenewalResponse == "") {
			return errors.New("receiverpairing: renewal retry state is incomplete")
		}
		if peer.LastRenewalRequestSHA256 != "" {
			if !validDigest(peer.LastRenewalRequestSHA256) {
				return errors.New("receiverpairing: renewal request digest is invalid")
			}
			if _, err := decodeBase64(peer.LastRenewalResponse); err != nil {
				return errors.New("receiverpairing: stored renewal response is invalid")
			}
		}
	}
	return nil
}

func appendRetiredCode(values []string, value string) []string {
	for _, existing := range values {
		if constantDigestEqual(existing, value) {
			return values
		}
	}
	if len(values) == maxRetiredCodes {
		values = append([]string(nil), values[1:]...)
	}
	return append(values, value)
}

func statusFromState(state stateRecord) ReceiverStatus {
	status := ReceiverStatus{ReceiverID: state.ReceiverID, RouteID: state.RouteID, RelayOrigin: state.RelayOrigin, Generation: state.Generation, LocalLocked: state.LocalLocked}
	if state.Attempt != nil {
		status.PendingAttemptID = state.Attempt.AttemptID
	}
	if state.Peer != nil {
		status.PairedClientID = state.Peer.ClientID
		status.CredentialGeneration = state.Peer.CredentialGeneration
		status.PeerLocked, status.PeerRevoked = state.Peer.Locked, state.Peer.Revoked
	}
	return status
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// Small wrappers keep canonical public-key encoding localized.
func x509MarshalPublic(public ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(public)
}
func pemPublic(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
