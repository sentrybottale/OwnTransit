//go:build darwin || linux

package receiverpairing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

func CreateRequest(options CreateRequestOptions) (ClientRequest, error) {
	return CreateRequestWithPayload(options, nil)
}

// CreateRequestWithPayload lets a runtime integration generate target-local
// TLS keys and return only their bounded public CSRs after ClientIdentity is
// fixed. The callback's private material remains outside this package.
func CreateRequestWithPayload(options CreateRequestOptions, build PayloadBuilder) (ClientRequest, error) {
	now := options.Now.UTC().Truncate(time.Second)
	if now.IsZero() || options.Validity <= 0 || options.Validity > MaxMessageValidity || validateRelayOrigin(options.RelayOrigin) != nil {
		return ClientRequest{}, errors.New("receiverpairing: request origin, time and validity are invalid")
	}
	advertisement, receiverPublic, err := parseAdvertisement(options.Advertisement, now)
	if err != nil {
		return ClientRequest{}, err
	}
	if advertisement.RelayOrigin != options.RelayOrigin {
		return ClientRequest{}, errors.New("receiverpairing: advertisement relay origin does not match the selected origin")
	}
	code, err := parseCode(options.Code)
	if err != nil {
		return ClientRequest{}, err
	}
	if code.ReceiverID != advertisement.ReceiverID || code.AttemptID != advertisement.AttemptID ||
		code.ExpiresUnix != advertisement.ExpiresUnix || !constantDigestEqual(code.AdvertisementSHA256, digestText(options.Advertisement)) ||
		!now.Before(time.Unix(code.ExpiresUnix, 0)) {
		return ClientRequest{}, errors.New("receiverpairing: private code does not bind this live advertisement")
	}
	clientID, err := randomID()
	if err != nil {
		return ClientRequest{}, err
	}
	nonce, err := randomID()
	if err != nil {
		return ClientRequest{}, err
	}
	pairingKey, err := signing.Generate()
	if err != nil {
		return ClientRequest{}, err
	}
	responseIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return ClientRequest{}, err
	}
	expires := now.Add(options.Validity)
	if expires.Unix() > advertisement.ExpiresUnix {
		expires = time.Unix(advertisement.ExpiresUnix, 0).UTC()
	}
	identity := ClientIdentity{
		ReceiverID: advertisement.ReceiverID, RouteID: advertisement.RouteID,
		RelayOrigin: advertisement.RelayOrigin, ClientID: clientID, CredentialGeneration: 1,
	}
	var publicPayload []byte
	if build != nil {
		publicPayload, err = build(identity)
		if err != nil {
			return ClientRequest{}, fmt.Errorf("receiverpairing: build public request payload: %w", err)
		}
	}
	if len(publicPayload) > MaxAuthorizationSize {
		return ClientRequest{}, errors.New("receiverpairing: public request payload exceeds its bound")
	}
	payload := requestPayload{
		Schema: requestSchema, Profile: Profile, ReceiverID: advertisement.ReceiverID, RouteID: advertisement.RouteID,
		RelayOrigin: advertisement.RelayOrigin, AttemptID: advertisement.AttemptID,
		AdvertisementSHA256: digestText(options.Advertisement), ClientID: clientID, Nonce: nonce,
		CreatedUnix: now.Unix(), ExpiresUnix: expires.Unix(), PairingPublicKeyPEM: string(pairingKey.PublicPEM),
		ResponseRecipient: responseIdentity.Recipient().String(), PublicPayload: base64.StdEncoding.EncodeToString(publicPayload),
		Code: string(options.Code),
	}
	signed, err := signPayload(requestEnvelopeSchema, requestDomain, payload, pairingKey.Private, MaxRequestSize)
	if err != nil {
		return ClientRequest{}, err
	}
	encrypted, err := sealAge(requestCipherSchema, signed, advertisement.ReceiverAgeRecipient, MaxRequestSize)
	if err != nil {
		return ClientRequest{}, err
	}
	material := ClientMaterial{
		receiverID: advertisement.ReceiverID, routeID: advertisement.RouteID, relayOrigin: advertisement.RelayOrigin,
		attemptID: advertisement.AttemptID, advertisementSHA: digestText(options.Advertisement), clientID: clientID,
		requestSHA: digestText(encrypted), pairingPrivate: append([]byte(nil), pairingKey.PrivatePEM...),
		responseIdentity: responseIdentity.String(), receiverPublic: append([]byte(nil), []byte(advertisement.ReceiverSigningPublic)...),
		receiverRecipient: advertisement.ReceiverAgeRecipient, request: append([]byte(nil), encrypted...),
	}
	if err := validateClientMaterial(material); err != nil {
		return ClientRequest{}, err
	}
	_ = receiverPublic
	return ClientRequest{Encrypted: encrypted, Material: material}, nil
}

func (receiver *Receiver) Claim(encoded []byte, now time.Time, issue IssueFunc) (ClaimResult, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(encoded) == 0 || len(encoded) > MaxRequestSize || issue == nil {
		return ClaimResult{}, errors.New("receiverpairing: bounded request, current time and issuer are required")
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return ClaimResult{}, err
	}
	defer root.Close()
	defer lock.Close()
	requestSHA := digestText(encoded)
	if state.LocalLocked {
		return ClaimResult{}, errors.New("receiverpairing: receiver is locally locked")
	}
	if state.Peer != nil {
		if state.Peer.Locked || state.Peer.Revoked {
			return ClaimResult{}, errors.New("receiverpairing: paired peer is locked or revoked")
		}
		if constantDigestEqual(requestSHA, state.Peer.InitialRequestSHA256) {
			response, err := decodeBase64(state.Peer.InitialResponse)
			if err != nil {
				return ClaimResult{}, err
			}
			return ClaimResult{Response: response, ReceiverID: state.ReceiverID, ClientID: state.Peer.ClientID, CredentialGeneration: state.Peer.CredentialGeneration, Idempotent: true}, nil
		}
		return ClaimResult{}, errors.New("receiverpairing: receiver is already paired to another exact request")
	}
	if state.Attempt == nil {
		return ClaimResult{}, errors.New("receiverpairing: no pending pairing attempt")
	}
	secrets, err := readSecrets(root, state, now)
	if err != nil {
		return ClaimResult{}, err
	}
	request, publicKey, code, publicPayload, err := openPairRequest(encoded, secrets.ageIdentity.String(), now)
	if err != nil {
		return ClaimResult{}, err
	}
	advertisement, err := decodeBase64(state.Attempt.Advertisement)
	if err != nil {
		return ClaimResult{}, err
	}
	if request.ReceiverID != state.ReceiverID || request.RouteID != state.RouteID || request.RelayOrigin != state.RelayOrigin ||
		request.AttemptID != state.Attempt.AttemptID || request.AdvertisementSHA256 != state.Attempt.AdvertisementSHA256 ||
		code.ReceiverID != state.ReceiverID || code.AttemptID != state.Attempt.AttemptID ||
		!constantDigestEqual(code.AdvertisementSHA256, state.Attempt.AdvertisementSHA256) ||
		!constantDigestEqual(digestText([]byte(request.Code)), state.Attempt.CodeSHA256) ||
		!constantDigestEqual(digestText(advertisement), state.Attempt.AdvertisementSHA256) ||
		request.ExpiresUnix > state.Attempt.ExpiresUnix || code.ExpiresUnix != state.Attempt.ExpiresUnix || !now.Before(time.Unix(state.Attempt.ExpiresUnix, 0)) {
		return ClaimResult{}, errors.New("receiverpairing: request does not bind the pending receiver attempt")
	}
	if state.Generation == math.MaxUint64 {
		return ClaimResult{}, errors.New("receiverpairing: state generation is exhausted")
	}
	peerRequest := PeerRequest{
		Kind: "pair", ReceiverID: state.ReceiverID, RouteID: state.RouteID, RelayOrigin: state.RelayOrigin,
		ClientID: request.ClientID, PairingPublicKeyPEM: append([]byte(nil), []byte(request.PairingPublicKeyPEM)...),
		PublicPayload: append([]byte(nil), publicPayload...), CredentialGeneration: 1, RequestSHA256: requestSHA,
	}
	authorization, err := issue(peerRequest)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("receiverpairing: issue peer authorization: %w", err)
	}
	if len(authorization) == 0 || len(authorization) > MaxAuthorizationSize {
		return ClaimResult{}, errors.New("receiverpairing: issued authorization has an invalid size")
	}
	response, err := makeResponse(responsePayload{
		Schema: responseSchema, Profile: Profile, Kind: "pair", ReceiverID: state.ReceiverID, RouteID: state.RouteID,
		RelayOrigin: state.RelayOrigin, AttemptID: state.Attempt.AttemptID, ClientID: request.ClientID,
		RequestSHA256: requestSHA, PairingPublicKeyPEM: request.PairingPublicKeyPEM, CredentialGeneration: 1,
		IssuedUnix: now.Unix(), ExpiresUnix: request.ExpiresUnix, Authorization: base64.StdEncoding.EncodeToString(authorization),
	}, request.ResponseRecipient, secrets.signingPrivate)
	if err != nil {
		return ClaimResult{}, err
	}
	state.Generation++
	state.RetiredCodeSHA256 = appendRetiredCode(state.RetiredCodeSHA256, state.Attempt.CodeSHA256)
	state.Peer = &peerRecord{
		Authorization: append([]byte(nil), authorization...),
		ClientID:      request.ClientID, PairingPublicKeyPEM: string(signingPublicBytes(publicKey)), AttemptID: state.Attempt.AttemptID,
		InitialRequestSHA256: requestSHA, InitialResponse: base64.StdEncoding.EncodeToString(response), CredentialGeneration: 1,
	}
	state.Attempt = nil
	if err := writeState(root, state); err != nil {
		return ClaimResult{}, err
	}
	return ClaimResult{Response: response, ReceiverID: state.ReceiverID, ClientID: request.ClientID, CredentialGeneration: 1}, nil
}

func OpenResponse(advertisementBytes, response []byte, material ClientMaterial, expectedOrigin string, now time.Time) (OpenResponseResult, error) {
	now = now.UTC().Truncate(time.Second)
	if err := validateClientMaterial(material); err != nil {
		return OpenResponseResult{}, err
	}
	advertisement, receiverPublic, err := parseAdvertisement(advertisementBytes, now)
	if err != nil {
		return OpenResponseResult{}, err
	}
	if expectedOrigin != material.relayOrigin || advertisement.RelayOrigin != expectedOrigin ||
		digestText(advertisementBytes) != material.advertisementSHA ||
		!bytes.Equal(material.receiverPublic, []byte(advertisement.ReceiverSigningPublic)) ||
		material.receiverRecipient != advertisement.ReceiverAgeRecipient {
		return OpenResponseResult{}, errors.New("receiverpairing: response origin or advertisement binding is invalid")
	}
	payload, authorization, err := openPairResponse(response, material.responseIdentity, receiverPublic, now)
	if err != nil {
		return OpenResponseResult{}, err
	}
	pairingKey, err := signing.ParsePrivate(material.pairingPrivate)
	if err != nil {
		return OpenResponseResult{}, err
	}
	publicPEM, _ := signingPublicPEM(pairingKey.Public().(ed25519.PublicKey))
	if payload.Kind != "pair" || payload.ReceiverID != material.receiverID || payload.RouteID != material.routeID ||
		payload.RelayOrigin != material.relayOrigin || payload.AttemptID != material.attemptID || payload.ClientID != material.clientID ||
		payload.RequestSHA256 != material.requestSHA || payload.PairingPublicKeyPEM != string(publicPEM) || payload.CredentialGeneration != 1 {
		return OpenResponseResult{}, errors.New("receiverpairing: response does not bind the exact client request")
	}
	pairing := Pairing{
		receiverID: material.receiverID, routeID: material.routeID, relayOrigin: material.relayOrigin, clientID: material.clientID,
		generation: 1, pairingPrivate: append([]byte(nil), material.pairingPrivate...), receiverPublic: append([]byte(nil), material.receiverPublic...),
		receiverRecipient: material.receiverRecipient,
	}
	return OpenResponseResult{Pairing: pairing, Authorization: authorization}, nil
}

func CreateRenewal(pairing Pairing, relayOrigin string, now time.Time, validity time.Duration) (RenewalRequest, error) {
	return CreateRenewalWithPayload(pairing, relayOrigin, now, validity, nil)
}

func CreateRenewalWithPayload(pairing Pairing, relayOrigin string, now time.Time, validity time.Duration, build PayloadBuilder) (RenewalRequest, error) {
	now = now.UTC().Truncate(time.Second)
	if err := validatePairing(pairing); err != nil || relayOrigin != pairing.relayOrigin || validity <= 0 || validity > MaxMessageValidity || now.IsZero() {
		return RenewalRequest{}, errors.New("receiverpairing: pairing, origin, time or validity is invalid")
	}
	if pairing.generation == math.MaxUint64 {
		return RenewalRequest{}, errors.New("receiverpairing: credential generation is exhausted")
	}
	nonce, err := randomID()
	if err != nil {
		return RenewalRequest{}, err
	}
	responseIdentity, err := age.GenerateX25519Identity()
	if err != nil {
		return RenewalRequest{}, err
	}
	next := pairing.generation + 1
	identity := ClientIdentity{ReceiverID: pairing.receiverID, RouteID: pairing.routeID, RelayOrigin: pairing.relayOrigin, ClientID: pairing.clientID, CredentialGeneration: next}
	var publicPayload []byte
	if build != nil {
		publicPayload, err = build(identity)
		if err != nil {
			return RenewalRequest{}, fmt.Errorf("receiverpairing: build renewal payload: %w", err)
		}
	}
	if len(publicPayload) > MaxAuthorizationSize {
		return RenewalRequest{}, errors.New("receiverpairing: renewal public payload exceeds its bound")
	}
	private, err := signing.ParsePrivate(pairing.pairingPrivate)
	if err != nil {
		return RenewalRequest{}, err
	}
	publicPEM, _ := signingPublicPEM(private.Public().(ed25519.PublicKey))
	payload := renewalPayload{
		Schema: renewalSchema, Profile: Profile, ReceiverID: pairing.receiverID, RouteID: pairing.routeID,
		RelayOrigin: pairing.relayOrigin, ClientID: pairing.clientID, Nonce: nonce, CredentialGeneration: next,
		CreatedUnix: now.Unix(), ExpiresUnix: now.Add(validity).Unix(), PairingPublicKeyPEM: string(publicPEM),
		ResponseRecipient: responseIdentity.Recipient().String(), PublicPayload: base64.StdEncoding.EncodeToString(publicPayload),
	}
	signed, err := signPayload(renewalEnvelopeSchema, renewalDomain, payload, private, MaxRequestSize)
	if err != nil {
		return RenewalRequest{}, err
	}
	encrypted, err := sealAge(renewalCipherSchema, signed, pairing.receiverRecipient, MaxRequestSize)
	if err != nil {
		return RenewalRequest{}, err
	}
	return RenewalRequest{Encrypted: encrypted, Material: RenewalMaterial{
		pairing: pairing, requestSHA: digestText(encrypted), responseIdentity: responseIdentity.String(), nextGeneration: next,
		request: append([]byte(nil), encrypted...),
	}}, nil
}

func (receiver *Receiver) Renew(encoded []byte, now time.Time, issue IssueFunc) (ClaimResult, error) {
	now = now.UTC().Truncate(time.Second)
	if now.IsZero() || len(encoded) == 0 || len(encoded) > MaxRequestSize || issue == nil {
		return ClaimResult{}, errors.New("receiverpairing: bounded renewal, current time and issuer are required")
	}
	root, lock, state, err := receiver.lockedState()
	if err != nil {
		return ClaimResult{}, err
	}
	defer root.Close()
	defer lock.Close()
	if state.LocalLocked {
		return ClaimResult{}, errors.New("receiverpairing: receiver is locally locked")
	}
	if state.Peer == nil {
		return ClaimResult{}, errors.New("receiverpairing: no paired peer")
	}
	if state.Peer.Locked || state.Peer.Revoked {
		return ClaimResult{}, errors.New("receiverpairing: paired peer is locked or revoked")
	}
	requestSHA := digestText(encoded)
	if state.Peer.LastRenewalRequestSHA256 != "" && constantDigestEqual(requestSHA, state.Peer.LastRenewalRequestSHA256) {
		response, err := decodeBase64(state.Peer.LastRenewalResponse)
		if err != nil {
			return ClaimResult{}, err
		}
		return ClaimResult{Response: response, ReceiverID: state.ReceiverID, ClientID: state.Peer.ClientID, CredentialGeneration: state.Peer.CredentialGeneration, Idempotent: true}, nil
	}
	secrets, err := readSecrets(root, state, now)
	if err != nil {
		return ClaimResult{}, err
	}
	pairingPublic, err := signing.ParsePublic([]byte(state.Peer.PairingPublicKeyPEM))
	if err != nil {
		return ClaimResult{}, err
	}
	renewal, publicPayload, err := openRenewalRequest(encoded, secrets.ageIdentity.String(), pairingPublic, now)
	if err != nil {
		return ClaimResult{}, err
	}
	if renewal.ReceiverID != state.ReceiverID || renewal.RouteID != state.RouteID || renewal.RelayOrigin != state.RelayOrigin ||
		renewal.ClientID != state.Peer.ClientID || renewal.PairingPublicKeyPEM != state.Peer.PairingPublicKeyPEM ||
		renewal.CredentialGeneration != state.Peer.CredentialGeneration+1 {
		return ClaimResult{}, errors.New("receiverpairing: renewal does not bind the paired identity or next generation")
	}
	if state.Generation == math.MaxUint64 {
		return ClaimResult{}, errors.New("receiverpairing: state generation is exhausted")
	}
	peerRequest := PeerRequest{
		Kind: "renew", ReceiverID: state.ReceiverID, RouteID: state.RouteID, RelayOrigin: state.RelayOrigin,
		ClientID: state.Peer.ClientID, PairingPublicKeyPEM: append([]byte(nil), []byte(state.Peer.PairingPublicKeyPEM)...),
		PublicPayload: append([]byte(nil), publicPayload...), CredentialGeneration: renewal.CredentialGeneration, RequestSHA256: requestSHA,
	}
	authorization, err := issue(peerRequest)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("receiverpairing: issue renewal authorization: %w", err)
	}
	if len(authorization) == 0 || len(authorization) > MaxAuthorizationSize {
		return ClaimResult{}, errors.New("receiverpairing: issued authorization has an invalid size")
	}
	response, err := makeResponse(responsePayload{
		Schema: responseSchema, Profile: Profile, Kind: "renew", ReceiverID: state.ReceiverID, RouteID: state.RouteID,
		RelayOrigin: state.RelayOrigin, ClientID: state.Peer.ClientID, RequestSHA256: requestSHA,
		PairingPublicKeyPEM: state.Peer.PairingPublicKeyPEM, CredentialGeneration: renewal.CredentialGeneration,
		IssuedUnix: now.Unix(), ExpiresUnix: renewal.ExpiresUnix, Authorization: base64.StdEncoding.EncodeToString(authorization),
	}, renewal.ResponseRecipient, secrets.signingPrivate)
	if err != nil {
		return ClaimResult{}, err
	}
	state.Generation++
	state.Peer.CredentialGeneration = renewal.CredentialGeneration
	state.Peer.Authorization = append([]byte(nil), authorization...)
	state.Peer.LastRenewalRequestSHA256 = requestSHA
	state.Peer.LastRenewalResponse = base64.StdEncoding.EncodeToString(response)
	if err := writeState(root, state); err != nil {
		return ClaimResult{}, err
	}
	return ClaimResult{Response: response, ReceiverID: state.ReceiverID, ClientID: state.Peer.ClientID, CredentialGeneration: renewal.CredentialGeneration}, nil
}

func OpenRenewalResponse(response []byte, material RenewalMaterial, expectedOrigin string, now time.Time) (OpenResponseResult, error) {
	now = now.UTC().Truncate(time.Second)
	if err := validateRenewalMaterial(material); err != nil {
		return OpenResponseResult{}, errors.New("receiverpairing: renewal material is invalid")
	}
	receiverPublic, err := signing.ParsePublic(material.pairing.receiverPublic)
	if err != nil {
		return OpenResponseResult{}, err
	}
	payload, authorization, err := openPairResponse(response, material.responseIdentity, receiverPublic, now)
	if err != nil {
		return OpenResponseResult{}, err
	}
	private, _ := signing.ParsePrivate(material.pairing.pairingPrivate)
	publicPEM, _ := signingPublicPEM(private.Public().(ed25519.PublicKey))
	if expectedOrigin != material.pairing.relayOrigin || payload.Kind != "renew" ||
		payload.ReceiverID != material.pairing.receiverID || payload.RouteID != material.pairing.routeID ||
		payload.RelayOrigin != material.pairing.relayOrigin || payload.ClientID != material.pairing.clientID ||
		payload.RequestSHA256 != material.requestSHA || payload.PairingPublicKeyPEM != string(publicPEM) ||
		payload.CredentialGeneration != material.nextGeneration {
		return OpenResponseResult{}, errors.New("receiverpairing: renewal response does not bind the exact request")
	}
	next := material.pairing
	next.generation = material.nextGeneration
	return OpenResponseResult{Pairing: next, Authorization: authorization}, nil
}

func openPairRequest(encoded []byte, receiverIdentity string, now time.Time) (requestPayload, ed25519.PublicKey, codePayload, []byte, error) {
	plaintext, err := openAge(encoded, requestCipherSchema, receiverIdentity, MaxRequestSize)
	if err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	var envelope signedEnvelope
	if err := decodeCanonical(plaintext, MaxRequestSize, &envelope); err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	payloadBytes, err := decodeBase64(envelope.Payload)
	if err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	var request requestPayload
	if err := strictjson.Decode(payloadBytes, &request); err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	public, err := signing.ParsePublic([]byte(request.PairingPublicKeyPEM))
	if err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	if err := openSigned(plaintext, requestEnvelopeSchema, requestDomain, public, MaxRequestSize, &request); err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	if request.Schema != requestSchema || request.Profile != Profile || validateID(request.ReceiverID) != nil || validateRoute(request.RouteID) != nil ||
		validateRelayOrigin(request.RelayOrigin) != nil || validateID(request.AttemptID) != nil || validateID(request.ClientID) != nil ||
		validateID(request.Nonce) != nil || !validDigest(request.AdvertisementSHA256) ||
		validateWindow(request.CreatedUnix, request.ExpiresUnix, now, MaxMessageValidity) != nil {
		return requestPayload{}, nil, codePayload{}, nil, errors.New("receiverpairing: request fields are invalid")
	}
	responseRecipient, err := age.ParseX25519Recipient(request.ResponseRecipient)
	if err != nil || responseRecipient.String() != request.ResponseRecipient {
		return requestPayload{}, nil, codePayload{}, nil, errors.New("receiverpairing: response recipient is invalid")
	}
	code, err := parseCode([]byte(request.Code))
	if err != nil {
		return requestPayload{}, nil, codePayload{}, nil, err
	}
	publicPayload, err := decodeBase64(request.PublicPayload)
	if err != nil || len(publicPayload) > MaxAuthorizationSize {
		return requestPayload{}, nil, codePayload{}, nil, errors.New("receiverpairing: public request payload is invalid")
	}
	return request, public, code, publicPayload, nil
}

func openRenewalRequest(encoded []byte, receiverIdentity string, pairingPublic ed25519.PublicKey, now time.Time) (renewalPayload, []byte, error) {
	plaintext, err := openAge(encoded, renewalCipherSchema, receiverIdentity, MaxRequestSize)
	if err != nil {
		return renewalPayload{}, nil, err
	}
	var renewal renewalPayload
	if err := openSigned(plaintext, renewalEnvelopeSchema, renewalDomain, pairingPublic, MaxRequestSize, &renewal); err != nil {
		return renewalPayload{}, nil, err
	}
	if renewal.Schema != renewalSchema || renewal.Profile != Profile || validateID(renewal.ReceiverID) != nil ||
		validateRoute(renewal.RouteID) != nil || validateRelayOrigin(renewal.RelayOrigin) != nil || validateID(renewal.ClientID) != nil ||
		validateID(renewal.Nonce) != nil || renewal.CredentialGeneration < 2 ||
		validateWindow(renewal.CreatedUnix, renewal.ExpiresUnix, now, MaxMessageValidity) != nil {
		return renewalPayload{}, nil, errors.New("receiverpairing: renewal fields are invalid")
	}
	expectedPEM, _ := signingPublicPEM(pairingPublic)
	if renewal.PairingPublicKeyPEM != string(expectedPEM) {
		return renewalPayload{}, nil, errors.New("receiverpairing: renewal pairing key changed")
	}
	responseRecipient, err := age.ParseX25519Recipient(renewal.ResponseRecipient)
	if err != nil || responseRecipient.String() != renewal.ResponseRecipient {
		return renewalPayload{}, nil, errors.New("receiverpairing: renewal response recipient is invalid")
	}
	publicPayload, err := decodeBase64(renewal.PublicPayload)
	if err != nil || len(publicPayload) > MaxAuthorizationSize {
		return renewalPayload{}, nil, errors.New("receiverpairing: renewal public payload is invalid")
	}
	return renewal, publicPayload, nil
}

func makeResponse(payload responsePayload, recipient string, private ed25519.PrivateKey) ([]byte, error) {
	signed, err := signPayload(responseEnvelopeSchema, responseDomain, payload, private, MaxResponseSize)
	if err != nil {
		return nil, err
	}
	return sealAge(responseCipherSchema, signed, recipient, MaxResponseSize)
}

func openPairResponse(encoded []byte, responseIdentity string, receiverPublic ed25519.PublicKey, now time.Time) (responsePayload, []byte, error) {
	plaintext, err := openAge(encoded, responseCipherSchema, responseIdentity, MaxResponseSize)
	if err != nil {
		return responsePayload{}, nil, err
	}
	var response responsePayload
	if err := openSigned(plaintext, responseEnvelopeSchema, responseDomain, receiverPublic, MaxResponseSize, &response); err != nil {
		return responsePayload{}, nil, err
	}
	if response.Schema != responseSchema || response.Profile != Profile || (response.Kind != "pair" && response.Kind != "renew") ||
		validateID(response.ReceiverID) != nil || validateRoute(response.RouteID) != nil || validateRelayOrigin(response.RelayOrigin) != nil ||
		validateID(response.ClientID) != nil || !validDigest(response.RequestSHA256) || response.CredentialGeneration == 0 ||
		validateWindow(response.IssuedUnix, response.ExpiresUnix, now, MaxMessageValidity) != nil {
		return responsePayload{}, nil, errors.New("receiverpairing: response fields are invalid")
	}
	if response.Kind == "pair" {
		if validateID(response.AttemptID) != nil || response.CredentialGeneration != 1 {
			return responsePayload{}, nil, errors.New("receiverpairing: initial response fields are invalid")
		}
	} else if response.AttemptID != "" || response.CredentialGeneration < 2 {
		return responsePayload{}, nil, errors.New("receiverpairing: renewal response fields are invalid")
	}
	if _, err := signing.ParsePublic([]byte(response.PairingPublicKeyPEM)); err != nil {
		return responsePayload{}, nil, err
	}
	authorization, err := decodeBase64(response.Authorization)
	if err != nil || len(authorization) == 0 || len(authorization) > MaxAuthorizationSize {
		return responsePayload{}, nil, errors.New("receiverpairing: response authorization is invalid")
	}
	return response, authorization, nil
}

func signingPublicBytes(public ed25519.PublicKey) []byte {
	encoded, _ := signingPublicPEM(public)
	return encoded
}

func validateClientMaterial(material ClientMaterial) error {
	if validateID(material.receiverID) != nil || validateRoute(material.routeID) != nil || validateRelayOrigin(material.relayOrigin) != nil ||
		validateID(material.attemptID) != nil || validateID(material.clientID) != nil || !validDigest(material.advertisementSHA) ||
		!validDigest(material.requestSHA) || digestText(material.request) != material.requestSHA {
		return errors.New("receiverpairing: client material binding is invalid")
	}
	private, err := signing.ParsePrivate(material.pairingPrivate)
	if err != nil {
		return errors.New("receiverpairing: client pairing key is invalid")
	}
	if _, err := signing.ParsePublic(material.receiverPublic); err != nil {
		return errors.New("receiverpairing: receiver public key is invalid")
	}
	identityValue, err := age.ParseX25519Identity(material.responseIdentity)
	if err != nil || identityValue.String() != material.responseIdentity {
		return errors.New("receiverpairing: client response identity is invalid")
	}
	recipient, err := age.ParseX25519Recipient(material.receiverRecipient)
	if err != nil || recipient.String() != material.receiverRecipient || len(private) != ed25519.PrivateKeySize {
		return errors.New("receiverpairing: receiver request recipient is invalid")
	}
	return nil
}

func validatePairing(pairing Pairing) error {
	if validateID(pairing.receiverID) != nil || validateRoute(pairing.routeID) != nil || validateRelayOrigin(pairing.relayOrigin) != nil ||
		validateID(pairing.clientID) != nil || pairing.generation == 0 {
		return errors.New("receiverpairing: persistent pairing binding is invalid")
	}
	private, err := signing.ParsePrivate(pairing.pairingPrivate)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return errors.New("receiverpairing: persistent pairing key is invalid")
	}
	if _, err := signing.ParsePublic(pairing.receiverPublic); err != nil {
		return errors.New("receiverpairing: persistent receiver key is invalid")
	}
	recipient, err := age.ParseX25519Recipient(pairing.receiverRecipient)
	if err != nil || recipient.String() != pairing.receiverRecipient {
		return errors.New("receiverpairing: persistent receiver recipient is invalid")
	}
	return nil
}

func validateRenewalMaterial(material RenewalMaterial) error {
	if err := validatePairing(material.pairing); err != nil || !validDigest(material.requestSHA) ||
		material.nextGeneration != material.pairing.generation+1 || digestText(material.request) != material.requestSHA {
		return errors.New("receiverpairing: renewal material binding is invalid")
	}
	identityValue, err := age.ParseX25519Identity(material.responseIdentity)
	if err != nil || identityValue.String() != material.responseIdentity {
		return errors.New("receiverpairing: renewal response identity is invalid")
	}
	return nil
}
