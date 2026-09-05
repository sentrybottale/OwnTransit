//go:build darwin || linux

package receiverpairing

import (
	"encoding/base64"
	"errors"
)

const (
	clientMaterialSchema  = "owntransit.receiver-pairing.client-material.v1"
	pairingPrivateSchema  = "owntransit.receiver-pairing.client-identity.v1"
	renewalMaterialSchema = "owntransit.receiver-pairing.renewal-material.v1"
	maxPrivateStateSize   = 2 << 20
)

type encodedClientMaterial struct {
	Schema               string `json:"schema"`
	Profile              string `json:"profile"`
	ReceiverID           string `json:"receiver_id"`
	RouteID              string `json:"route_id"`
	RelayOrigin          string `json:"relay_origin"`
	AttemptID            string `json:"attempt_id"`
	AdvertisementSHA256  string `json:"advertisement_sha256"`
	ClientID             string `json:"client_id"`
	RequestSHA256        string `json:"request_sha256"`
	Request              string `json:"encrypted_request"`
	PairingPrivateKeyPEM string `json:"pairing_private_key_pem"`
	ResponseAgeIdentity  string `json:"response_age_identity"`
	ReceiverPublicKeyPEM string `json:"receiver_public_key_pem"`
	ReceiverAgeRecipient string `json:"receiver_age_recipient"`
}

type encodedPairing struct {
	Schema               string `json:"schema"`
	Profile              string `json:"profile"`
	ReceiverID           string `json:"receiver_id"`
	RouteID              string `json:"route_id"`
	RelayOrigin          string `json:"relay_origin"`
	ClientID             string `json:"client_id"`
	CredentialGeneration uint64 `json:"credential_generation"`
	PairingPrivateKeyPEM string `json:"pairing_private_key_pem"`
	ReceiverPublicKeyPEM string `json:"receiver_public_key_pem"`
	ReceiverAgeRecipient string `json:"receiver_age_recipient"`
}

type encodedRenewalMaterial struct {
	Schema              string `json:"schema"`
	Profile             string `json:"profile"`
	Pairing             string `json:"pairing"`
	RequestSHA256       string `json:"request_sha256"`
	Request             string `json:"encrypted_request"`
	ResponseAgeIdentity string `json:"response_age_identity"`
	NextGeneration      uint64 `json:"next_generation"`
}

// MarshalPrivate is an explicit secret-bearing operation. ClientMaterial has
// no exported secret fields and does not implement Stringer or json.Marshaler.
func (material ClientMaterial) MarshalPrivate() ([]byte, error) {
	if err := validateClientMaterial(material); err != nil {
		return nil, err
	}
	return encodeCanonical(encodedClientMaterial{
		Schema: clientMaterialSchema, Profile: Profile, ReceiverID: material.receiverID, RouteID: material.routeID,
		RelayOrigin: material.relayOrigin, AttemptID: material.attemptID, AdvertisementSHA256: material.advertisementSHA,
		ClientID: material.clientID, RequestSHA256: material.requestSHA,
		Request: base64.StdEncoding.EncodeToString(material.request), PairingPrivateKeyPEM: base64.StdEncoding.EncodeToString(material.pairingPrivate),
		ResponseAgeIdentity: material.responseIdentity, ReceiverPublicKeyPEM: base64.StdEncoding.EncodeToString(material.receiverPublic),
		ReceiverAgeRecipient: material.receiverRecipient,
	}, maxPrivateStateSize)
}

func ParseClientMaterial(encoded []byte) (ClientMaterial, error) {
	var value encodedClientMaterial
	if err := decodeCanonical(encoded, maxPrivateStateSize, &value); err != nil {
		return ClientMaterial{}, err
	}
	if value.Schema != clientMaterialSchema || value.Profile != Profile {
		return ClientMaterial{}, errors.New("receiverpairing: client material schema is unsupported")
	}
	request, err := decodeBase64(value.Request)
	if err != nil {
		return ClientMaterial{}, err
	}
	private, err := decodeBase64(value.PairingPrivateKeyPEM)
	if err != nil {
		return ClientMaterial{}, err
	}
	receiverPublic, err := decodeBase64(value.ReceiverPublicKeyPEM)
	if err != nil {
		return ClientMaterial{}, err
	}
	material := ClientMaterial{
		receiverID: value.ReceiverID, routeID: value.RouteID, relayOrigin: value.RelayOrigin, attemptID: value.AttemptID,
		advertisementSHA: value.AdvertisementSHA256, clientID: value.ClientID, requestSHA: value.RequestSHA256,
		request: request, pairingPrivate: private, responseIdentity: value.ResponseAgeIdentity,
		receiverPublic: receiverPublic, receiverRecipient: value.ReceiverAgeRecipient,
	}
	if err := validateClientMaterial(material); err != nil {
		return ClientMaterial{}, err
	}
	return material, nil
}

// MarshalPrivate explicitly exports the long-term client pairing key for a
// caller-controlled private durable store.
func (pairing Pairing) MarshalPrivate() ([]byte, error) {
	if err := validatePairing(pairing); err != nil {
		return nil, err
	}
	return encodeCanonical(encodedPairing{
		Schema: pairingPrivateSchema, Profile: Profile, ReceiverID: pairing.receiverID, RouteID: pairing.routeID,
		RelayOrigin: pairing.relayOrigin, ClientID: pairing.clientID, CredentialGeneration: pairing.generation,
		PairingPrivateKeyPEM: base64.StdEncoding.EncodeToString(pairing.pairingPrivate),
		ReceiverPublicKeyPEM: base64.StdEncoding.EncodeToString(pairing.receiverPublic), ReceiverAgeRecipient: pairing.receiverRecipient,
	}, maxPrivateStateSize)
}

func ParsePairing(encoded []byte) (Pairing, error) {
	var value encodedPairing
	if err := decodeCanonical(encoded, maxPrivateStateSize, &value); err != nil {
		return Pairing{}, err
	}
	if value.Schema != pairingPrivateSchema || value.Profile != Profile {
		return Pairing{}, errors.New("receiverpairing: pairing schema is unsupported")
	}
	private, err := decodeBase64(value.PairingPrivateKeyPEM)
	if err != nil {
		return Pairing{}, err
	}
	receiverPublic, err := decodeBase64(value.ReceiverPublicKeyPEM)
	if err != nil {
		return Pairing{}, err
	}
	pairing := Pairing{
		receiverID: value.ReceiverID, routeID: value.RouteID, relayOrigin: value.RelayOrigin, clientID: value.ClientID,
		generation: value.CredentialGeneration, pairingPrivate: private, receiverPublic: receiverPublic,
		receiverRecipient: value.ReceiverAgeRecipient,
	}
	if err := validatePairing(pairing); err != nil {
		return Pairing{}, err
	}
	return pairing, nil
}

func (material RenewalMaterial) MarshalPrivate() ([]byte, error) {
	if err := validateRenewalMaterial(material); err != nil {
		return nil, err
	}
	pairing, err := material.pairing.MarshalPrivate()
	if err != nil {
		return nil, err
	}
	return encodeCanonical(encodedRenewalMaterial{
		Schema: renewalMaterialSchema, Profile: Profile, Pairing: base64.StdEncoding.EncodeToString(pairing),
		RequestSHA256: material.requestSHA, Request: base64.StdEncoding.EncodeToString(material.request),
		ResponseAgeIdentity: material.responseIdentity, NextGeneration: material.nextGeneration,
	}, maxPrivateStateSize)
}

func ParseRenewalMaterial(encoded []byte) (RenewalMaterial, error) {
	var value encodedRenewalMaterial
	if err := decodeCanonical(encoded, maxPrivateStateSize, &value); err != nil {
		return RenewalMaterial{}, err
	}
	if value.Schema != renewalMaterialSchema || value.Profile != Profile {
		return RenewalMaterial{}, errors.New("receiverpairing: renewal material schema is unsupported")
	}
	pairingBytes, err := decodeBase64(value.Pairing)
	if err != nil {
		return RenewalMaterial{}, err
	}
	pairing, err := ParsePairing(pairingBytes)
	if err != nil {
		return RenewalMaterial{}, err
	}
	request, err := decodeBase64(value.Request)
	if err != nil {
		return RenewalMaterial{}, err
	}
	material := RenewalMaterial{
		pairing: pairing, requestSHA: value.RequestSHA256, request: request,
		responseIdentity: value.ResponseAgeIdentity, nextGeneration: value.NextGeneration,
	}
	if err := validateRenewalMaterial(material); err != nil {
		return RenewalMaterial{}, err
	}
	return material, nil
}
