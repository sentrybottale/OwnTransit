//go:build darwin || linux

// Package pairrelaycmd provides the local, root-owned operational boundary for
// receiver-owned relay mode. It never stores endpoint issuer material.
package pairrelaycmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	registrationPrefix  = "otrelay1."
	MaxRegistrationCode = 32 << 10
)

type registrationWire struct {
	Schema          string `json:"schema"`
	ReceiverID      string `json:"receiver_id"`
	RouteID         string `json:"route_id"`
	Token           string `json:"token"`
	RelayServerName string `json:"relay_server_name"`
	RelayCAPEM      string `json:"relay_ca_pem"`
	RelayServerSPKI string `json:"relay_server_spki_sha256"`
}

// EncodeRegistration returns one canonical copy-safe relay code. It contains
// relay-visible routing/admission material and public relay trust only—never an
// endpoint private key, pairing secret, or endpoint issuer key.
func EncodeRegistration(value pairrelay.Registration) (string, error) {
	if zeroID(value.ReceiverID) || zeroRoute(value.RouteID) || len(value.Token) == 0 || len(value.Token) > pairrelay.MaxTokenBytes ||
		!validServerInfo(value.ServerInfo) {
		return "", errors.New("pairrelaycmd: invalid registration")
	}
	wire := registrationWire{
		Schema: "owntransit.pairrelay.registration.v1", ReceiverID: value.ReceiverID.String(), RouteID: value.RouteID.String(),
		Token: base64.RawURLEncoding.EncodeToString(value.Token), RelayServerName: value.ServerInfo.ServerName,
		RelayCAPEM: base64.RawURLEncoding.EncodeToString(value.ServerInfo.CAPEM), RelayServerSPKI: value.ServerInfo.LeafSPKISHA256,
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return "", err
	}
	result := registrationPrefix + base64.RawURLEncoding.EncodeToString(payload)
	if len(result) > MaxRegistrationCode {
		return "", errors.New("pairrelaycmd: registration code exceeds its bound")
	}
	return result, nil
}

// DecodeRegistration strictly parses the sole canonical relay-code encoding.
func DecodeRegistration(encoded string) (pairrelay.Registration, error) {
	if len(encoded) <= len(registrationPrefix) || len(encoded) > MaxRegistrationCode ||
		!strings.HasPrefix(encoded, registrationPrefix) || strings.TrimSpace(encoded) != encoded {
		return pairrelay.Registration{}, errors.New("pairrelaycmd: invalid registration code")
	}
	payloadText := strings.TrimPrefix(encoded, registrationPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(payloadText)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != payloadText {
		return pairrelay.Registration{}, errors.New("pairrelaycmd: invalid registration encoding")
	}
	var wire registrationWire
	if err := strictjson.Decode(payload, &wire); err != nil || wire.Schema != "owntransit.pairrelay.registration.v1" {
		return pairrelay.Registration{}, errors.New("pairrelaycmd: invalid registration payload")
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) {
		return pairrelay.Registration{}, errors.New("pairrelaycmd: noncanonical registration payload")
	}
	receiverID, receiverErr := protocol.ParseID(wire.ReceiverID)
	routeID, routeErr := protocol.ParseRouteID(wire.RouteID)
	token, tokenErr := decodeRawURL(wire.Token, pairrelay.MaxTokenBytes)
	ca, caErr := decodeRawURL(wire.RelayCAPEM, pairrelay.MaxAdmissionCABytes)
	info := pairrelay.ServerInfo{ServerName: wire.RelayServerName, CAPEM: ca, LeafSPKISHA256: wire.RelayServerSPKI}
	if receiverErr != nil || routeErr != nil || tokenErr != nil || caErr != nil || zeroID(receiverID) || zeroRoute(routeID) ||
		!validServerInfo(info) {
		return pairrelay.Registration{}, errors.New("pairrelaycmd: invalid registration fields")
	}
	return pairrelay.Registration{ReceiverID: receiverID, RouteID: routeID, Token: token, ServerInfo: info}, nil
}

func decodeRawURL(value string, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("pairrelaycmd: invalid base64url field")
	}
	return decoded, nil
}

func validServerInfo(info pairrelay.ServerInfo) bool {
	if !validDNSName(info.ServerName) || len(info.CAPEM) == 0 ||
		len(info.CAPEM) > pairrelay.MaxAdmissionCABytes {
		return false
	}
	block, rest := pem.Decode(info.CAPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 ||
		!bytes.Equal(pem.EncodeToMemory(block), info.CAPEM) {
		return false
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || !certificate.MaxPathLenZero ||
		certificate.MaxPathLen != 0 || certificate.KeyUsage&x509.KeyUsageCertSign == 0 ||
		certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.CheckSignatureFrom(certificate) != nil {
		return false
	}
	if _, ok := certificate.PublicKey.(ed25519.PublicKey); !ok {
		return false
	}
	_, err = identity.ParseSPKIPin(info.LeafSPKISHA256)
	return err == nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func zeroID(value protocol.ID) bool { return value == (protocol.ID{}) }

func zeroRoute(value protocol.RouteID) bool { return value == (protocol.RouteID{}) }
