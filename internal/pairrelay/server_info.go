package pairrelay

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const maxServerInfoBytes = MaxAdmissionCABytes + 4096

type serverInfoWire struct {
	Schema         string `json:"schema"`
	ServerName     string `json:"server_name"`
	CAPEM          string `json:"ca_pem"`
	LeafSPKISHA256 string `json:"leaf_spki_sha256"`
}

func serverInfoFromMaterial(material TLSMaterial) (ServerInfo, error) {
	if len(material.Certificate.Certificate) == 0 {
		return ServerInfo{}, ErrProtocol
	}
	leaf := material.Certificate.Leaf
	var err error
	if leaf == nil {
		leaf, err = x509.ParseCertificate(material.Certificate.Certificate[0])
	}
	if err != nil || leaf == nil {
		return ServerInfo{}, ErrProtocol
	}
	pin, err := identity.SPKIPin(leaf)
	if err != nil {
		return ServerInfo{}, ErrProtocol
	}
	return ServerInfo{ServerName: material.ServerName, CAPEM: append([]byte(nil), material.CAPEM...), LeafSPKISHA256: pin}, nil
}

func encodeServerInfo(value ServerInfo) ([]byte, error) {
	if !validDNSName(value.ServerName) || len(value.CAPEM) == 0 || len(value.CAPEM) > MaxAdmissionCABytes ||
		identityPinInvalid(value.LeafSPKISHA256) {
		return nil, ErrProtocol
	}
	encoded, err := json.Marshal(serverInfoWire{
		Schema: "owntransit.pairrelay.server-info.v2", ServerName: value.ServerName,
		CAPEM: base64.StdEncoding.EncodeToString(value.CAPEM), LeafSPKISHA256: value.LeafSPKISHA256,
	})
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxServerInfoBytes {
		return nil, ErrProtocol
	}
	return encoded, nil
}

func decodeServerInfo(encoded []byte) (ServerInfo, error) {
	if len(encoded) == 0 || len(encoded) > maxServerInfoBytes {
		return ServerInfo{}, ErrProtocol
	}
	var wire serverInfoWire
	if err := strictjson.Decode(encoded, &wire); err != nil || wire.Schema != "owntransit.pairrelay.server-info.v2" {
		return ServerInfo{}, ErrProtocol
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(append(canonical, '\n'), encoded) {
		return ServerInfo{}, ErrProtocol
	}
	ca, err := base64.StdEncoding.DecodeString(wire.CAPEM)
	if err != nil || base64.StdEncoding.EncodeToString(ca) != wire.CAPEM || !validDNSName(wire.ServerName) ||
		identityPinInvalid(wire.LeafSPKISHA256) {
		return ServerInfo{}, ErrProtocol
	}
	return ServerInfo{ServerName: wire.ServerName, CAPEM: ca, LeafSPKISHA256: wire.LeafSPKISHA256}, nil
}

func identityPinInvalid(value string) bool {
	_, err := identity.ParseSPKIPin(value)
	return err != nil
}
