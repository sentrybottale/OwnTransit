//go:build darwin || linux

// Package pairruntime integrates receiver-owned pairing with the two TLS
// boundaries. Issuance runs in the receiver authority process, not the network
// worker. SSH authentication and configuration are outside this package.
package pairruntime

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strconv"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/leasewire"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/receiverpairing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/tlsprofile"
)

const credentialValidity = 24 * time.Hour
const maxCredentialBytes = 128 << 10

var ErrState = errors.New("pairruntime: invalid, unavailable or locked local state")

type Scope struct {
	ReceiverID string `json:"receiver_id"`
	RouteID    string `json:"route_id"`
	ClientID   string `json:"client_id"`
	Generation uint64 `json:"generation"`
}

func (s Scope) ids() (protocol.ID, protocol.RouteID, protocol.ID, error) {
	r, e1 := protocol.ParseID(s.ReceiverID)
	t, e2 := protocol.ParseRouteID(s.RouteID)
	c, e3 := protocol.ParseID(s.ClientID)
	if e1 != nil || e2 != nil || e3 != nil || r == (protocol.ID{}) || c == (protocol.ID{}) || t == (protocol.RouteID{}) || r == c || s.Generation == 0 {
		return r, t, c, ErrState
	}
	return r, t, c, nil
}

func receiverName(receiver, route string) string {
	return "i-" + receiver + ".r-" + route + ".receiver.paired.owntransit.invalid"
}
func clientName(s Scope) string {
	return "i-" + s.ClientID + ".r-" + s.RouteID + ".g-" + strconv.FormatUint(s.Generation, 10) + ".client.paired.owntransit.invalid"
}

// LeafKeys must be explicitly serialized only into a protected local record.
type LeafKeys struct {
	Outer []byte `json:"outer"`
	Inner []byte `json:"inner"`
}

func (LeafKeys) String() string   { return "pairruntime.LeafKeys[REDACTED]" }
func (LeafKeys) GoString() string { return "pairruntime.LeafKeys[REDACTED]" }

type CredentialRequest struct {
	Schema   string `json:"schema"`
	Scope    Scope  `json:"scope"`
	OuterCSR []byte `json:"outer_csr"`
	InnerCSR []byte `json:"inner_csr"`
}
type Authorization struct {
	Schema   string `json:"schema"`
	Scope    Scope  `json:"scope"`
	Outer    []byte `json:"outer_certificate"`
	Inner    []byte `json:"inner_certificate"`
	Receiver []byte `json:"receiver_certificate"`
}
type ReceiverLeaves struct {
	Outer []byte   `json:"outer_certificate"`
	Inner []byte   `json:"inner_certificate"`
	Keys  LeafKeys `json:"keys"`
}

func (ReceiverLeaves) String() string   { return "pairruntime.ReceiverLeaves[REDACTED]" }
func (ReceiverLeaves) GoString() string { return "pairruntime.ReceiverLeaves[REDACTED]" }

func GenerateReceiverLeaves(status receiverpairing.ReceiverStatus, authority receiverpairing.AuthorityMaterial, now time.Time) (ReceiverLeaves, error) {
	r, e1 := protocol.ParseID(status.ReceiverID)
	t, e2 := protocol.ParseRouteID(status.RouteID)
	if e1 != nil || e2 != nil {
		return ReceiverLeaves{}, ErrState
	}
	outerName, err := pairrelay.PeerDNSName(pairrelay.RoleReceiver, r, r, t)
	if err != nil {
		return ReceiverLeaves{}, err
	}
	o, err := pki.IssueLeaf(authority.OuterEndpoint, outerName, x509.ExtKeyUsageClientAuth, now, credentialValidity)
	if err != nil {
		return ReceiverLeaves{}, err
	}
	i, err := pki.IssueLeaf(authority.InnerConnector, receiverName(status.ReceiverID, status.RouteID), x509.ExtKeyUsageServerAuth, now, credentialValidity)
	if err != nil {
		return ReceiverLeaves{}, err
	}
	return ReceiverLeaves{Outer: o.CertPEM, Inner: i.CertPEM, Keys: LeafKeys{Outer: o.KeyPEM, Inner: i.KeyPEM}}, nil
}

// RefreshReceiverLeaves renews certificates without changing the receiver's
// pinned operational keys. A sleeping client can reconnect with the same pin;
// no relay response or silent identity replacement participates.
func RefreshReceiverLeaves(old ReceiverLeaves, status receiverpairing.ReceiverStatus, authority receiverpairing.AuthorityMaterial, now time.Time) (ReceiverLeaves, error) {
	r, e := protocol.ParseID(status.ReceiverID)
	if e != nil {
		return ReceiverLeaves{}, e
	}
	route, e := protocol.ParseRouteID(status.RouteID)
	if e != nil {
		return ReceiverLeaves{}, e
	}
	outerName, e := pairrelay.PeerDNSName(pairrelay.RoleReceiver, r, r, route)
	if e != nil {
		return ReceiverLeaves{}, e
	}
	reissue := func(cert, key []byte, name string, issuer pki.Material, usage x509.ExtKeyUsage) ([]byte, error) {
		pair, e := identity.ParseKeyPair(cert, key)
		if e != nil {
			return nil, e
		}
		signer, ok := pair.PrivateKey.(crypto.Signer)
		if !ok {
			return nil, ErrState
		}
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, signer)
		if e != nil {
			return nil, e
		}
		req, e := x509.ParseCertificateRequest(der)
		if e != nil {
			return nil, e
		}
		leaf, e := pki.IssueCSR(issuer, req, name, usage, now, credentialValidity)
		return leaf.CertPEM, e
	}
	o, e := reissue(old.Outer, old.Keys.Outer, outerName, authority.OuterEndpoint, x509.ExtKeyUsageClientAuth)
	if e != nil {
		return ReceiverLeaves{}, e
	}
	i, e := reissue(old.Inner, old.Keys.Inner, receiverName(status.ReceiverID, status.RouteID), authority.InnerConnector, x509.ExtKeyUsageServerAuth)
	if e != nil {
		return ReceiverLeaves{}, e
	}
	return ReceiverLeaves{Outer: o, Inner: i, Keys: old.Keys}, nil
}

func NewCredentialRequest(value receiverpairing.ClientIdentity) ([]byte, LeafKeys, error) {
	s := Scope{value.ReceiverID, value.RouteID, value.ClientID, value.CredentialGeneration}
	r, t, c, err := s.ids()
	if err != nil {
		return nil, LeafKeys{}, err
	}
	n, err := pairrelay.PeerDNSName(pairrelay.RoleClient, c, r, t)
	if err != nil {
		return nil, LeafKeys{}, err
	}
	o, err := pki.NewCSR(n)
	if err != nil {
		return nil, LeafKeys{}, err
	}
	i, err := pki.NewCSR(clientName(s))
	if err != nil {
		return nil, LeafKeys{}, err
	}
	data, err := json.Marshal(CredentialRequest{"owntransit.paired-csr.v1", s, o.CSRPEM, i.CSRPEM})
	return data, LeafKeys{Outer: o.KeyPEM, Inner: i.KeyPEM}, err
}

// IssueCredentials is pure issuance: the caller commits its public result in
// the same transaction that spends the code or advances renewal generation.
func IssueCredentials(peer receiverpairing.PeerRequest, authority receiverpairing.AuthorityMaterial, leaves ReceiverLeaves, now time.Time) ([]byte, error) {
	s := Scope{peer.ReceiverID, peer.RouteID, peer.ClientID, peer.CredentialGeneration}
	r, t, c, err := s.ids()
	if err != nil || (peer.Kind != "pair" && peer.Kind != "renew") || len(peer.PublicPayload) > maxCredentialBytes {
		return nil, ErrState
	}
	var req CredentialRequest
	if strictjson.Decode(peer.PublicPayload, &req) != nil || req.Schema != "owntransit.paired-csr.v1" || req.Scope != s {
		return nil, ErrState
	}
	n, err := pairrelay.PeerDNSName(pairrelay.RoleClient, c, r, t)
	if err != nil {
		return nil, err
	}
	o, err := pki.ParseCSR(req.OuterCSR, n)
	if err != nil {
		return nil, ErrState
	}
	i, err := pki.ParseCSR(req.InnerCSR, clientName(s))
	if err != nil || bytes.Equal(o.RawSubjectPublicKeyInfo, i.RawSubjectPublicKeyInfo) {
		return nil, ErrState
	}
	outer, err := pki.IssueCSR(authority.OuterEndpoint, o, n, x509.ExtKeyUsageClientAuth, now, credentialValidity)
	if err != nil {
		return nil, err
	}
	inner, err := pki.IssueCSR(authority.InnerClient, i, clientName(s), x509.ExtKeyUsageClientAuth, now, credentialValidity)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Authorization{"owntransit.paired-authorization.v1", s, outer.CertPEM, inner.CertPEM, leaves.Inner})
}

func ParseAuthorization(encoded []byte, scope Scope) (Authorization, error) {
	var a Authorization
	if _, _, _, err := scope.ids(); err != nil || len(encoded) == 0 || len(encoded) > maxCredentialBytes {
		return a, ErrState
	}
	if strictjson.Decode(encoded, &a) != nil || a.Schema != "owntransit.paired-authorization.v1" || a.Scope != scope {
		return Authorization{}, ErrState
	}
	return a, nil
}

func leaf(encoded []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(encoded)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrState
	}
	return x509.ParseCertificate(b.Bytes)
}

func materialReader(values map[string][]byte) tlsprofile.MaterialReader {
	return func(name string) ([]byte, error) {
		if v, ok := values[name]; ok {
			return append([]byte(nil), v...), nil
		}
		return nil, ErrState
	}
}

func ClientTLS(a Authorization, keys LeafKeys, trust receiverpairing.Trust) (*tls.Config, error) {
	if _, _, _, err := a.Scope.ids(); err != nil {
		return nil, err
	}
	r, err := leaf(a.Receiver)
	if err != nil {
		return nil, err
	}
	pin, err := identity.SPKIPin(r)
	if err != nil {
		return nil, err
	}
	name := clientName(a.Scope)
	return tlsprofile.ClientFromMaterial(config.ClientTLS{CertFile: "cert", KeyFile: "key", CAFile: "peer-ca", IssuerCAFile: "issuer", LocalDNSName: name, ServerName: receiverName(a.Scope.ReceiverID, a.Scope.RouteID), SPKIPins: []string{pin}}, name, leasewire.ALPN, materialReader(map[string][]byte{"cert": a.Inner, "key": keys.Inner, "peer-ca": []byte(trust.InnerConnectorCAPEM), "issuer": []byte(trust.InnerClientCAPEM)}))
}

func ReceiverTLS(a Authorization, leaves ReceiverLeaves, trust receiverpairing.Trust) (*tls.Config, error) {
	if _, _, _, err := a.Scope.ids(); err != nil {
		return nil, err
	}
	c, err := leaf(a.Inner)
	if err != nil {
		return nil, err
	}
	pin, err := identity.HashSPKI(c)
	if err != nil {
		return nil, err
	}
	name := receiverName(a.Scope.ReceiverID, a.Scope.RouteID)
	return tlsprofile.ServerFromMaterial(config.ServerTLS{CertFile: "cert", KeyFile: "key", ClientCAFile: "peer-ca", IssuerCAFile: "issuer", LocalDNSName: name}, name, leasewire.ALPN, map[string]identity.PinSet{clientName(a.Scope): {pin: {}}}, materialReader(map[string][]byte{"cert": leaves.Inner, "key": leaves.Keys.Inner, "peer-ca": []byte(trust.InnerClientCAPEM), "issuer": []byte(trust.InnerConnectorCAPEM)}))
}
