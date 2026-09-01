package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"net"
	"testing"
)

const (
	testPeerName   = "peer.owntransit.invalid"
	testServerName = "route.owntransit.invalid"
	testALPN       = "owntransit-test/1"
)

func TestPeerProfileVerifyConnectionAcceptsStrictProfile(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, testPeerName, x509.ExtKeyUsageClientAuth, nil)
	profile, state := validPeerProfileAndState(t, authority.cert, credential.cert)

	if err := profile.VerifyConnection(state); err != nil {
		t.Fatalf("VerifyConnection rejected valid state: %v", err)
	}

	var callback func(tls.ConnectionState) error = profile.VerifyConnection
	if err := callback(state); err != nil {
		t.Fatalf("method is not usable as tls.Config.VerifyConnection: %v", err)
	}
}

func TestPeerProfileVerifyConnectionRejectsTLSAndChainViolations(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, testPeerName, x509.ExtKeyUsageClientAuth, nil)
	profile, valid := validPeerProfileAndState(t, authority.cert, credential.cert)

	tests := []struct {
		name   string
		mutate func(*PeerProfile, *tls.ConnectionState)
	}{
		{"TLS 1.2", func(_ *PeerProfile, state *tls.ConnectionState) { state.Version = tls.VersionTLS12 }},
		{"resumption", func(_ *PeerProfile, state *tls.ConnectionState) { state.DidResume = true }},
		{"missing ALPN", func(_ *PeerProfile, state *tls.ConnectionState) { state.NegotiatedProtocol = "" }},
		{"wrong ALPN", func(_ *PeerProfile, state *tls.ConnectionState) { state.NegotiatedProtocol = "other/1" }},
		{"missing SNI", func(_ *PeerProfile, state *tls.ConnectionState) { state.ServerName = "" }},
		{"wrong SNI", func(_ *PeerProfile, state *tls.ConnectionState) { state.ServerName = "other.owntransit.invalid" }},
		{"missing peer", func(_ *PeerProfile, state *tls.ConnectionState) { state.PeerCertificates = nil }},
		{"nil peer", func(_ *PeerProfile, state *tls.ConnectionState) { state.PeerCertificates = []*x509.Certificate{nil} }},
		{"missing verified chain", func(_ *PeerProfile, state *tls.ConnectionState) { state.VerifiedChains = nil }},
		{"empty verified chain", func(_ *PeerProfile, state *tls.ConnectionState) { state.VerifiedChains = [][]*x509.Certificate{{}} }},
		{"nil verified leaf", func(_ *PeerProfile, state *tls.ConnectionState) { state.VerifiedChains = [][]*x509.Certificate{{nil}} }},
		{"different verified leaf", func(_ *PeerProfile, state *tls.ConnectionState) {
			other := cloneCertificate(state.PeerCertificates[0])
			other.Raw = []byte("different")
			state.VerifiedChains = [][]*x509.Certificate{{other, authority.cert}}
		}},
		{"missing leaf DER", func(_ *PeerProfile, state *tls.ConnectionState) {
			leaf := installLeafClone(state)
			leaf.Raw = nil
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateProfile := profile
			candidateState := cloneConnectionState(valid)
			test.mutate(&candidateProfile, &candidateState)
			if err := candidateProfile.VerifyConnection(candidateState); err == nil {
				t.Fatal("VerifyConnection accepted forbidden TLS state")
			}
		})
	}
}

func TestPeerProfileVerifyConnectionRejectsCertificateProfileViolations(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, testPeerName, x509.ExtKeyUsageClientAuth, nil)
	profile, valid := validPeerProfileAndState(t, authority.cert, credential.cert)

	tests := []struct {
		name   string
		mutate func(*PeerProfile, *tls.ConnectionState)
	}{
		{"invalid basic constraints", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).BasicConstraintsValid = false
		}},
		{"CA leaf", func(_ *PeerProfile, state *tls.ConnectionState) { installLeafClone(state).IsCA = true }},
		{"missing key usage", func(_ *PeerProfile, state *tls.ConnectionState) { installLeafClone(state).KeyUsage = 0 }},
		{"extra key usage", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}},
		{"missing EKU", func(_ *PeerProfile, state *tls.ConnectionState) { installLeafClone(state).ExtKeyUsage = nil }},
		{"wrong EKU", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}},
		{"dual EKU", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		}},
		{"any EKU", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}},
		{"unknown EKU", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
		}},
		{"missing SAN", func(_ *PeerProfile, state *tls.ConnectionState) { installLeafClone(state).DNSNames = nil }},
		{"wrong SAN", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).DNSNames = []string{"other.owntransit.invalid"}
		}},
		{"multiple SANs", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).DNSNames = []string{testPeerName, "other.owntransit.invalid"}
		}},
		{"IP SAN", func(_ *PeerProfile, state *tls.ConnectionState) {
			installLeafClone(state).IPAddresses = []net.IP{net.ParseIP("192.0.2.1")}
		}},
		{"unrecognized raw SAN profile", func(_ *PeerProfile, state *tls.ConnectionState) {
			leaf := installLeafClone(state)
			for i := range leaf.Extensions {
				if leaf.Extensions[i].Id.Equal(oidSubjectAlternativeName) {
					value, err := asn1.Marshal([]asn1.RawValue{{
						Class: asn1.ClassContextSpecific,
						Tag:   8,
						Bytes: []byte{42, 3},
					}})
					if err != nil {
						t.Fatalf("marshal test SAN: %v", err)
					}
					leaf.Extensions[i].Value = value
				}
			}
		}},
		{"unauthorized SPKI", func(profile *PeerProfile, _ *tls.ConnectionState) {
			profile.AllowedSPKIs = PinSet{{1}: {}}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateProfile := profile
			candidateState := cloneConnectionState(valid)
			test.mutate(&candidateProfile, &candidateState)
			if err := candidateProfile.VerifyConnection(candidateState); err == nil {
				t.Fatal("VerifyConnection accepted a forbidden certificate profile")
			}
		})
	}
}

func TestPeerProfileVerifyConnectionRejectsInvalidPolicy(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, testPeerName, x509.ExtKeyUsageClientAuth, nil)
	profile, state := validPeerProfileAndState(t, authority.cert, credential.cert)

	tests := []struct {
		name   string
		mutate func(*PeerProfile)
	}{
		{"empty peer name", func(profile *PeerProfile) { profile.ExpectedDNSName = "" }},
		{"non-canonical peer name", func(profile *PeerProfile) { profile.ExpectedDNSName = "Peer.owntransit.invalid" }},
		{"trailing-dot peer name", func(profile *PeerProfile) { profile.ExpectedDNSName = testPeerName + "." }},
		{"non-canonical SNI", func(profile *PeerProfile) { profile.ExpectedServerName = "Route.owntransit.invalid" }},
		{"unsupported required EKU", func(profile *PeerProfile) { profile.RequiredEKU = x509.ExtKeyUsageAny }},
		{"empty ALPN", func(profile *PeerProfile) { profile.ALPN = "" }},
		{"empty pin allowlist", func(profile *PeerProfile) { profile.AllowedSPKIs = nil }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := profile
			test.mutate(&candidate)
			if err := candidate.VerifyConnection(state); err == nil {
				t.Fatal("VerifyConnection accepted invalid policy")
			}
		})
	}
}

func TestPeerProfileServerNameCheckIsOptional(t *testing.T) {
	authority := newTestAuthority(t)
	credential := newTestCredential(t, authority, testPeerName, x509.ExtKeyUsageClientAuth, nil)
	profile, state := validPeerProfileAndState(t, authority.cert, credential.cert)
	profile.ExpectedServerName = ""
	state.ServerName = ""

	if err := profile.VerifyConnection(state); err != nil {
		t.Fatalf("VerifyConnection required optional SNI: %v", err)
	}
}

func validPeerProfileAndState(t *testing.T, authority, leaf *x509.Certificate) (PeerProfile, tls.ConnectionState) {
	t.Helper()
	hash, err := HashSPKI(leaf)
	if err != nil {
		t.Fatal(err)
	}
	profile := PeerProfile{
		ExpectedDNSName:    testPeerName,
		ExpectedServerName: testServerName,
		RequiredEKU:        x509.ExtKeyUsageClientAuth,
		ALPN:               testALPN,
		AllowedSPKIs:       PinSet{hash: {}},
	}
	state := tls.ConnectionState{
		Version:            tls.VersionTLS13,
		DidResume:          false,
		NegotiatedProtocol: testALPN,
		ServerName:         testServerName,
		PeerCertificates:   []*x509.Certificate{leaf, authority},
		VerifiedChains:     [][]*x509.Certificate{{leaf, authority}},
	}
	return profile, state
}

func cloneConnectionState(state tls.ConnectionState) tls.ConnectionState {
	clone := state
	clone.PeerCertificates = append([]*x509.Certificate(nil), state.PeerCertificates...)
	clone.VerifiedChains = make([][]*x509.Certificate, len(state.VerifiedChains))
	for i, chain := range state.VerifiedChains {
		clone.VerifiedChains[i] = append([]*x509.Certificate(nil), chain...)
	}
	return clone
}

func installLeafClone(state *tls.ConnectionState) *x509.Certificate {
	leaf := cloneCertificate(state.PeerCertificates[0])
	state.PeerCertificates[0] = leaf
	for i := range state.VerifiedChains {
		if len(state.VerifiedChains[i]) != 0 {
			state.VerifiedChains[i][0] = leaf
		}
	}
	return leaf
}
