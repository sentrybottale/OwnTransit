package signing

import (
	"bytes"
	"strings"
	"testing"
)

func TestExactByteDomainSeparatedSignature(t *testing.T) {
	keys, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParsePublic(keys.PublicPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParsePrivate(keys.PrivatePEM)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("exact bytes")
	signature, err := Sign("owntransit.test.v1", payload, parsedPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify("owntransit.test.v1", payload, signature, parsedPublic); err != nil {
		t.Fatal(err)
	}
	if err := Verify("owntransit.other.v1", payload, signature, parsedPublic); err == nil {
		t.Fatal("signature was accepted in another domain")
	}
	if err := ValidateKeyID(keys.KeyID); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), payload...)
	changed[0] ^= 1
	if err := Verify("owntransit.test.v1", changed, signature, parsedPublic); err == nil {
		t.Fatal("signature was accepted for changed bytes")
	}
}

func TestSigningRejectsAmbiguousNULDomain(t *testing.T) {
	keys, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign("a\x00b", []byte("c"), keys.Private); err == nil {
		t.Fatal("domain containing NUL was accepted")
	}

	// These inputs would produce the same delimiter-based signature message if
	// verification accepted the NUL-containing domain.
	signature, err := Sign("a", []byte("b\x00c"), keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify("a\x00b", []byte("c"), signature, keys.Public); err == nil {
		t.Fatal("NUL-containing verification domain was accepted")
	}
}

func TestSigningRejectsOversizedDomainAndPayload(t *testing.T) {
	keys, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	oversizedDomain := strings.Repeat("d", maximumSignatureDomainSize+1)
	if _, err := Sign(oversizedDomain, []byte("payload"), keys.Private); err == nil {
		t.Fatal("oversized signing domain was accepted")
	}
	if err := Verify(oversizedDomain, []byte("payload"), make([]byte, 64), keys.Public); err == nil {
		t.Fatal("oversized verification domain was accepted")
	}
	oversizedPayload := make([]byte, maximumSignaturePayloadSize+1)
	if _, err := Sign("owntransit.test.v1", oversizedPayload, keys.Private); err == nil {
		t.Fatal("oversized signing payload was accepted")
	}
	if err := Verify("owntransit.test.v1", oversizedPayload, make([]byte, 64), keys.Public); err == nil {
		t.Fatal("oversized verification payload was accepted")
	}
}

func TestSigningAcceptsExactInputLimits(t *testing.T) {
	keys, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	domain := strings.Repeat("d", maximumSignatureDomainSize)
	payload := make([]byte, maximumSignaturePayloadSize)
	payload[0] = 1
	signature, err := Sign(domain, payload, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(domain, payload, signature, keys.Public); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureInputUsesExactDomainSeparator(t *testing.T) {
	message, err := signatureInput("owntransit.test.v1", []byte("exact bytes"))
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("owntransit.test.v1\x00exact bytes")
	if !bytes.Equal(message, want) {
		t.Fatalf("signature input = %q, want %q", message, want)
	}
}

func TestSignatureInputSizeRejectsIntegerOverflow(t *testing.T) {
	maximumInt := int(^uint(0) >> 1)
	tests := []struct {
		name          string
		domainLength  int
		payloadLength int
	}{
		{name: "negative domain", domainLength: -1, payloadLength: 1},
		{name: "negative payload", domainLength: 1, payloadLength: -1},
		{name: "domain at maximum", domainLength: maximumInt, payloadLength: 0},
		{name: "payload at maximum", domainLength: 0, payloadLength: maximumInt},
		{name: "combined overflow", domainLength: 1, payloadLength: maximumInt - 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := signatureInputSize(test.domainLength, test.payloadLength); err == nil {
				t.Fatal("overflowing signature input size was accepted")
			}
		})
	}
}

func TestSignatureInputSizeAcceptsPlatformBoundary(t *testing.T) {
	maximumInt := int(^uint(0) >> 1)
	tests := []struct {
		domainLength  int
		payloadLength int
	}{
		{domainLength: 0, payloadLength: 0},
		{domainLength: 1, payloadLength: 0},
		{domainLength: maximumInt - 1, payloadLength: 0},
		{domainLength: 0, payloadLength: maximumInt - 1},
		{domainLength: 1, payloadLength: maximumInt - 2},
	}
	for _, test := range tests {
		got, err := signatureInputSize(test.domainLength, test.payloadLength)
		if err != nil {
			t.Fatal(err)
		}
		want := test.domainLength + 1 + test.payloadLength
		if got != want {
			t.Fatalf("signature input size = %d, want %d", got, want)
		}
	}
}
