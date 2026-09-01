package signing

import "testing"

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
