package pairoffer

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func publicVectorSecret() [sha256.Size]byte {
	// Public synthetic vector, not an operational pairing secret.
	var secret [sha256.Size]byte
	for i := range secret {
		secret[i] = byte(i)
	}
	return secret
}

func TestPublicVector(t *testing.T) {
	// Independently calculated with Ruby OpenSSL SHA256/HMAC, not this package.
	const expectedCode = "otpair2.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-wICZg"
	const expectedOffer = "{\"schema\":\"owntransit.receiver-offer.v1\",\"locator\":\"4529b7de8bc5618f1e26f40d0c5f43300b94d4a352aef26745ad99a46f31f14b\",\"advertisement\":\"T3duVHJhbnNpdCBwdWJsaWMgb2ZmZXIgdGVzdCB2MQo\",\"proof\":\"FjJg6ZlH7YwFuG3XpWYcZ_3aE6xkTFo70N-uQ7x8rgw\"}\n"
	ad := []byte("OwnTransit public offer test v1\n")
	code, encoded, err := New(publicVectorSecret(), ad)
	if err != nil || string(code) != expectedCode || len(code) != CodeSize || string(encoded) != expectedOffer {
		t.Fatal("public offer vector differs")
	}
	if err := ValidateCode(code); err != nil {
		t.Fatal(err)
	}
	secret, err := Secret(code)
	if err != nil || secret != publicVectorSecret() {
		t.Fatal("code did not retain all 256 bits")
	}
	offer, err := Parse(encoded)
	if err != nil || !bytes.Equal(offer.Advertisement, ad) {
		t.Fatal("public vector parse failed")
	}
	locator, err := Locator(code)
	if err != nil || locator != offer.Locator {
		t.Fatal("lookup locator differs")
	}
	encodedAgain, err := Encode(offer)
	if err != nil || !bytes.Equal(encodedAgain, encoded) {
		t.Fatal("public offer re-encoding changed bytes")
	}
	verified, err := Verify(code, encoded)
	if err != nil || !bytes.Equal(verified, ad) {
		t.Fatal("public vector authentication failed")
	}
	if bytes.Contains(encoded, code) || bytes.Contains(encoded, []byte(base64.RawURLEncoding.EncodeToString(secret[:]))) {
		t.Fatal("public offer contains private code material")
	}
}

func TestVerifyRejectsEveryChangedAuthenticationByte(t *testing.T) {
	code, encoded, err := New(publicVectorSecret(), []byte("public receiver advertisement"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"locator", "proof", "advertisement"} {
		t.Run(field, func(t *testing.T) {
			n := sha256.Size
			if field == "advertisement" {
				n = len(original.Advertisement)
			}
			for i := 0; i < n; i++ {
				changed := original
				changed.Advertisement = append([]byte(nil), original.Advertisement...)
				switch field {
				case "locator":
					changed.Locator[i] ^= 1
				case "proof":
					changed.Proof[i] ^= 1
				case "advertisement":
					changed.Advertisement[i] ^= 1
				}
				bad, err := Encode(changed)
				if err != nil {
					t.Fatal(err)
				}
				if ad, err := Verify(code, bad); err != ErrInvalid || ad != nil {
					t.Fatalf("changed %s byte %d released untrusted advertisement", field, i)
				}
			}
		})
	}
	otherSecret := publicVectorSecret()
	otherSecret[0] ^= 1
	otherCode, _, err := New(otherSecret, original.Advertisement)
	if err != nil {
		t.Fatal(err)
	}
	if ad, err := Verify(otherCode, encoded); err != ErrInvalid || ad != nil {
		t.Fatal("crossed code released an advertisement")
	}
}

func TestCodeRejectsMalformedInput(t *testing.T) {
	code, _, err := New(publicVectorSecret(), []byte("public advertisement"))
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), code...)
	changed[len(changed)-1] ^= 1
	inputs := [][]byte{
		nil, {}, []byte(CodePrefix), code[:len(code)-1], append(append([]byte(nil), code...), '='),
		[]byte(strings.Replace(string(code), CodePrefix, "otpair1.", 1)),
		[]byte(strings.Replace(string(code), CodePrefix, "otpair3.", 1)),
		[]byte(strings.ToUpper(string(code))), []byte(" " + string(code)), []byte(string(code) + "\n"),
		[]byte("owntransit pair setup " + string(code)), []byte("wss://relay.example/connects"),
		[]byte(CodePrefix + strings.Repeat("!", CodeSize-len(CodePrefix))), changed,
	}
	for i, input := range inputs {
		if err := ValidateCode(input); err != ErrInvalid {
			t.Fatalf("malformed input %d accepted", i)
		}
		if secret, err := Secret(input); err != ErrInvalid || secret != ([sha256.Size]byte{}) {
			t.Fatalf("malformed input %d released secret material", i)
		}
		if locator, err := Locator(input); err != ErrInvalid || locator != ([sha256.Size]byte{}) {
			t.Fatalf("malformed input %d produced a lookup locator", i)
		}
	}
}

func TestParseRejectsNoncanonicalAndUnknownOffers(t *testing.T) {
	_, encoded, err := New(publicVectorSecret(), []byte{0xff})
	if err != nil {
		t.Fatal(err)
	}
	var original wireOffer
	if err := json.Unmarshal(encoded, &original); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*wireOffer){
		func(w *wireOffer) { w.Schema = "owntransit.receiver-offer.v2" },
		func(w *wireOffer) { w.Locator = strings.ToUpper(w.Locator) },
		func(w *wireOffer) { w.Locator = w.Locator[:len(w.Locator)-2] },
		func(w *wireOffer) { w.Locator = strings.Repeat("z", 64) },
		func(w *wireOffer) { w.Proof = "" },
		func(w *wireOffer) { w.Proof += "=" },
		func(w *wireOffer) { w.Proof = strings.Repeat("!", 43) },
		func(w *wireOffer) { w.Advertisement = "" },
		func(w *wireOffer) { w.Advertisement += "==" },
		func(w *wireOffer) { w.Advertisement = "/w" },
		func(w *wireOffer) { w.Advertisement = "_x" }, // Nonzero unused base64 bits.
		func(w *wireOffer) {
			w.Advertisement = base64.RawURLEncoding.EncodeToString(make([]byte, MaxAdvertisementBytes+1))
		},
	}
	inputs := [][]byte{
		nil, encoded[:len(encoded)-1], append(append([]byte(nil), encoded...), '\n'),
		[]byte(" " + string(encoded)), []byte(string(encoded) + "{}"),
		[]byte(strings.Replace(string(encoded), "{", "{\"extra\":1,", 1)),
		[]byte(strings.Replace(string(encoded), "{", "{\"schema\":\"owntransit.receiver-offer.v1\",", 1)),
		[]byte(strings.Replace(string(encoded), "\"schema\"", "\"Schema\"", 1)),
		[]byte(strings.Replace(string(encoded), "{", "{\n", 1)),
		bytes.Repeat([]byte{' '}, MaxOfferBytes+1),
	}
	for _, mutate := range mutations {
		wire := original
		mutate(&wire)
		bad, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, append(bad, '\n'))
	}
	for i, input := range inputs {
		if offer, err := Parse(input); err != ErrInvalid || offer.Advertisement != nil {
			t.Fatalf("malformed offer %d accepted", i)
		}
	}
	// A canonical but incorrect proof is structurally valid; Parse is not an
	// endpoint authority check and cannot verify a MAC without the code.
	original.Proof = base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	bad, _ := json.Marshal(original)
	if _, err := Parse(append(bad, '\n')); err != nil {
		t.Fatal("format parser unexpectedly claimed to authenticate proof")
	}
}

func TestOfferBoundsAndIndependentMemory(t *testing.T) {
	secret := publicVectorSecret()
	for _, ad := range [][]byte{nil, {}, make([]byte, MaxAdvertisementBytes+1)} {
		if code, offer, err := New(secret, ad); err != ErrInvalid || code != nil || offer != nil {
			t.Fatal("invalid advertisement size accepted")
		}
		if encoded, err := Encode(Offer{Advertisement: ad}); err != ErrInvalid || encoded != nil {
			t.Fatal("invalid advertisement size encoded")
		}
	}
	ad := bytes.Repeat([]byte{0xff}, MaxAdvertisementBytes)
	code, encoded, err := New(secret, ad)
	if err != nil || len(encoded) > MaxOfferBytes {
		t.Fatal("maximum advertisement did not fit offer bound")
	}
	ad[0] = 0
	verified, err := Verify(code, encoded)
	if err != nil || len(verified) != MaxAdvertisementBytes || verified[0] != 0xff {
		t.Fatal("input mutation affected published offer")
	}
	verified[0] = 0
	verifiedAgain, err := Verify(code, encoded)
	if err != nil || verifiedAgain[0] != 0xff {
		t.Fatal("returned advertisement aliases encoded offer")
	}
	if bytes.Contains(encoded, []byte(hex.EncodeToString(secret[:]))) {
		t.Fatal("public offer contains raw secret encoding")
	}
}

func FuzzParseAndVerify(f *testing.F) {
	code, offer, err := New(publicVectorSecret(), []byte("public advertisement"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(code, offer)
	f.Add([]byte{}, []byte{})
	f.Fuzz(func(t *testing.T, code, offer []byte) {
		parsed, parseErr := Parse(offer)
		ad, verifyErr := Verify(code, offer)
		if verifyErr == nil {
			if parseErr != nil || ValidateCode(code) != nil || !bytes.Equal(ad, parsed.Advertisement) {
				t.Fatal("verification bypassed a prerequisite")
			}
		} else if ad != nil {
			t.Fatal("failed verification released an advertisement")
		}
	})
}
