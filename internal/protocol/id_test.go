package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestIDCanonicalBase32(t *testing.T) {
	var zero ID
	want := strings.Repeat("a", EncodedIDSize)
	if got := zero.String(); got != want {
		t.Fatalf("zero ID = %q, want %q", got, want)
	}

	parsed, err := ParseID(want)
	if err != nil {
		t.Fatalf("ParseID: %v", err)
	}
	if parsed != zero {
		t.Fatalf("parsed ID = %x, want zero", parsed)
	}
}

func TestIDRoundTripsEverySemanticType(t *testing.T) {
	route, boot, epoch, session := fixtureIDs()

	gotRoute, err := ParseRouteID(route.String())
	if err != nil || gotRoute != route {
		t.Fatalf("route round trip = %x, %v", gotRoute, err)
	}
	gotBoot, err := ParseBootNonce(boot.String())
	if err != nil || gotBoot != boot {
		t.Fatalf("boot round trip = %x, %v", gotBoot, err)
	}
	gotEpoch, err := ParseEpochID(epoch.String())
	if err != nil || gotEpoch != epoch {
		t.Fatalf("epoch round trip = %x, %v", gotEpoch, err)
	}
	gotSession, err := ParseSessionID(session.String())
	if err != nil || gotSession != session {
		t.Fatalf("session round trip = %x, %v", gotSession, err)
	}
}

func TestParseIDRejectsNoncanonicalText(t *testing.T) {
	canonical := strings.Repeat("a", EncodedIDSize)
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "short", value: canonical[:len(canonical)-1]},
		{name: "long", value: canonical + "a"},
		{name: "uppercase", value: strings.ToUpper(canonical)},
		{name: "padding", value: canonical[:len(canonical)-1] + "="},
		{name: "digit zero", value: canonical[:10] + "0" + canonical[11:]},
		{name: "digit one", value: canonical[:10] + "1" + canonical[11:]},
		{name: "space", value: canonical[:10] + " " + canonical[11:]},
		// For a 256-bit value, only one bit in the final base32 character is
		// significant. "b" decodes to the same bytes as canonical "a" in
		// permissive decoders but has nonzero unused trailing bits.
		{name: "nonzero trailing bits", value: canonical[:len(canonical)-1] + "b"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseID(test.value); !errors.Is(err, ErrInvalidID) {
				t.Fatalf("ParseID(%q) error = %v, want %v", test.value, err, ErrInvalidID)
			}
		})
	}
}

func TestRandomIDGenerators(t *testing.T) {
	id, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if parsed, err := ParseID(id.String()); err != nil || parsed != id {
		t.Fatalf("NewID round trip = %x, %v", parsed, err)
	}

	route, err := NewRouteID()
	if err != nil {
		t.Fatalf("NewRouteID: %v", err)
	}
	boot, err := NewBootNonce()
	if err != nil {
		t.Fatalf("NewBootNonce: %v", err)
	}
	epoch, err := NewEpochID()
	if err != nil {
		t.Fatalf("NewEpochID: %v", err)
	}
	session, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}

	if len(route.String()) != EncodedIDSize || len(boot.String()) != EncodedIDSize ||
		len(epoch.String()) != EncodedIDSize || len(session.String()) != EncodedIDSize {
		t.Fatal("random semantic ID did not have canonical encoded length")
	}
}

func FuzzParseID(f *testing.F) {
	f.Add(strings.Repeat("a", EncodedIDSize))
	f.Add("not-an-id")
	f.Fuzz(func(t *testing.T, text string) {
		id, err := ParseID(text)
		if err != nil {
			return
		}
		if got := id.String(); got != text {
			t.Fatalf("accepted noncanonical ID %q; canonical is %q", text, got)
		}
		roundTrip, err := ParseID(id.String())
		if err != nil || roundTrip != id {
			t.Fatalf("round trip = %x, %v; want %x", roundTrip, err, id)
		}
	})
}
