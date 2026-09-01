package enrollmentexchange

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestBindResponseAcceptsMaximumEnrollmentEnvelope(t *testing.T) {
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", sha256.Size*2)
	response := make([]byte, enrollment.MaxEnvelopeSize)
	response[0] = 1
	bound, err := BindResponse(digest, digest, digest, digest, response, keys.Private)
	if err != nil {
		t.Fatal(err)
	}
	previousLimit := enrollment.MaxEnvelopeSize + (256 << 10)
	if len(bound) <= previousLimit {
		t.Fatal("maximum response did not exercise the previous undersized bound")
	}
	if len(bound) > MaxBoundResponseSize {
		t.Fatalf("bound response size = %d, limit = %d", len(bound), MaxBoundResponseSize)
	}
	if _, err := BindResponse(digest, digest, digest, digest, make([]byte, enrollment.MaxEnvelopeSize+1), keys.Private); err == nil {
		t.Fatal("oversized enrollment response was accepted")
	}
}
