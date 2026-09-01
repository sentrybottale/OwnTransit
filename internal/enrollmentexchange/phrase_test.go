package enrollmentexchange

import (
	"crypto/sha256"
	"reflect"
	"testing"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

func TestPhraseExactVector(t *testing.T) {
	invitation := []byte("invite\n")
	request := []byte("signed request\n")
	ciphertext := []byte("ciphertext\n")
	digest, err := transcriptDigest(invitation, request, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hexDigest(digest), "aae933f43fc72e584b14d66a53855438b573c0c6811139849bf79fdc4018be9d"; got != want {
		t.Fatalf("transcript digest = %s, want %s", got, want)
	}
	targetDigest := comparisonDigest(targetToProvisionerDomain, digest)
	if got, want := hexDigest(targetDigest), "4edb2bc0b27b912fd8d6103e80d13ab9855a5be76c739250351775b85cdaefc0"; got != want {
		t.Fatalf("target-to-provisioner digest = %s, want %s", got, want)
	}
	provisionerDigest := comparisonDigest(provisionerToTargetDomain, digest)
	if got, want := hexDigest(provisionerDigest), "b825413407894481724d7e7de66062302e4728d714181720fc80965dfa9fcd31"; got != want {
		t.Fatalf("provisioner-to-target digest = %s, want %s", got, want)
	}
	for word, want := range []uint16{630, 1738, 1921} {
		if got := wordIndex(targetDigest, word); got != want {
			t.Fatalf("target-to-provisioner index %d = %d, want %d", word, got, want)
		}
	}
	for word, want := range []uint16{1473, 336, 616} {
		if got := wordIndex(provisionerDigest, word); got != want {
			t.Fatalf("provisioner-to-target index %d = %d, want %d", word, got, want)
		}
	}

	got, err := derivePhrase(invitation, request, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	want := SafetyPhrase{"excite", "sun", "usual", "return", "claw", "escape"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("phrase = %q, want %q", got, want)
	}
}

func TestPhraseBindsAllExactByteStringsAndTheirBoundaries(t *testing.T) {
	base, err := derivePhrase([]byte("ab"), []byte("c"), []byte("de"))
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name             string
		invitation       []byte
		request          []byte
		encryptedRequest []byte
	}{
		{"invitation bytes", []byte("aB"), []byte("c"), []byte("de")},
		{"signed request bytes", []byte("ab"), []byte("C"), []byte("de")},
		{"encrypted request bytes", []byte("ab"), []byte("c"), []byte("dE")},
		{"invitation/request boundary", []byte("a"), []byte("bc"), []byte("de")},
		{"request/ciphertext boundary", []byte("ab"), []byte("cd"), []byte("e")},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			changed, err := derivePhrase(check.invitation, check.request, check.encryptedRequest)
			if err != nil {
				t.Fatal(err)
			}
			if changed == base {
				t.Fatal("changed transcript produced the same complete six-word phrase")
			}
		})
	}
}

func TestPhraseRejectsEmptyAndOversizedInputs(t *testing.T) {
	for _, check := range []struct {
		name             string
		invitation       []byte
		request          []byte
		encryptedRequest []byte
	}{
		{"empty invitation", nil, []byte("request"), []byte("ciphertext")},
		{"empty signed request", []byte("invitation"), nil, []byte("ciphertext")},
		{"empty encrypted request", []byte("invitation"), []byte("request"), nil},
		{"large invitation", make([]byte, MaxInvitationSize+1), []byte("request"), []byte("ciphertext")},
		{"large signed request", []byte("invitation"), make([]byte, enrollment.MaxRequestSize+1), []byte("ciphertext")},
		{"large encrypted request", []byte("invitation"), []byte("request"), make([]byte, MaxEncryptedRequestSize+1)},
	} {
		t.Run(check.name, func(t *testing.T) {
			if _, err := derivePhrase(check.invitation, check.request, check.encryptedRequest); err == nil {
				t.Fatal("invalid transcript was accepted")
			}
		})
	}
}

func TestWordIndexUsesBigEndianNonOverlappingBits(t *testing.T) {
	var digest [sha256.Size]byte
	copy(digest[:], []byte{0x00, 0x30, 0x03, 0xff, 0x80})
	want := []uint16{1, 1024, 2047}
	for word, expected := range want {
		if got := wordIndex(digest, word); got != expected {
			t.Fatalf("word %d index = %d, want %d", word, got, expected)
		}
	}

	allOnes := [sha256.Size]byte{}
	for index := range allOnes {
		allOnes[index] = 0xff
	}
	for word := 0; word < safetyWordsPerDirection; word++ {
		if got := wordIndex(allOnes, word); got != 2047 {
			t.Fatalf("all-ones word %d index = %d, want 2047", word, got)
		}
	}
}

func TestComparisonDirectionsAreDomainSeparated(t *testing.T) {
	transcript := sha256.Sum256([]byte("same full transcript"))
	targetWords := comparisonDigest(targetToProvisionerDomain, transcript)
	provisionerWords := comparisonDigest(provisionerToTargetDomain, transcript)
	if targetWords == provisionerWords {
		t.Fatal("opposite comparison directions produced the same digest")
	}
}

func TestFrozenWordListShape(t *testing.T) {
	words, err := wordList()
	if err != nil {
		t.Fatal(err)
	}
	if len(words) != 2048 || words[0] != "abandon" || words[2047] != "zoo" {
		t.Fatalf("unexpected word-list identity: count=%d first=%q last=%q", len(words), words[0], words[len(words)-1])
	}
	prefixes := make(map[string]string, len(words))
	for _, word := range words {
		prefixLength := 4
		if len(word) < prefixLength {
			prefixLength = len(word)
		}
		prefix := word[:prefixLength]
		if previous, exists := prefixes[prefix]; exists {
			t.Fatalf("words %q and %q share comparison prefix %q", previous, word, prefix)
		}
		prefixes[prefix] = word
	}
}
