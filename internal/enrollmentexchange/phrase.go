// Package enrollmentexchange defines the hostile enrollment courier's exact
// transcript primitives. It grants no authority to the relay which carries
// the bytes.
//
// The raw invitation, mailbox, request-encryption, binding, and phrase
// operations intentionally remain package-private. They are not a safe setup
// API until durable target and operator confirmation states bind the full
// transcript digest and gate both issuance and activation.
package enrollmentexchange

import (
	"crypto/sha256"
	_ "embed"
	"encoding/binary"
	"errors"
	"strings"
	"sync"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

const (
	MaxInvitationSize       = 256 << 10
	MaxEncryptedRequestSize = 640 << 10
	SafetyWordCount         = 6

	safetyWordsPerDirection   = SafetyWordCount / 2
	transcriptDomain          = "OwnTransit enrollment transcript v1"
	targetToProvisionerDomain = "OwnTransit enrollment target-to-provisioner words v1"
	provisionerToTargetDomain = "OwnTransit enrollment provisioner-to-target words v1"
	wordListSHA256Hex         = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
)

//go:embed bip39_english.txt
var encodedSafetyWords string

var (
	loadWordsOnce sync.Once
	safetyWords   []string
	wordListError error
)

// SafetyPhrase contains six public comparison words. The first three are read
// by the target to the provisioner; the final three are revealed and read in the
// reverse direction only after the first half matches. The words are neither a
// secret nor authority: only the full transcript digest may gate enrollment.
type SafetyPhrase [SafetyWordCount]string

// derivePhrase derives two direction-separated 33-bit word groups over the
// frozen 2,048-word vocabulary. It binds the exact signed invitation, signed
// request plaintext, and encrypted request bytes.
func derivePhrase(invitationBytes, requestBytes, encryptedRequestBytes []byte) (SafetyPhrase, error) {
	digest, err := transcriptDigest(invitationBytes, requestBytes, encryptedRequestBytes)
	if err != nil {
		return SafetyPhrase{}, err
	}
	return phraseFromTranscriptDigest(digest)
}

func transcriptDigest(invitationBytes, requestBytes, encryptedRequestBytes []byte) ([sha256.Size]byte, error) {
	if len(invitationBytes) == 0 || len(invitationBytes) > MaxInvitationSize {
		return [sha256.Size]byte{}, errors.New("enrollmentexchange: invitation size is outside the supported bound")
	}
	if len(requestBytes) == 0 || len(requestBytes) > enrollment.MaxRequestSize {
		return [sha256.Size]byte{}, errors.New("enrollmentexchange: signed request size is outside the supported bound")
	}
	if len(encryptedRequestBytes) == 0 || len(encryptedRequestBytes) > MaxEncryptedRequestSize {
		return [sha256.Size]byte{}, errors.New("enrollmentexchange: encrypted request size is outside the supported bound")
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte(transcriptDomain))
	_, _ = hash.Write([]byte{0})
	writeTranscriptField(hash, invitationBytes)
	writeTranscriptField(hash, requestBytes)
	writeTranscriptField(hash, encryptedRequestBytes)
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func writeTranscriptField(hash hashWriter, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write(value)
}

func phraseFromTranscriptDigest(transcript [sha256.Size]byte) (SafetyPhrase, error) {
	words, err := wordList()
	if err != nil {
		return SafetyPhrase{}, err
	}

	targetToProvisioner := comparisonDigest(targetToProvisionerDomain, transcript)
	provisionerToTarget := comparisonDigest(provisionerToTargetDomain, transcript)
	var phrase SafetyPhrase
	for word := 0; word < safetyWordsPerDirection; word++ {
		phrase[word] = words[wordIndex(targetToProvisioner, word)]
		phrase[safetyWordsPerDirection+word] = words[wordIndex(provisionerToTarget, word)]
	}
	return phrase, nil
}

func comparisonDigest(domain string, transcript [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(transcript[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

// wordIndex reads one 11-bit vocabulary index in network bit order. Callers
// deliberately use only the first three indices from each directional digest.
func wordIndex(digest [sha256.Size]byte, word int) uint16 {
	var index uint16
	for bit := 0; bit < 11; bit++ {
		offset := word*11 + bit
		index = index<<1 | uint16((digest[offset/8]>>(7-uint(offset%8)))&1)
	}
	return index
}

func wordList() ([]string, error) {
	loadWordsOnce.Do(func() {
		digest := sha256.Sum256([]byte(encodedSafetyWords))
		if hexDigest(digest) != wordListSHA256Hex {
			wordListError = errors.New("enrollmentexchange: embedded safety-word vocabulary has changed")
			return
		}
		if !strings.HasSuffix(encodedSafetyWords, "\n") {
			wordListError = errors.New("enrollmentexchange: embedded safety-word vocabulary is not newline terminated")
			return
		}
		values := strings.Split(strings.TrimSuffix(encodedSafetyWords, "\n"), "\n")
		if len(values) != 1<<11 {
			wordListError = errors.New("enrollmentexchange: embedded safety-word vocabulary does not contain 2,048 words")
			return
		}
		previous := ""
		for _, value := range values {
			if value == "" || value <= previous {
				wordListError = errors.New("enrollmentexchange: embedded safety-word vocabulary is not canonical and unique")
				return
			}
			for _, character := range value {
				if character < 'a' || character > 'z' {
					wordListError = errors.New("enrollmentexchange: embedded safety-word vocabulary contains a non-ASCII word")
					return
				}
			}
			previous = value
		}
		safetyWords = values
	})
	return safetyWords, wordListError
}

func hexDigest(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, octet := range value {
		encoded[index*2] = digits[octet>>4]
		encoded[index*2+1] = digits[octet&0x0f]
	}
	return string(encoded)
}
