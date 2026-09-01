package enrollmentexchange

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"filippo.io/age"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

const requestPlaintextMagic = "OwnTransit padded enrollment request v1\x00"

var requestPlaintextClasses = [...]int{64 << 10, 128 << 10, 256 << 10, 512 << 10}

// sealRequest encrypts one already signed target request to the invitation's
// one-use recipient and pads the authenticated plaintext to the smallest
// frozen size class. Callers must durably retain and retry the returned exact
// ciphertext rather than invoking sealRequest again.
func sealRequest(requestBytes []byte, recipientText string, now time.Time) ([]byte, error) {
	if len(requestBytes) == 0 || len(requestBytes) > enrollment.MaxRequestSize {
		return nil, errors.New("enrollmentexchange: signed request has an invalid size")
	}
	if _, err := enrollment.ParseRequest(requestBytes, now); err != nil {
		return nil, err
	}
	recipient, err := age.ParseX25519Recipient(recipientText)
	if err != nil || recipient.String() != recipientText {
		return nil, errors.New("enrollmentexchange: request recipient is not canonical age X25519")
	}
	plaintext, err := padRequest(requestBytes)
	if err != nil {
		return nil, err
	}
	defer wipe(plaintext)
	var ciphertext bytes.Buffer
	writer, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return nil, fmt.Errorf("enrollmentexchange: initialize request encryption: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: encrypt request: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("enrollmentexchange: finalize request encryption: %w", err)
	}
	if ciphertext.Len() == 0 || ciphertext.Len() > MaxEncryptedRequestSize {
		return nil, errors.New("enrollmentexchange: encrypted request exceeds its size limit")
	}
	return ciphertext.Bytes(), nil
}

// openRequest decrypts, unpads and verifies the target's existing signed
// request. It returns exact signed bytes for ordinary enrollment validation and
// the safety transcript; it grants no approval or issuance authority.
func openRequest(ciphertext []byte, identityText string, now time.Time) ([]byte, enrollment.RequestPayload, error) {
	if len(ciphertext) == 0 || len(ciphertext) > MaxEncryptedRequestSize {
		return nil, enrollment.RequestPayload{}, errors.New("enrollmentexchange: encrypted request has an invalid size")
	}
	identity, err := age.ParseX25519Identity(identityText)
	if err != nil || identity.String() != identityText {
		return nil, enrollment.RequestPayload{}, errors.New("enrollmentexchange: request identity is not canonical age X25519")
	}
	reader, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, enrollment.RequestPayload{}, errors.New("enrollmentexchange: request decryption failed")
	}
	maxPlaintext := int64(requestPlaintextClasses[len(requestPlaintextClasses)-1])
	plaintext, err := io.ReadAll(io.LimitReader(reader, maxPlaintext+1))
	if err != nil {
		return nil, enrollment.RequestPayload{}, errors.New("enrollmentexchange: read decrypted request")
	}
	defer wipe(plaintext)
	requestBytes, err := unpadRequest(plaintext)
	if err != nil {
		return nil, enrollment.RequestPayload{}, err
	}
	payload, err := enrollment.ParseRequest(requestBytes, now)
	if err != nil {
		return nil, enrollment.RequestPayload{}, err
	}
	return append([]byte(nil), requestBytes...), payload, nil
}

// bindRequestToInvitation proves that the decrypted target-generated request
// kept every tentative role, route, issuer, verifier, release and platform
// claim from the exact invitation. Human confirmation is still required.
func bindRequestToInvitation(invitation invitation, request enrollment.RequestPayload) error {
	if request.Sequence != 1 || request.Role != invitation.Role || request.RouteID != invitation.RouteID ||
		request.ConnectorInstallationID != invitation.ConnectorInstallationID || request.Runtime != invitation.Runtime ||
		request.IssuerPins != invitation.IssuerPins || request.DeploymentSignerKeyID != invitation.DeploymentSignerKeyID {
		return errors.New("enrollmentexchange: request does not match invitation bootstrap bindings")
	}
	if request.CreatedUnix < invitation.CreatedUnix || request.ExpiresUnix > invitation.ExpiresUnix {
		return errors.New("enrollmentexchange: request validity is outside its invitation")
	}
	return nil
}

func padRequest(requestBytes []byte) ([]byte, error) {
	headerSize := len(requestPlaintextMagic) + 4 + sha256.Size
	minimum := headerSize + len(requestBytes)
	classSize := 0
	for _, candidate := range requestPlaintextClasses {
		if minimum <= candidate {
			classSize = candidate
			break
		}
	}
	if classSize == 0 {
		return nil, errors.New("enrollmentexchange: signed request does not fit a supported padding class")
	}
	plaintext := make([]byte, classSize)
	offset := copy(plaintext, requestPlaintextMagic)
	binary.BigEndian.PutUint32(plaintext[offset:offset+4], uint32(len(requestBytes)))
	offset += 4
	digest := sha256.Sum256(requestBytes)
	offset += copy(plaintext[offset:], digest[:])
	offset += copy(plaintext[offset:], requestBytes)
	if _, err := rand.Read(plaintext[offset:]); err != nil {
		wipe(plaintext)
		return nil, fmt.Errorf("enrollmentexchange: generate request padding: %w", err)
	}
	return plaintext, nil
}

func unpadRequest(plaintext []byte) ([]byte, error) {
	validClass := false
	for _, size := range requestPlaintextClasses {
		if len(plaintext) == size {
			validClass = true
			break
		}
	}
	if !validClass {
		return nil, errors.New("enrollmentexchange: decrypted request has an invalid padding class")
	}
	headerSize := len(requestPlaintextMagic) + 4 + sha256.Size
	if len(plaintext) < headerSize || !bytes.Equal(plaintext[:len(requestPlaintextMagic)], []byte(requestPlaintextMagic)) {
		return nil, errors.New("enrollmentexchange: decrypted request has an invalid version header")
	}
	offset := len(requestPlaintextMagic)
	requestSize := int(binary.BigEndian.Uint32(plaintext[offset : offset+4]))
	offset += 4
	declaredDigest := plaintext[offset : offset+sha256.Size]
	offset += sha256.Size
	if requestSize <= 0 || requestSize > enrollment.MaxRequestSize || requestSize > len(plaintext)-offset {
		return nil, errors.New("enrollmentexchange: decrypted request has an invalid declared size")
	}
	requestBytes := plaintext[offset : offset+requestSize]
	digest := sha256.Sum256(requestBytes)
	if !bytes.Equal(digest[:], declaredDigest) {
		return nil, errors.New("enrollmentexchange: decrypted request digest mismatch")
	}
	return requestBytes, nil
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
