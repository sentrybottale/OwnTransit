package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"sync"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

const (
	MaxMailboxSlots = 1024
	// Keep the complete opaque mailbox arena well below the relay's 256 MiB
	// container limit. The remaining memory is reserved for the carrier,
	// WebSocket/TLS stacks, Go runtime and fixed slot metadata.
	MaxMailboxStoredBytes = 32 << 20
	MaxMailboxLifetime    = 24 * time.Hour
)

// ErrMailboxUnavailable is deliberately generic across absent IDs, wrong
// capabilities, expiry, overwrite attempts and capacity pressure.
var ErrMailboxUnavailable = errors.New("enrollment exchange mailbox unavailable")

type mailboxSlot struct {
	expires           time.Time
	requestWriteHash  [sha256.Size]byte
	requestReadHash   [sha256.Size]byte
	responseWriteHash [sha256.Size]byte
	responseReadHash  [sha256.Size]byte
	request           []byte
	response          []byte
	consumed          bool
}

// MailboxStore is an in-memory, non-listable, bounded opaque two-slot core.
// It contains no persistence, parser, signer, issuer, policy or target
// authority. A relay restart simply requires exact-byte re-upload.
type MailboxStore struct {
	mu          sync.Mutex
	slots       map[string]*mailboxSlot
	storedBytes int
	now         func() time.Time
}

func NewMailboxStore() *MailboxStore {
	return &MailboxStore{slots: make(map[string]*mailboxSlot), now: time.Now}
}

// Create installs one invitation's four independently generated action
// capabilities. The caller must derive expiry from the already validated
// invitation; it cannot exceed the fixed lifetime bound.
func (store *MailboxStore) Create(mailboxID, requestWrite, requestRead, responseWrite, responseRead string, expires time.Time) error {
	if store == nil || store.now == nil {
		return ErrMailboxUnavailable
	}
	parsed, err := protocol.ParseID(mailboxID)
	if err != nil || parsed == (protocol.ID{}) {
		return ErrMailboxUnavailable
	}
	capabilities := []string{requestWrite, requestRead, responseWrite, responseRead}
	decoded := make([][]byte, len(capabilities))
	for index, capability := range capabilities {
		decoded[index], err = parseMailboxCapability(capability)
		if err != nil {
			return ErrMailboxUnavailable
		}
		for prior := 0; prior < index; prior++ {
			if bytes.Equal(decoded[index], decoded[prior]) {
				return ErrMailboxUnavailable
			}
		}
	}
	now := store.now().UTC()
	if !expires.After(now) || expires.After(now.Add(MaxMailboxLifetime)) {
		return ErrMailboxUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	requestWriteHash := mailboxActionHash(mailboxID, "request-write", requestWrite)
	requestReadHash := mailboxActionHash(mailboxID, "request-read", requestRead)
	responseWriteHash := mailboxActionHash(mailboxID, "response-write", responseWrite)
	responseReadHash := mailboxActionHash(mailboxID, "response-read", responseRead)
	if existing := store.slots[mailboxID]; existing != nil {
		if existing.expires.Equal(expires.UTC()) &&
			subtle.ConstantTimeCompare(existing.requestWriteHash[:], requestWriteHash[:]) == 1 &&
			subtle.ConstantTimeCompare(existing.requestReadHash[:], requestReadHash[:]) == 1 &&
			subtle.ConstantTimeCompare(existing.responseWriteHash[:], responseWriteHash[:]) == 1 &&
			subtle.ConstantTimeCompare(existing.responseReadHash[:], responseReadHash[:]) == 1 {
			return nil
		}
		return ErrMailboxUnavailable
	}
	if len(store.slots) >= MaxMailboxSlots {
		return ErrMailboxUnavailable
	}
	store.slots[mailboxID] = &mailboxSlot{
		expires:           expires.UTC(),
		requestWriteHash:  requestWriteHash,
		requestReadHash:   requestReadHash,
		responseWriteHash: responseWriteHash,
		responseReadHash:  responseReadHash,
	}
	return nil
}

func (store *MailboxStore) PutRequest(mailboxID, capability string, opaque []byte) error {
	return store.put(mailboxID, "request-write", capability, opaque, MaxEncryptedRequestSize)
}

func (store *MailboxStore) ReadRequest(mailboxID, capability string) ([]byte, error) {
	return store.read(mailboxID, "request-read", capability)
}

func (store *MailboxStore) PutResponse(mailboxID, capability string, opaque []byte) error {
	return store.put(mailboxID, "response-write", capability, opaque, MaxBoundResponseSize)
}

func (store *MailboxStore) ReadResponse(mailboxID, capability string) ([]byte, error) {
	return store.read(mailboxID, "response-read", capability)
}

func (store *MailboxStore) Consume(mailboxID, responseReadCapability string) error {
	if store == nil || store.now == nil {
		return ErrMailboxUnavailable
	}
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	slot := store.slots[mailboxID]
	if slot == nil || !now.Before(slot.expires) || !slot.authorized(mailboxID, "response-read", responseReadCapability) {
		return ErrMailboxUnavailable
	}
	if slot.consumed {
		return nil
	}
	store.storedBytes -= len(slot.request) + len(slot.response)
	wipe(slot.request)
	wipe(slot.response)
	slot.request, slot.response, slot.consumed = nil, nil, true
	return nil
}

func (store *MailboxStore) put(mailboxID, action, capability string, opaque []byte, limit int) error {
	if store == nil || store.now == nil || len(opaque) == 0 || len(opaque) > limit {
		return ErrMailboxUnavailable
	}
	if _, err := parseMailboxCapability(capability); err != nil {
		return ErrMailboxUnavailable
	}
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	slot := store.slots[mailboxID]
	if slot == nil || slot.consumed || !now.Before(slot.expires) || !slot.authorized(mailboxID, action, capability) {
		return ErrMailboxUnavailable
	}
	var destination *[]byte
	switch action {
	case "request-write":
		destination = &slot.request
	case "response-write":
		destination = &slot.response
	default:
		return ErrMailboxUnavailable
	}
	if len(*destination) != 0 {
		if bytes.Equal(*destination, opaque) {
			return nil
		}
		return ErrMailboxUnavailable
	}
	if store.storedBytes > MaxMailboxStoredBytes-len(opaque) {
		return ErrMailboxUnavailable
	}
	*destination = append([]byte(nil), opaque...)
	store.storedBytes += len(opaque)
	return nil
}

func (store *MailboxStore) read(mailboxID, action, capability string) ([]byte, error) {
	if store == nil || store.now == nil {
		return nil, ErrMailboxUnavailable
	}
	if _, err := parseMailboxCapability(capability); err != nil {
		return nil, ErrMailboxUnavailable
	}
	now := store.now().UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.expireLocked(now)
	slot := store.slots[mailboxID]
	if slot == nil || slot.consumed || !now.Before(slot.expires) || !slot.authorized(mailboxID, action, capability) {
		return nil, ErrMailboxUnavailable
	}
	var source []byte
	switch action {
	case "request-read":
		source = slot.request
	case "response-read":
		source = slot.response
	default:
		return nil, ErrMailboxUnavailable
	}
	if len(source) == 0 {
		return nil, ErrMailboxUnavailable
	}
	return append([]byte(nil), source...), nil
}

func (slot *mailboxSlot) authorized(mailboxID, action, capability string) bool {
	actual := mailboxActionHash(mailboxID, action, capability)
	var expected [sha256.Size]byte
	switch action {
	case "request-write":
		expected = slot.requestWriteHash
	case "request-read":
		expected = slot.requestReadHash
	case "response-write":
		expected = slot.responseWriteHash
	case "response-read":
		expected = slot.responseReadHash
	default:
		return false
	}
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func (store *MailboxStore) expireLocked(now time.Time) {
	for id, slot := range store.slots {
		if !now.Before(slot.expires) {
			store.storedBytes -= len(slot.request) + len(slot.response)
			wipe(slot.request)
			wipe(slot.response)
			delete(store.slots, id)
		}
	}
	if store.storedBytes < 0 {
		store.storedBytes = 0
	}
}

func mailboxActionHash(mailboxID, action, capability string) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("OwnTransit mailbox action capability v1"))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(action))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(mailboxID))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(capability))
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}
