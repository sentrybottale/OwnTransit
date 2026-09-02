package enrollmentexchange

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestMailboxStoreIsOpaqueBoundedOneWriteAndExactlyIdempotent(t *testing.T) {
	target, operator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store := NewMailboxStore()
	store.now = func() time.Time { return now }
	if err := store.Create(
		target.MailboxID,
		target.RequestWriteCapability,
		operator.RequestReadCapability,
		operator.ResponseWriteCapability,
		target.ResponseReadCapability,
		now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(
		target.MailboxID,
		target.RequestWriteCapability,
		operator.RequestReadCapability,
		operator.ResponseWriteCapability,
		target.ResponseReadCapability,
		now.Add(time.Hour),
	); err != nil {
		t.Fatalf("exact mailbox creation retry failed: %v", err)
	}
	if err := store.Create(
		target.MailboxID,
		target.RequestWriteCapability,
		operator.RequestReadCapability,
		operator.ResponseWriteCapability,
		target.ResponseReadCapability,
		now.Add(2*time.Hour),
	); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("mailbox creation accepted changed expiry: %v", err)
	}

	request := []byte("opaque padded request")
	if err := store.PutRequest(target.MailboxID, target.RequestWriteCapability, request); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRequest(target.MailboxID, target.RequestWriteCapability, append([]byte(nil), request...)); err != nil {
		t.Fatalf("exact retry failed: %v", err)
	}
	if err := store.PutRequest(target.MailboxID, target.RequestWriteCapability, []byte("overwrite")); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("overwrite = %v", err)
	}
	read, err := store.ReadRequest(target.MailboxID, operator.RequestReadCapability)
	if err != nil || !bytes.Equal(read, request) {
		t.Fatalf("request read = %q, %v", read, err)
	}
	read[0] ^= 1
	again, _ := store.ReadRequest(target.MailboxID, operator.RequestReadCapability)
	if bytes.Equal(read, again) {
		t.Fatal("mailbox read aliased stored bytes")
	}

	response := []byte("opaque bound response")
	expectedResponse := append([]byte(nil), response...)
	if err := store.PutResponse(target.MailboxID, operator.ResponseWriteCapability, response); err != nil {
		t.Fatal(err)
	}
	for index := range response {
		response[index] ^= 0xff
	}
	got, err := store.ReadResponse(target.MailboxID, target.ResponseReadCapability)
	if err != nil || !bytes.Equal(got, expectedResponse) {
		t.Fatalf("response read = %q, %v", got, err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := store.Consume(target.MailboxID, target.ResponseReadCapability); err != nil {
			t.Fatalf("consume attempt %d: %v", attempt, err)
		}
	}
	if _, err := store.ReadResponse(target.MailboxID, target.ResponseReadCapability); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("consumed response remained readable: %v", err)
	}
}

func TestMailboxStoreUsesGenericFailuresForCrossWireWrongCapabilityAndExpiry(t *testing.T) {
	firstTarget, firstOperator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	secondTarget, secondOperator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store := NewMailboxStore()
	store.now = func() time.Time { return now }
	for _, value := range []struct {
		target   targetExchange
		operator operatorExchange
	}{
		{firstTarget, firstOperator}, {secondTarget, secondOperator},
	} {
		if err := store.Create(value.target.MailboxID, value.target.RequestWriteCapability, value.operator.RequestReadCapability, value.operator.ResponseWriteCapability, value.target.ResponseReadCapability, now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.PutRequest(firstTarget.MailboxID, secondTarget.RequestWriteCapability, []byte("x")); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("wrong cap = %v", err)
	}
	if _, err := store.ReadRequest(firstTarget.MailboxID, secondOperator.RequestReadCapability); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("cross-wire = %v", err)
	}
	if _, err := store.ReadRequest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", firstOperator.RequestReadCapability); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("absent = %v", err)
	}
	now = now.Add(time.Minute)
	if err := store.PutRequest(firstTarget.MailboxID, firstTarget.RequestWriteCapability, []byte("x")); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("expired put = %v", err)
	}
	if _, err := store.ReadResponse(firstTarget.MailboxID, firstTarget.ResponseReadCapability); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("expired read = %v", err)
	}
}

func TestMailboxStoreRejectsAliasedCapabilitiesAndUnboundedBodies(t *testing.T) {
	target, operator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	store := NewMailboxStore()
	store.now = func() time.Time { return now }
	if err := store.Create(target.MailboxID, target.RequestWriteCapability, target.RequestWriteCapability, operator.ResponseWriteCapability, target.ResponseReadCapability, now.Add(time.Hour)); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("reused capability = %v", err)
	}
	if err := store.Create(target.MailboxID, target.RequestWriteCapability, operator.RequestReadCapability, operator.ResponseWriteCapability, target.ResponseReadCapability, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutRequest(target.MailboxID, target.RequestWriteCapability, make([]byte, MaxEncryptedRequestSize+1)); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("oversized request = %v", err)
	}
	if err := store.PutResponse(target.MailboxID, operator.ResponseWriteCapability, make([]byte, MaxBoundResponseSize+1)); !errors.Is(err, ErrMailboxUnavailable) {
		t.Fatalf("oversized response = %v", err)
	}
}

func FuzzMailboxCapabilityNeverPanics(f *testing.F) {
	f.Add("mailbox", "capability", []byte("opaque"))
	f.Fuzz(func(t *testing.T, mailboxID, capability string, opaque []byte) {
		store := NewMailboxStore()
		_ = store.PutRequest(mailboxID, capability, opaque)
		_, _ = store.ReadResponse(mailboxID, capability)
	})
}
