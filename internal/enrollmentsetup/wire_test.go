package enrollmentsetup

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestReadyStateRoundTripsOnlyBoundedMailboxTombstone(t *testing.T) {
	var mailboxID protocol.ID
	mailboxID[len(mailboxID)-1] = 1
	tombstone := enrollmentexchange.TargetMailboxTombstone{
		Endpoint: "wss://relay.example/connects/enrollment", MailboxID: mailboxID.String(),
		ResponseReadCapability: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	}
	encoded, err := EncodeState(State{phase: enrollmentexchange.PhaseReady, tombstone: &tombstone})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ReadFrame(bytes.NewReader(encoded), FrameState, MaxFrameSize)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(payload)
	if err != nil || decoded.Phase() != enrollmentexchange.PhaseReady {
		t.Fatalf("decoded READY = %q, %v", decoded.Phase(), err)
	}
	got, ok := decoded.MailboxTombstone()
	if !ok || got != tombstone {
		t.Fatalf("tombstone = %+v, %v", got, ok)
	}
	if _, err := EncodeState(State{phase: enrollmentexchange.PhaseApplied, tombstone: &tombstone}); err == nil {
		t.Fatal("applied state exported READY-only cleanup authority")
	}
}
