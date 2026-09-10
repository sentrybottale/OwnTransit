package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
)

func TestApprovalIsConstructionAndPrintsExactLostCodeRecovery(t *testing.T) {
	id := (protocol.ID{1}).String()
	var out bytes.Buffer
	printApprovalHandoff(&out, "wss://relay.example/connects", id)
	text := out.String()
	for _, want := range []string{"Target approved", "UNDER CONSTRUCTION", "owntransit-client setup", "sudo owntransit-target code --target-id " + id, "wss://relay.example/connects"} {
		if !strings.Contains(text, want) {
			t.Fatalf("handoff omitted %q", want)
		}
	}
	for _, bad := range []string{"THIS VPS is finished", "TUNNEL READY", "otrelay1.", "otpair2."} {
		if strings.Contains(text, bad) {
			t.Fatal("approval invented readiness or printed a code")
		}
	}
	if !strings.Contains(text, "\n  sudo owntransit-target code --target-id "+id+"\n") {
		t.Fatal("retrieval was not a standalone copyable command")
	}
}
