package enrollmentexchange

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestTargetAndOperatorPrepareOneExactFullDigestTranscript(t *testing.T) {
	value, signer, now := invitationFixture(t)
	target, operator, recipient, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	value.Exchange = target
	value.RequestEncryptionRecipient = recipient
	encoded, err := signInvitation(value, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	tentative, err := parseTentativeInvitation(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, _ := requestFixture(t, value, now)

	targetPrepared, err := prepareTargetTranscript(tentative, requestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	operatorPrepared, err := prepareOperatorTranscript(tentative, operator, targetPrepared.encryptedRequestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	if targetPrepared.fullSHA256 != operatorPrepared.fullSHA256 || targetPrepared.phrase != operatorPrepared.phrase ||
		targetPrepared.invitationSHA256 != operatorPrepared.invitationSHA256 ||
		targetPrepared.requestSHA256 != operatorPrepared.requestSHA256 ||
		targetPrepared.encryptedRequestSHA256 != operatorPrepared.encryptedRequestSHA256 ||
		!bytes.Equal(targetPrepared.requestBytes, operatorPrepared.requestBytes) {
		t.Fatal("target and operator did not prepare the same exact transcript")
	}
	if targetPrepared.fullSHA256 == ([sha256.Size]byte{}) || targetPrepared.phrase == (SafetyPhrase{}) {
		t.Fatal("prepared transcript omitted its full digest or comparison phrase")
	}
}

func TestPreparedTranscriptRejectsCrossWiredInvitationAndOperatorSecrets(t *testing.T) {
	value, signer, now := invitationFixture(t)
	target, _, recipient, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	value.Exchange = target
	value.RequestEncryptionRecipient = recipient
	encoded, err := signInvitation(value, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	tentative, err := parseTentativeInvitation(encoded, now)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, _ := requestFixture(t, value, now)
	prepared, err := prepareTargetTranscript(tentative, requestBytes, now)
	if err != nil {
		t.Fatal(err)
	}

	_, wrongOperator, _, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareOperatorTranscript(tentative, wrongOperator, prepared.encryptedRequestBytes, now); err == nil {
		t.Fatal("operator secrets for another invitation were accepted")
	}

	changed := tentative
	first := byte('0')
	if changed.SHA256[0] == first {
		first = '1'
	}
	changed.SHA256 = string(first) + changed.SHA256[1:]
	if _, err := prepareTargetTranscript(changed, requestBytes, now); err == nil {
		t.Fatal("tentative handle detached from its exact invitation bytes was accepted")
	}
}
