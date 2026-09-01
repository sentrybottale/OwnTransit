package enrollmentexchange

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestDurableTargetFirstTwoWayConfirmationAndReadyGate(t *testing.T) {
	fixture := newExchangeFlowFixture(t)
	target, err := NewTargetSession(fixture.invitation, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, err := target.MailboxAction()
	if err != nil {
		t.Fatal(err)
	}
	operator, err := NewOperatorSession(fixture.receipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := operator.ProvisionerWords(); err == nil {
		t.Fatal("reverse words were revealed before target-first confirmation")
	}
	targetWords, err := target.TargetWords()
	if err != nil {
		t.Fatal(err)
	}
	before := operator.Generation()
	outcome, err := operator.ConfirmTargetWords([3]string{})
	if err != nil || outcome != OutcomeDeferred || operator.Generation() != before {
		t.Fatalf("empty operator input = %q, %v generation=%d", outcome, err, operator.Generation())
	}
	outcome, err = operator.ConfirmTargetWords(targetWords)
	if err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("operator confirmation = %q, %v", outcome, err)
	}
	reverseWords, err := operator.ProvisionerWords()
	if err != nil {
		t.Fatal(err)
	}
	outcome, err = target.ConfirmProvisionerWords(reverseWords)
	if err != nil || outcome != OutcomeConfirmed {
		t.Fatalf("target confirmation = %q, %v", outcome, err)
	}

	encodedTarget, err := target.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := ParseTargetSession(encodedTarget, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	resumedWords, err := resumed.TargetWords()
	if err != nil || resumedWords != targetWords || resumed.Phase() != PhaseTranscriptConfirmed {
		t.Fatalf("resumed target = words %v phase %q err %v", resumedWords, resumed.Phase(), err)
	}
	encodedOperator, err := operator.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumedOperator, err := ParseOperatorSession(encodedOperator, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := resumedOperator.ProvisionerWords(); err != nil || got != reverseWords {
		t.Fatalf("resumed operator words = %v, %v", got, err)
	}

	approvedSet := fixture.approvedSetDigest(t)
	innerResponse := []byte("opaque-existing-enrollment-response\n")
	bound, err := resumedOperator.BindResponse(innerResponse, approvedSet, fixture.signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := resumed.AcceptBoundResponse(bound)
	if err != nil || !bytes.Equal(accepted, innerResponse) {
		t.Fatalf("accepted response = %q, %v", accepted, err)
	}
	if resumed.Phase() != PhaseResponseVerified {
		t.Fatalf("phase after response = %q", resumed.Phase())
	}
	if err := resumed.RecordApplied(); err != nil {
		t.Fatal(err)
	}
	probeFailure := errors.New("relay denied service")
	if err := resumed.CompleteReadyProbe(context.Background(), func(context.Context) error { return probeFailure }); !errors.Is(err, probeFailure) {
		t.Fatalf("failed probe = %v", err)
	}
	if resumed.Phase() != PhaseApplied {
		t.Fatalf("failed probe changed phase to %q", resumed.Phase())
	}
	if err := resumed.CompleteReadyProbe(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if resumed.Phase() != PhaseReady {
		t.Fatalf("successful probe phase = %q", resumed.Phase())
	}
}

func TestVerifiedResponseAndAppliedStateResumeWithoutMailbox(t *testing.T) {
	fixture := newExchangeFlowFixture(t)
	target, err := NewTargetSession(fixture.invitation, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := target.MailboxAction()
	operator, err := NewOperatorSession(fixture.receipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	words, _ := target.TargetWords()
	_, _ = operator.ConfirmTargetWords(words)
	reverse, _ := operator.ProvisionerWords()
	_, _ = target.ConfirmProvisionerWords(reverse)
	inner := []byte("opaque target-encrypted lifecycle response\n")
	bound, err := operator.BindResponse(inner, fixture.approvedSetDigest(t), fixture.signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.AcceptBoundResponse(bound); err != nil {
		t.Fatal(err)
	}

	// The mailbox is deliberately absent from this point onward. Durable
	// target state alone must retain the exact verified response.
	verifiedState, err := target.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumedVerified, err := ParseTargetSession(verifiedState, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := resumedVerified.VerifiedEnrollmentResponse()
	if err != nil || !bytes.Equal(retained, inner) {
		t.Fatalf("retained response = %q, %v", retained, err)
	}
	if err := resumedVerified.RecordApplied(); err != nil {
		t.Fatal(err)
	}

	// Simulate lifecycle apply succeeding and the process crashing immediately
	// after the phase transition was durably written, before READY.
	appliedState, err := resumedVerified.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumedApplied, err := ParseTargetSession(appliedState, fixture.now)
	if err != nil || resumedApplied.Phase() != PhaseApplied {
		t.Fatalf("resumed applied phase=%q err=%v", resumedApplied.Phase(), err)
	}
	if err := resumedApplied.CompleteReadyProbe(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if resumedApplied.Phase() != PhaseReady {
		t.Fatalf("resumed READY phase = %q", resumedApplied.Phase())
	}
}

func TestComparisonMismatchIsTerminalAndDoesNotRevealPositions(t *testing.T) {
	fixture := newExchangeFlowFixture(t)
	target, err := NewTargetSession(fixture.invitation, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := target.MailboxAction()
	operator, err := NewOperatorSession(fixture.receipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	targetWords, _ := target.TargetWords()
	targetWords[1] = "wrong"
	outcome, err := operator.ConfirmTargetWords(targetWords)
	if err != nil || outcome != OutcomeCancelled || operator.Phase() != PhaseCancelled {
		t.Fatalf("mismatch = %q phase=%q err=%v", outcome, operator.Phase(), err)
	}
	if _, err := operator.ProvisionerWords(); err == nil {
		t.Fatal("cancelled operator revealed reverse words")
	}
	if _, err := operator.ConfirmTargetWords(targetWords); err == nil {
		t.Fatal("cancelled comparison was retried")
	}
	encoded, err := operator.Encode()
	if err != nil {
		t.Fatal(err)
	}
	resumed, err := ParseOperatorSession(encoded, fixture.now)
	if err != nil || resumed.Phase() != PhaseCancelled {
		t.Fatalf("resumed mismatch = %q, %v", resumed.Phase(), err)
	}
}

func TestBoundResponseRejectsCrossWiringAndActivationWithoutLocalConfirmation(t *testing.T) {
	first := newExchangeFlowFixture(t)
	second := newExchangeFlowFixture(t)
	firstTarget, _ := NewTargetSession(first.invitation, first.client.RequestBytes, first.now)
	action, _ := firstTarget.MailboxAction()
	firstOperator, _ := NewOperatorSession(first.receipt, action.EncryptedRequest, first.now)
	words, _ := firstTarget.TargetWords()
	_, _ = firstOperator.ConfirmTargetWords(words)
	reverse, _ := firstOperator.ProvisionerWords()
	_, _ = firstTarget.ConfirmProvisionerWords(reverse)
	bound, err := firstOperator.BindResponse([]byte("opaque\n"), first.approvedSetDigest(t), first.signer.Private)
	if err != nil {
		t.Fatal(err)
	}

	secondTarget, err := NewTargetSession(second.invitation, second.client.RequestBytes, second.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secondTarget.AcceptBoundResponse(bound); err == nil {
		t.Fatal("unconfirmed target accepted a response")
	}
	secondAction, _ := secondTarget.MailboxAction()
	secondOperator, _ := NewOperatorSession(second.receipt, secondAction.EncryptedRequest, second.now)
	secondWords, _ := secondTarget.TargetWords()
	_, _ = secondOperator.ConfirmTargetWords(secondWords)
	secondReverse, _ := secondOperator.ProvisionerWords()
	_, _ = secondTarget.ConfirmProvisionerWords(secondReverse)
	if _, err := secondTarget.AcceptBoundResponse(bound); err == nil {
		t.Fatal("cross-wired confirmed target accepted another transcript's response")
	}
}

func TestTargetAndOperatorStoresUseGenerationCAS(t *testing.T) {
	fixture := newExchangeFlowFixture(t)
	target, err := NewTargetSession(fixture.invitation, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	canonicalParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	targetRoot := filepath.Join(canonicalParent, "target")
	if err := CreateTargetStore(targetRoot, target); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTargetStore(targetRoot, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := loaded.MailboxAction()
	operator, err := NewOperatorSession(fixture.receipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	operatorRoot := filepath.Join(canonicalParent, "operator")
	if err := CreateOperatorStore(operatorRoot, operator); err != nil {
		t.Fatal(err)
	}

	targetWords, _ := loaded.TargetWords()
	_, _ = operator.ConfirmTargetWords(targetWords)
	if err := ReplaceOperatorStore(operatorRoot, 1, operator, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceOperatorStore(operatorRoot, 1, operator, fixture.now); err == nil {
		t.Fatal("stale operator generation replacement succeeded")
	}
	reverse, _ := operator.ProvisionerWords()
	_, _ = loaded.ConfirmProvisionerWords(reverse)
	if err := ReplaceTargetStore(targetRoot, 1, loaded, fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := ReplaceTargetStore(targetRoot, 1, loaded, fixture.now); err == nil {
		t.Fatal("stale target generation replacement succeeded")
	}
	resumed, err := LoadTargetStore(targetRoot, fixture.now)
	if err != nil || resumed.Phase() != PhaseTranscriptConfirmed {
		t.Fatalf("stored target = %q, %v", resumed.Phase(), err)
	}
}

func TestInitialStoresResumeOnlyExactProtectedResidue(t *testing.T) {
	fixture := newExchangeFlowFixture(t)
	target, err := NewTargetSession(fixture.invitation, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, _ := target.MailboxAction()
	operator, err := NewOperatorSession(fixture.receipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	canonicalParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name       string
		file       string
		create     func(string) error
		encode     func() ([]byte, error)
		prepublish bool
	}{
		{name: "target-root-only", file: targetSessionFile, create: func(path string) error { return CreateTargetStore(path, target) }, encode: target.Encode},
		{name: "target-exact-file", file: targetSessionFile, create: func(path string) error { return CreateTargetStore(path, target) }, encode: target.Encode, prepublish: true},
		{name: "operator-root-only", file: operatorSessionFile, create: func(path string) error { return CreateOperatorStore(path, operator) }, encode: operator.Encode},
		{name: "operator-exact-file", file: operatorSessionFile, create: func(path string) error { return CreateOperatorStore(path, operator) }, encode: operator.Encode, prepublish: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(canonicalParent, test.name)
			root, err := securefs.CreateRoot(path)
			if err != nil {
				t.Fatal(err)
			}
			if test.prepublish {
				encoded, encodeErr := test.encode()
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				if err := root.EnsureFile(test.file, encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := root.Close(); err != nil {
				t.Fatal(err)
			}
			if err := test.create(path); err != nil {
				t.Fatalf("resume exact residue: %v", err)
			}
			if err := test.create(path); err != nil {
				t.Fatalf("idempotent retry: %v", err)
			}
		})
	}

	wrongPath := filepath.Join(canonicalParent, "wrong-residue")
	root, err := securefs.CreateRoot(wrongPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureFile(targetSessionFile, []byte("different\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	if err := CreateTargetStore(wrongPath, target); err == nil {
		t.Fatal("initial store accepted ambiguous different session residue")
	}
}

func FuzzParseTargetSessionFailsClosed(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _ = ParseTargetSession(encoded, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	})
}

type exchangeFlowFixture struct {
	now         time.Time
	signer      signing.KeyPair
	invitation  []byte
	receipt     []byte
	client      enrollment.PendingMaterial
	trust       enrollment.Trust
	releaseID   string
	routeID     string
	connectorID string
}

func newExchangeFlowFixture(t *testing.T) exchangeFlowFixture {
	t.Helper()
	base, signer, now := invitationFixture(t)
	issued, err := IssueInvitation(InvitationOptions{
		Role: enrollment.RoleClient, RouteID: base.RouteID, ConnectorInstallationID: base.ConnectorInstallationID,
		Runtime: base.Runtime, Trust: base.Trust, ExchangeEndpoint: base.Exchange.Endpoint, Validity: time.Hour,
		IntendedRecipient: "Example recipient record", IdentityContactReference: "Directory record EXAMPLE-123",
	}, signer.Private, now)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseTentativeInvitation(issued.Invitation, now)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	client, err := enrollment.NewPendingRequest(enrollment.InitOptions{
		Role: enrollment.RoleClient, InstallationID: installation.String(),
		RouteID: parsed.Invitation.RouteID, ConnectorInstallationID: parsed.Invitation.ConnectorInstallationID,
		Sequence: 1, Now: now, RequestValidity: 30 * time.Minute,
		Trust: parsed.Invitation.Trust, DeploymentSigner: signer.Public, Runtime: parsed.Invitation.Runtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	return exchangeFlowFixture{
		now: now, signer: signer, invitation: issued.Invitation, receipt: issued.OperatorReceipt,
		client: client, trust: parsed.Invitation.Trust, releaseID: parsed.Invitation.Runtime.ReleaseID,
		routeID: parsed.Invitation.RouteID, connectorID: parsed.Invitation.ConnectorInstallationID,
	}
}

func (fixture exchangeFlowFixture) approvedSetDigest(t *testing.T) string {
	t.Helper()
	makeRuntime := func(role enrollment.Role) enrollment.RuntimeBinding {
		value := enrollment.RuntimeBinding{
			ReleaseID: fixture.releaseID, ReleaseSequence: fixture.client.Payload.Runtime.ReleaseSequence,
			ArtifactSHA256: strings.Repeat("ab", 32), OS: "linux", Arch: "amd64", Role: role,
			Protocol: enrollment.DeploymentProtocol, LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		}
		if role == enrollment.RoleConnector {
			value.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
		}
		if role == enrollment.RoleClient {
			value.OS, value.Arch = "darwin", "arm64"
		}
		return value
	}
	relayID, _ := protocol.NewID()
	connectorID, err := protocol.ParseID(fixture.connectorID)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(role enrollment.Role, installation, route, connector string) enrollment.PendingMaterial {
		material, makeErr := enrollment.NewPendingRequest(enrollment.InitOptions{
			Role: role, InstallationID: installation, RouteID: route, ConnectorInstallationID: connector,
			Sequence: 1, Now: fixture.now, RequestValidity: 30 * time.Minute,
			Trust: fixture.trust, DeploymentSigner: ed25519.PublicKey(fixture.signer.Public), Runtime: makeRuntime(role),
		})
		if makeErr != nil {
			t.Fatal(makeErr)
		}
		return material
	}
	relay := makeRequest(enrollment.RoleRelay, relayID.String(), "", "")
	connector := makeRequest(enrollment.RoleConnector, connectorID.String(), fixture.routeID, "")
	digest, err := ApprovedRequestSetSHA256(relay.RequestBytes, connector.RequestBytes, fixture.client.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
