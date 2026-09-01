//go:build darwin || linux

package enrollmentsetup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestClientSetupStagesExactMaterialThenCommitsOnlyAfterTwoWayConfirmation(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.client(t)
	first, err := client.Stage(fixture.issued.Invitation, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Phase() != enrollmentexchange.PhasePendingComparison {
		t.Fatalf("phase = %q", first.Phase())
	}
	if _, err := os.Lstat(client.paths.privateRoot); !os.IsNotExist(err) {
		t.Fatalf("tentative setup touched permanent client root: %v", err)
	}
	firstAction, ok := first.MailboxAction()
	if !ok {
		t.Fatal("tentative setup omitted mailbox action")
	}
	resumed, err := client.Stage(append([]byte(nil), fixture.issued.Invitation...), fixture.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	resumedAction, ok := resumed.MailboxAction()
	if !ok || !bytes.Equal(firstAction.EncryptedRequest, resumedAction.EncryptedRequest) ||
		firstAction.MailboxID != resumedAction.MailboxID || firstAction.RequestWriteCapability != resumedAction.RequestWriteCapability {
		t.Fatal("exact retry regenerated or cross-wired tentative material")
	}

	words, _ := first.TargetWords()
	operator, err := enrollmentexchange.NewOperatorSession(fixture.issued.OperatorReceipt, firstAction.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := operator.ConfirmTargetWords(words); err != nil || outcome != enrollmentexchange.OutcomeConfirmed {
		t.Fatalf("operator confirmation = %q, %v", outcome, err)
	}
	reverse, err := operator.ProvisionerWords()
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := client.Confirm(reverse, fixture.now.Add(2*time.Second))
	if err != nil || confirmed.Phase() != enrollmentexchange.PhaseTranscriptConfirmed {
		t.Fatalf("target confirmation = %q, %v", confirmed.Phase(), err)
	}
	pending, err := enrollmenttarget.PendingRequest(client.paths.privateRoot)
	if err != nil {
		t.Fatalf("confirmed pending import: %v", err)
	}
	if pending.RequestSHA256 == "" || len(pending.RequestBytes) == 0 {
		t.Fatal("confirmed import did not retain its exact signed request")
	}
	root, err := client.openSetupRoot(false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	selector, err := readSelector(root)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := root.OpenDir(selector.Workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer workspace.Close()
	if _, err := workspace.ReadFile(pendingFile, maxPendingSize); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tentative private material remains after commit: %v", err)
	}
}

func TestClientSetupDurablyReachesReadyThenRetiresLocalEnrollmentAuthority(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.appliedClient(t)
	ready, err := client.CompleteReady(context.Background(), func(context.Context) error { return nil }, fixture.now.Add(5*time.Second))
	if err != nil || ready.Phase() != enrollmentexchange.PhaseReady {
		t.Fatalf("READY phase=%q err=%v", ready.Phase(), err)
	}
	if _, ok := ready.MailboxTombstone(); !ok {
		t.Fatal("durable READY omitted its one-time mailbox cleanup authority")
	}
	cleaned, err := client.CleanupReady(fixture.now.Add(6 * time.Second))
	if err != nil || cleaned.Phase() != enrollmentexchange.PhaseReady {
		t.Fatalf("cleanup phase=%q err=%v", cleaned.Phase(), err)
	}
	if _, ok := cleaned.MailboxTombstone(); ok {
		t.Fatal("cleaned READY retained mailbox authority")
	}
	if resumed, err := client.Status(fixture.now.Add(2 * time.Hour)); err != nil || resumed.Phase() != enrollmentexchange.PhaseReady {
		t.Fatalf("expired post-cleanup resume phase=%q err=%v", resumed.Phase(), err)
	}
}

func TestClientSetupResumesReceiptWrittenBeforeReadySessionCAS(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.appliedClient(t)
	current, err := client.openCurrent(fixture.now.Add(5*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	var result enrollmenttarget.ApplyResult
	if err := current.session.ReconcileAppliedResponse(func(response []byte) error {
		var reconcileErr error
		result, reconcileErr = enrollmenttarget.ReconcileAppliedResponse(client.paths.privateRoot, response, current.session.RequestSHA256())
		return reconcileErr
	}); err != nil {
		current.Close()
		t.Fatal(err)
	}
	if err := current.session.CompleteReadyProbe(context.Background(), func(context.Context) error { return nil }); err != nil {
		current.Close()
		t.Fatal(err)
	}
	tombstone, err := current.session.MailboxTombstone()
	if err != nil {
		current.Close()
		t.Fatal(err)
	}
	receipt := readyRecord{
		Schema: readySchema, InvitationSHA256: current.plan.InvitationSHA256,
		Workspace: workspaceName(current.plan.InvitationSHA256), InstallationID: current.plan.InstallationID,
		RequestSHA256: current.session.RequestSHA256(), ActiveRecordID: result.RecordID, Runtime: current.plan.Runtime,
		ReadySessionGeneration: current.session.Generation(), ValidationUnix: current.plan.VerifiedUnix,
		ReadyUnix: fixture.now.Add(5 * time.Second).Unix(), MailboxEndpoint: tombstone.Endpoint,
		MailboxID: tombstone.MailboxID, ResponseReadCapability: tombstone.ResponseReadCapability,
	}
	encoded, err := encodeReady(receipt)
	if err != nil {
		current.Close()
		t.Fatal(err)
	}
	if err := current.root.EnsureFile(readyFile, encoded, 0o600); err != nil {
		current.Close()
		t.Fatal(err)
	}
	// Deliberately omit ReplaceTargetStore: this is the receipt-before-CAS crash.
	current.Close()
	if resumed, err := client.Status(fixture.now.Add(6 * time.Second)); err != nil || resumed.Phase() != enrollmentexchange.PhaseReady {
		t.Fatalf("resume phase=%q err=%v", resumed.Phase(), err)
	}
	if _, err := client.CleanupReady(fixture.now.Add(7 * time.Second)); err != nil {
		t.Fatalf("cleanup of pre-CAS Applied session: %v", err)
	}
}

func TestClientSetupMismatchAndExpiredCancelTombstoneTentativeSecrets(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.client(t)
	state, err := client.Stage(fixture.issued.Invitation, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	words, _ := state.TargetWords()
	words[0] = map[bool]string{true: "ability", false: "abandon"}[words[0] == "abandon"]
	cancelled, err := client.Confirm(words, fixture.now.Add(time.Second))
	if err != nil || cancelled.Phase() != enrollmentexchange.PhaseCancelled {
		t.Fatalf("mismatch phase=%q err=%v", cancelled.Phase(), err)
	}
	if _, err := os.Lstat(client.paths.privateRoot); !os.IsNotExist(err) {
		t.Fatalf("mismatch poisoned permanent bootstrap: %v", err)
	}
	if _, err := client.Stage(fixture.issued.Invitation, fixture.now.Add(2*time.Second)); !errors.Is(err, ErrResetRequired) {
		t.Fatalf("cancelled invitation was reusable: %v", err)
	}

	second := fixture.issue(t, "Second recipient")
	if _, err := client.Stage(second.Invitation, fixture.now.Add(3*time.Second)); err != nil {
		t.Fatalf("different invitation after explicit mismatch cancellation: %v", err)
	}
	if state, err := client.Cancel(fixture.now.Add(2 * time.Hour)); err != nil || state.Phase() != enrollmentexchange.PhaseCancelled {
		t.Fatalf("expired setup cancellation phase=%q err=%v", state.Phase(), err)
	}
	if _, err := os.Lstat(client.paths.privateRoot); !os.IsNotExist(err) {
		t.Fatalf("expired cancellation poisoned permanent bootstrap: %v", err)
	}
}

func TestClientSetupConcurrentStageLeavesOneExactResumableSession(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.client(t)
	start := make(chan struct{})
	errorsSeen := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := client.Stage(fixture.issued.Invitation, fixture.now)
			errorsSeen <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errorsSeen)
	successes := 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("concurrent stage produced no committed session")
	}
	if state, err := client.Status(fixture.now.Add(time.Second)); err != nil || state.Phase() != enrollmentexchange.PhasePendingComparison {
		t.Fatalf("post-race resume phase=%q err=%v", state.Phase(), err)
	}
}

func TestCommittedApplyFallbackIsImpossibleBeforeResponseVerification(t *testing.T) {
	status := enrollmenttarget.Status{}
	status.State.ActiveRecordID = strings.Repeat("a", 64)
	if mayReconcileCommittedApply(enrollmentexchange.PhaseTranscriptConfirmed, status, nil) {
		t.Fatal("transcript-confirmed setup accepted unrelated active state as its pending import")
	}
	if !mayReconcileCommittedApply(enrollmentexchange.PhaseResponseVerified, status, nil) {
		t.Fatal("response-verified crash reconciliation was disabled")
	}
	if mayReconcileCommittedApply(enrollmentexchange.PhaseResponseVerified, status, errors.New("invalid state")) {
		t.Fatal("invalid active state was accepted for crash reconciliation")
	}
}

func TestReadyReceiptRejectsAnotherAuthenticatedRuntimeBeforeReportingReady(t *testing.T) {
	fixture := newClientSetupFixture(t)
	client := fixture.client(t)
	other := fixture.runtime
	other.ReleaseSequence++
	receipt := readyRecord{Runtime: other}
	if err := client.validateReadyTarget(receipt); err == nil {
		t.Fatal("historical READY receipt survived an installed runtime selector change")
	}
}

func TestInstalledClientPathsAreCanonicalAndSymlinkFreeByConstruction(t *testing.T) {
	linux, err := installedClientPaths("linux")
	if err != nil {
		t.Fatal(err)
	}
	if linux.privateRoot != "/var/lib/owntransit/client/private" || linux.setupRoot != "/var/lib/owntransit/client/setup" {
		t.Fatalf("linux paths = %+v", linux)
	}
	darwin, err := installedClientPaths("darwin")
	if err != nil {
		t.Fatal(err)
	}
	if darwin.privateRoot != "/private/var/db/OwnTransit/client/private" || darwin.authorityRoot != "/private/var/db/OwnTransit/client/authority" || darwin.setupRoot != "/private/var/db/OwnTransit/client/setup" {
		t.Fatalf("darwin paths = %+v", darwin)
	}
}

type clientSetupFixture struct {
	now       time.Time
	runtime   enrollment.RuntimeBinding
	trust     enrollment.Trust
	issuers   enrollment.Issuers
	signer    signing.KeyPair
	route     string
	connector string
	issued    enrollmentexchange.IssuedInvitation
	parent    string
}

func newClientSetupFixture(t *testing.T) clientSetupFixture {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	makeCA := func(name string) pki.Material {
		ca, err := pki.NewCA(name, now, 365*24*time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		return ca
	}
	outer := makeCA("OwnTransit test relay CA")
	innerClient := makeCA("OwnTransit test client CA")
	innerConnector := makeCA("OwnTransit test connector CA")
	releaseID, _ := protocol.NewID()
	routeID, _ := protocol.NewID()
	connectorID, _ := protocol.NewID()
	runtimeBinding := enrollment.RuntimeBinding{
		ReleaseID: releaseID.String(), ReleaseSequence: 1, ArtifactSHA256: strings.Repeat("a", 64),
		OS: "linux", Arch: "amd64", Role: enrollment.RoleClient,
		Protocol: enrollment.DeploymentProtocol, LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
	}
	trust := enrollment.Trust{
		RelayAdmissionCA: string(outer.CertPEM), InnerClientCA: string(innerClient.CertPEM),
		InnerConnectorCA: string(innerConnector.CertPEM),
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := clientSetupFixture{
		now: now, runtime: runtimeBinding, trust: trust, signer: signer,
		issuers: enrollment.Issuers{RelayAdmission: outer, InnerClient: innerClient, InnerConnector: innerConnector},
		route:   routeID.String(), connector: connectorID.String(), parent: parent,
	}
	fixture.issued = fixture.issue(t, "Example recipient")
	return fixture
}

func (fixture clientSetupFixture) issue(t *testing.T, recipient string) enrollmentexchange.IssuedInvitation {
	t.Helper()
	issued, err := enrollmentexchange.IssueInvitation(enrollmentexchange.InvitationOptions{
		Role: enrollment.RoleClient, RouteID: fixture.route, ConnectorInstallationID: fixture.connector,
		Runtime: fixture.runtime, Trust: fixture.trust, ExchangeEndpoint: "wss://relay.example.com/connects/enrollment",
		Validity: time.Hour, IntendedRecipient: recipient, IdentityContactReference: "Example directory record 42",
	}, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func (fixture clientSetupFixture) client(t *testing.T) *Client {
	t.Helper()
	return &Client{
		paths: clientPaths{
			privateRoot: filepath.Join(fixture.parent, "private"), authorityRoot: filepath.Join(fixture.parent, "authority"),
			runtimeRoot: filepath.Join(fixture.parent, "runtime"), runtimeConfig: filepath.Join(fixture.parent, "runtime"),
			anchorViewRoot: filepath.Join(fixture.parent, "anchor-view"), setupRoot: filepath.Join(fixture.parent, "setup"),
		},
		runtime: fixture.runtime,
	}
}

func (fixture clientSetupFixture) appliedClient(t *testing.T) *Client {
	t.Helper()
	client := fixture.client(t)
	staged, err := client.Stage(fixture.issued.Invitation, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	action, ok := staged.MailboxAction()
	if !ok {
		t.Fatal("staged client omitted its mailbox action")
	}
	operator, err := enrollmentexchange.NewOperatorSession(fixture.issued.OperatorReceipt, action.EncryptedRequest, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	words, ok := staged.TargetWords()
	if !ok {
		t.Fatal("staged client omitted its target words")
	}
	if outcome, err := operator.ConfirmTargetWords(words); err != nil || outcome != enrollmentexchange.OutcomeConfirmed {
		t.Fatalf("operator confirmation = %q, %v", outcome, err)
	}
	reverse, err := operator.ProvisionerWords()
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := client.Confirm(reverse, fixture.now.Add(time.Second))
	if err != nil || confirmed.Phase() != enrollmentexchange.PhaseTranscriptConfirmed {
		t.Fatalf("target confirmation = %q, %v", confirmed.Phase(), err)
	}
	clientRequest, err := enrollmenttarget.PendingRequest(client.paths.privateRoot)
	if err != nil {
		t.Fatal(err)
	}
	runtimeFor := func(role enrollment.Role) enrollment.RuntimeBinding {
		value := fixture.runtime
		value.Role = role
		value.OS, value.Arch = "linux", "amd64"
		value.ConnectorTarget = ""
		if role == enrollment.RoleConnector {
			value.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
		}
		return value
	}
	makeRequest := func(role enrollment.Role, installationID, routeID, connectorID string) enrollment.PendingMaterial {
		material, makeErr := enrollment.NewPendingRequest(enrollment.InitOptions{
			Role: role, InstallationID: installationID, RouteID: routeID, ConnectorInstallationID: connectorID,
			Sequence: 1, Now: fixture.now, RequestValidity: 30 * time.Minute,
			Trust: fixture.trust, DeploymentSigner: fixture.signer.Public, Runtime: runtimeFor(role),
		})
		if makeErr != nil {
			t.Fatal(makeErr)
		}
		return material
	}
	relayID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	relayRequest := makeRequest(enrollment.RoleRelay, relayID.String(), "", "")
	connectorRequest := makeRequest(enrollment.RoleConnector, fixture.connector, fixture.route, "")
	responses, err := enrollment.ApproveInitialRoute(enrollment.RouteApproval{
		RelayRequest: relayRequest.RequestBytes, ConnectorRequest: connectorRequest.RequestBytes,
		ClientRequest: clientRequest.RequestBytes, RelayURL: "wss://relay.example.com/connects",
		RelayListen: enrollment.PackagedRelayListen, DeploymentSequence: 1, Now: fixture.now,
		LeafValidity: 24 * time.Hour, DeploymentValidity: time.Hour,
		Issuers: fixture.issuers, DeploymentSigner: fixture.signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}
	approvedDigest, err := enrollmentexchange.ApprovedRequestSetSHA256(
		relayRequest.RequestBytes, connectorRequest.RequestBytes, clientRequest.RequestBytes, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := operator.BindResponse(responses.ClientEnvelope, approvedDigest, fixture.signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := client.AcceptAndApply(bound, fixture.now.Add(3*time.Second))
	if err != nil || applied.Phase() != enrollmentexchange.PhaseApplied {
		t.Fatalf("apply phase=%q err=%v", applied.Phase(), err)
	}
	return client
}
