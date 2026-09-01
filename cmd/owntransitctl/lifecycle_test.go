package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmenttarget"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestBootstrapCreatesPrivateTargetStateFromPublicTrustOnly(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleClient)
	encoded, err := bootstrapTarget(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, encoded)
	var summary bootstrapSummary
	if err := json.Unmarshal(encoded, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "owntransit.ctl.bootstrap.v1" || summary.Role != enrollment.RoleClient || summary.InstallationID == "" || summary.StateGeneration != 1 || summary.ReleaseSequence != 1 {
		t.Fatalf("invalid bootstrap summary: %+v", summary)
	}
	assertPathMode(t, fixture.options.stateRoot, 0o700)
	status, err := enrollmenttarget.ReadStatus(mustResolveStateRoot(t, fixture.options.stateRoot))
	if err != nil {
		t.Fatal(err)
	}
	if status.State.InstallationID != summary.InstallationID || status.State.PendingRequest != nil || status.State.HighestReleaseSequence != 1 {
		t.Fatalf("invalid initial target status: %+v", status.State)
	}
	if err := filepath.WalkDir(fixture.options.stateRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.Contains(entry.Name(), "outer-key") || strings.Contains(entry.Name(), "inner-key") || strings.Contains(entry.Name(), "age-identity") {
			t.Fatalf("bootstrap created endpoint secret %q", path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestClientEnrollmentInitPendingCancelAndStatus(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleClient)
	bootstrapBytes, err := bootstrapTarget(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	var bootstrap bootstrapSummary
	if err := json.Unmarshal(bootstrapBytes, &bootstrap); err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(fixture.parent, "client-request.otr")
	result, err := initializeEnrollment(enrollInitOptions{
		stateRoot: fixture.options.stateRoot, routeID: route.String(),
		connectorID: connectorID.String(), validity: time.Hour,
		outputPath: requestPath, now: fixture.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, result)
	assertPathMode(t, requestPath, 0o644)
	requestBytes, err := os.ReadFile(requestPath)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := enrollment.ParseRequest(requestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Role != enrollment.RoleClient || payload.InstallationID != bootstrap.InstallationID || payload.RouteID != route.String() || payload.ConnectorInstallationID != connectorID.String() {
		t.Fatalf("wrong client request scope: %+v", payload)
	}
	var initSummary requestSummary
	if err := json.Unmarshal(result, &initSummary); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(requestBytes)
	if initSummary.Action != "initialized" || initSummary.Sequence != 1 || initSummary.RequestSHA256 != fmtDigest(digest) {
		t.Fatalf("wrong init summary: %+v", initSummary)
	}

	secondPath := filepath.Join(fixture.parent, "client-request-copy.otr")
	pendingBytes, err := exportPending(exportPendingOptions{stateRoot: fixture.options.stateRoot, outputPath: secondPath})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, pendingBytes)
	secondRequest, err := os.ReadFile(secondPath)
	if err != nil || !bytes.Equal(secondRequest, requestBytes) {
		t.Fatal("pending did not re-export the exact request")
	}

	statusBytes, err := readStatus(stateOptions{stateRoot: fixture.options.stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, statusBytes)
	var before statusSummary
	if err := json.Unmarshal(statusBytes, &before); err != nil {
		t.Fatal(err)
	}
	if before.Pending == nil || before.Pending.RequestSHA256 != initSummary.RequestSHA256 || before.Active {
		t.Fatalf("wrong pending status: %+v", before)
	}

	cancelBytes, err := cancelPending(stateOptions{stateRoot: fixture.options.stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, cancelBytes)
	var canceled cancelSummary
	if err := json.Unmarshal(cancelBytes, &canceled); err != nil {
		t.Fatal(err)
	}
	if !canceled.Canceled || canceled.RequestSequenceHighWater != 1 {
		t.Fatalf("wrong cancel summary: %+v", canceled)
	}
	afterBytes, err := readStatus(stateOptions{stateRoot: fixture.options.stateRoot})
	if err != nil {
		t.Fatal(err)
	}
	var after statusSummary
	if err := json.Unmarshal(afterBytes, &after); err != nil {
		t.Fatal(err)
	}
	if after.Pending != nil || after.RequestSequenceHighWater != 1 || after.StateGeneration <= before.StateGeneration {
		t.Fatalf("wrong status after cancellation: %+v", after)
	}
}

func TestEnrollInitRejectsExistingOutputBeforeGeneratingPendingState(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleClient)
	if _, err := bootstrapTarget(fixture.options); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(fixture.parent, "existing-request")
	if err := os.WriteFile(output, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	_, err = initializeEnrollment(enrollInitOptions{
		stateRoot: fixture.options.stateRoot, routeID: route.String(), connectorID: connectorID.String(),
		validity: time.Hour, outputPath: output, now: fixture.now,
	})
	if err == nil {
		t.Fatal("enroll-init accepted an existing output")
	}
	contents, readErr := os.ReadFile(output)
	if readErr != nil || string(contents) != "keep" {
		t.Fatalf("existing output changed: contents=%q err=%v", contents, readErr)
	}
	status, err := enrollmenttarget.ReadStatus(mustResolveStateRoot(t, fixture.options.stateRoot))
	if err != nil {
		t.Fatal(err)
	}
	if status.State.PendingRequest != nil || status.State.RequestSequenceHighWater != 0 {
		t.Fatalf("state changed before output preflight: %+v", status.State)
	}
}

func TestBootstrapRejectsSymlinkedTrustInputAndClientConnectorTarget(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleClient)
	link := filepath.Join(fixture.parent, "outer-ca-link.pem")
	if err := os.Symlink(fixture.options.outerCA, link); err != nil {
		t.Fatal(err)
	}
	fixture.options.outerCA = link
	if _, err := bootstrapTarget(fixture.options); err == nil {
		t.Fatal("bootstrap accepted a symlinked CA")
	}
	if _, err := os.Lstat(fixture.options.stateRoot); !os.IsNotExist(err) {
		t.Fatalf("bootstrap touched state before trust validation: %v", err)
	}

	other := newBootstrapFixture(t, enrollment.RoleClient)
	other.options.connectorTarget = compiledConnectorTarget
	if _, err := bootstrapTarget(other.options); err == nil {
		t.Fatal("client bootstrap accepted a connector target")
	}
	if _, err := os.Lstat(other.options.stateRoot); !os.IsNotExist(err) {
		t.Fatalf("target mismatch touched state: %v", err)
	}
}

func TestConnectorBootstrapUsesOnlyTheCompiledTarget(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleConnector)
	fixture.options.connectorTarget = ""
	if _, err := bootstrapTarget(fixture.options); err != nil {
		t.Fatal(err)
	}
	wrong := newBootstrapFixture(t, enrollment.RoleConnector)
	wrong.options.connectorTarget = "tcp4/127.0.0.1:1"
	if _, err := bootstrapTarget(wrong.options); err == nil {
		t.Fatal("connector bootstrap accepted a target not selected by its build profile")
	}
}

func TestApplyCommitsMatchingOfflineResponseAndEmitsPublicReceipt(t *testing.T) {
	parent := t.TempDir()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	outer, err := pki.NewCA("OwnTransit apply outer CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerConnector, err := pki.NewCA("OwnTransit apply connector CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerClient, err := pki.NewCA("OwnTransit apply client CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	writePublic := func(name string, contents []byte) string {
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	outerPath := writePublic("outer-ca.pem", outer.CertPEM)
	innerConnectorPath := writePublic("inner-connector-ca.pem", innerConnector.CertPEM)
	innerClientPath := writePublic("inner-client-ca.pem", innerClient.CertPEM)
	signerPath := writePublic("deployment-signer.pem", signer.PublicPEM)
	newOptions := func(role enrollment.Role) bootstrapOptions {
		return bootstrapOptions{
			stateRoot: filepath.Join(parent, string(role)+"-state"), role: string(role),
			rollbackAnchor: filepath.Join(parent, string(role)+"-anchor"),
			releaseID:      releaseID.String(), releaseSequence: 1,
			artifactSHA256: strings.Repeat("b", sha256.Size*2),
			goos:           "linux", goarch: "amd64", outerCA: outerPath,
			innerConnectorCA: innerConnectorPath, innerClientCA: innerClientPath,
			deploymentSigner: signerPath, now: now,
		}
	}
	relayOptions := newOptions(enrollment.RoleRelay)
	connectorOptions := newOptions(enrollment.RoleConnector)
	clientOptions := newOptions(enrollment.RoleClient)
	if _, err := bootstrapTarget(relayOptions); err != nil {
		t.Fatal(err)
	}
	connectorBootstrapBytes, err := bootstrapTarget(connectorOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapTarget(clientOptions); err != nil {
		t.Fatal(err)
	}
	var connectorBootstrap bootstrapSummary
	if err := json.Unmarshal(connectorBootstrapBytes, &connectorBootstrap); err != nil {
		t.Fatal(err)
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	request := func(name string, options enrollInitOptions) []byte {
		options.outputPath = filepath.Join(parent, name)
		options.validity = time.Hour
		options.now = now
		if _, err := initializeEnrollment(options); err != nil {
			t.Fatal(err)
		}
		contents, err := os.ReadFile(options.outputPath)
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	relayRequest := request("relay-request.otr", enrollInitOptions{stateRoot: relayOptions.stateRoot})
	connectorRequest := request("connector-request.otr", enrollInitOptions{
		stateRoot: connectorOptions.stateRoot, routeID: route.String(),
	})
	clientRequest := request("client-request.otr", enrollInitOptions{
		stateRoot: clientOptions.stateRoot, routeID: route.String(),
		connectorID: connectorBootstrap.InstallationID,
	})
	responses, err := enrollment.ApproveInitialRoute(enrollment.RouteApproval{
		RelayRequest: relayRequest, ConnectorRequest: connectorRequest, ClientRequest: clientRequest,
		RelayURL: "wss://relay.example.com/connects", RelayListen: enrollment.PackagedRelayListen,
		DeploymentSequence: 1, Now: now, LeafValidity: 24 * time.Hour,
		DeploymentValidity: time.Hour,
		Issuers: enrollment.Issuers{
			RelayAdmission: outer, InnerConnector: innerConnector, InnerClient: innerClient,
		},
		DeploymentSigner: signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}
	responsePath := writePublic("client-response.otre", responses.ClientEnvelope)
	receiptBytes, err := applyResponse(applyOptions{
		stateRoot: clientOptions.stateRoot, responsePath: responsePath, now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretOutput(t, receiptBytes)
	var receipt applySummary
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != "owntransit.ctl.apply.v1" || receipt.Role != enrollment.RoleClient ||
		receipt.InstallationID == "" || receipt.RecordID == "" || receipt.DeploymentSequence != 1 ||
		receipt.CredentialEpoch != 1 || receipt.RequestSHA256 == "" || receipt.StateGeneration <= 1 ||
		!receipt.OneTimeSecretRemoved {
		t.Fatalf("invalid apply receipt: %+v", receipt)
	}
	status, err := enrollmenttarget.ReadStatus(mustResolveStateRoot(t, clientOptions.stateRoot))
	if err != nil {
		t.Fatal(err)
	}
	if status.State.ActiveRecordID != receipt.RecordID || status.State.PendingRequest != nil ||
		status.State.HighestDeploymentSequence != receipt.DeploymentSequence ||
		status.State.HighestCredentialSequence != receipt.CredentialEpoch {
		t.Fatalf("apply receipt does not match target state: receipt=%+v state=%+v", receipt, status.State)
	}
}

func TestApplyRejectsSymlinkedAndOversizedResponseWithoutChangingState(t *testing.T) {
	fixture := newBootstrapFixture(t, enrollment.RoleClient)
	if _, err := bootstrapTarget(fixture.options); err != nil {
		t.Fatal(err)
	}
	response := filepath.Join(fixture.parent, "response.otre")
	if err := os.WriteFile(response, []byte("not an envelope"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(fixture.parent, "response-link.otre")
	if err := os.Symlink(response, link); err != nil {
		t.Fatal(err)
	}
	if _, err := applyResponse(applyOptions{
		stateRoot: fixture.options.stateRoot, responsePath: link, now: fixture.now,
	}); err == nil {
		t.Fatal("apply accepted a symlinked response envelope")
	}
	oversized := filepath.Join(fixture.parent, "oversized-response.otre")
	if err := os.WriteFile(oversized, make([]byte, enrollment.MaxEnvelopeSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := applyResponse(applyOptions{
		stateRoot: fixture.options.stateRoot, responsePath: oversized, now: fixture.now,
	}); err == nil {
		t.Fatal("apply accepted an oversized response envelope")
	}
	status, err := enrollmenttarget.ReadStatus(mustResolveStateRoot(t, fixture.options.stateRoot))
	if err != nil {
		t.Fatal(err)
	}
	if status.State.StateGeneration != 1 || status.State.ActiveRecordID != "" || status.State.PendingRequest != nil {
		t.Fatalf("rejected response changed state: %+v", status.State)
	}
}

type bootstrapFixture struct {
	parent  string
	now     time.Time
	options bootstrapOptions
}

func newBootstrapFixture(t *testing.T, role enrollment.Role) bootstrapFixture {
	t.Helper()
	parent := t.TempDir()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	outer, err := pki.NewCA("OwnTransit test outer CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerConnector, err := pki.NewCA("OwnTransit test connector CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerClient, err := pki.NewCA("OwnTransit test client CA", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	writePublic := func(name string, contents []byte) string {
		path := filepath.Join(parent, name)
		if err := os.WriteFile(path, contents, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	options := bootstrapOptions{
		stateRoot: filepath.Join(parent, "state"), role: string(role),
		rollbackAnchor: filepath.Join(parent, "rollback-anchor"),
		releaseID:      releaseID.String(), releaseSequence: 1,
		artifactSHA256: strings.Repeat("a", sha256.Size*2),
		goos:           "linux", goarch: "amd64",
		outerCA:          writePublic("outer-ca.pem", outer.CertPEM),
		innerConnectorCA: writePublic("inner-connector-ca.pem", innerConnector.CertPEM),
		innerClientCA:    writePublic("inner-client-ca.pem", innerClient.CertPEM),
		deploymentSigner: writePublic("deployment-signer.pem", signer.PublicPEM),
		now:              now,
	}
	return bootstrapFixture{parent: parent, now: now, options: options}
}

func mustResolveStateRoot(t *testing.T, path string) string {
	t.Helper()
	resolved, err := resolveStateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func assertNoSecretOutput(t *testing.T, encoded []byte) {
	t.Helper()
	for _, marker := range []string{"PRIVATE KEY", "AGE-SECRET-KEY", "response.age-identity", "outer-key.pem", "inner-key.pem"} {
		if bytes.Contains(encoded, []byte(marker)) {
			t.Fatalf("public output contains secret marker %q", marker)
		}
	}
}

func assertPathMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func fmtDigest(value [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, current := range value {
		result[index*2] = alphabet[current>>4]
		result[index*2+1] = alphabet[current&0x0f]
	}
	return string(result)
}
