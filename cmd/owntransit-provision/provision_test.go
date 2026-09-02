package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"golang.org/x/sys/unix"
)

func TestInitAuthorityCreatesOneRouteScopedAuthorityWithoutEndpointKeys(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	directory := filepath.Join(mustCanonicalTempDir(t), "authority")
	summaryBytes, err := initAuthority(initAuthorityOptions{outputDir: directory, now: now})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(summaryBytes, []byte("PRIVATE KEY")) {
		t.Fatal("public authority summary contains private key material")
	}

	var summary authoritySummary
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatalf("decode authority summary: %v", err)
	}
	route, err := protocol.ParseRouteID(summary.RouteID)
	if err != nil || route == (protocol.RouteID{}) || summary.Scope != "single-route" || summary.CreatedUnix != now.Unix() {
		t.Fatalf("invalid authority summary: %+v", summary)
	}
	storedSummary, err := os.ReadFile(filepath.Join(directory, authoritySummaryFile))
	if err != nil || !bytes.Equal(storedSummary, summaryBytes) {
		t.Fatal("stored authority summary does not match stdout summary")
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{
		authoritySummaryFile,
		deploymentSignerKeyFile,
		deploymentSignerPublicFile,
		innerClientIssuerCertFile,
		innerClientIssuerKeyFile,
		innerConnectorCertFile,
		innerConnectorKeyFile,
		outerIssuerCertFile,
		outerIssuerKeyFile,
	}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("authority files = %v, want %v", names, wantNames)
	}
	assertMode(t, directory, 0o700)
	for _, name := range []string{
		outerIssuerKeyFile,
		innerConnectorKeyFile,
		innerClientIssuerKeyFile,
		deploymentSignerKeyFile,
	} {
		assertMode(t, filepath.Join(directory, name), 0o600)
	}
	for _, name := range []string{
		outerIssuerCertFile,
		innerConnectorCertFile,
		innerClientIssuerCertFile,
		deploymentSignerPublicFile,
		authoritySummaryFile,
	} {
		assertMode(t, filepath.Join(directory, name), 0o644)
	}

	issuers := []struct {
		cert    string
		key     string
		purpose string
		pin     string
	}{
		{outerIssuerCertFile, outerIssuerKeyFile, "outer endpoint", summary.OuterEndpointIssuer.CertificatePin},
		{innerConnectorCertFile, innerConnectorKeyFile, "inner connector", summary.InnerConnectorIssuer.CertificatePin},
		{innerClientIssuerCertFile, innerClientIssuerKeyFile, "inner client capability", summary.InnerClientCapability.CertificatePin},
	}
	publicKeys := make([][]byte, 0, 4)
	for _, value := range issuers {
		material, err := pki.LoadIssuer(filepath.Join(directory, value.cert), filepath.Join(directory, value.key), now)
		if err != nil {
			t.Fatalf("load %s issuer: %v", value.purpose, err)
		}
		if material.Certificate.Subject.CommonName != authorityIssuerName(route, value.purpose) {
			t.Fatalf("%s issuer is not route-scoped", value.purpose)
		}
		pin, err := pki.CertificatePin(material.Certificate)
		if err != nil || pin != value.pin {
			t.Fatalf("%s issuer pin = %q, %v", value.purpose, pin, err)
		}
		publicKeys = append(publicKeys, material.Certificate.RawSubjectPublicKeyInfo)
	}
	publicPEM, err := os.ReadFile(filepath.Join(directory, deploymentSignerPublicFile))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := signing.ParsePublic(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM, err := os.ReadFile(filepath.Join(directory, deploymentSignerKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := signing.ParsePrivate(privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	if !publicKey.Equal(privateKey.Public()) || summary.DeploymentSigner.KeyID != signing.KeyID(publicKey) {
		t.Fatal("deployment signer public and private material do not match")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeys = append(publicKeys, publicDER)
	for first := range publicKeys {
		for second := first + 1; second < len(publicKeys); second++ {
			if bytes.Equal(publicKeys[first], publicKeys[second]) {
				t.Fatal("authority reused a key across trust domains")
			}
		}
	}
}

func TestInitAuthorityRefusesExistingOrSymlinkOutput(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	parent := mustCanonicalTempDir(t)
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := initAuthority(initAuthorityOptions{outputDir: existing, now: now}); err == nil {
		t.Fatal("init-authority accepted an existing directory")
	}
	entries, err := os.ReadDir(existing)
	if err != nil || len(entries) != 0 {
		t.Fatalf("existing directory was changed: entries=%v err=%v", entries, err)
	}

	real := filepath.Join(parent, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := initAuthority(initAuthorityOptions{outputDir: link, now: now}); err == nil {
		t.Fatal("init-authority accepted a symlink output")
	}
	entries, err = os.ReadDir(real)
	if err != nil || len(entries) != 0 {
		t.Fatalf("symlink target was changed: entries=%v err=%v", entries, err)
	}
}

func TestApproveInitialRouteWritesOnlyThreeTargetEncryptedResponsesAndPublicDigests(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixture(t, now)
	summaryBytes, err := approveInitialRoute(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(summaryBytes, []byte("PRIVATE KEY")) || bytes.Contains(summaryBytes, []byte("CERTIFICATE")) {
		t.Fatal("public response summary contains credential material")
	}

	var summary routeResponseSummary
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.RouteID != fixture.authority.RouteID || summary.DeploymentSequence != 1 || summary.ApprovedUnix != now.Unix() || len(summary.Responses) != 3 {
		t.Fatalf("invalid response summary: %+v", summary)
	}
	storedSummary, err := os.ReadFile(filepath.Join(fixture.options.outputDir, responseSummaryFile))
	if err != nil || !bytes.Equal(storedSummary, summaryBytes) {
		t.Fatal("stored response summary does not match returned summary")
	}
	assertMode(t, fixture.options.outputDir, 0o700)
	assertMode(t, filepath.Join(fixture.options.outputDir, responseSummaryFile), 0o644)

	entries, err := os.ReadDir(fixture.options.outputDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{clientResponseFile, connectorResponseFile, relayResponseFile, responseSummaryFile}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("response files = %v, want %v", names, wantNames)
	}

	summaryByRole := make(map[enrollment.Role]responseFileSummary, len(summary.Responses))
	for _, file := range summary.Responses {
		summaryByRole[file.Role] = file
	}
	for _, target := range []struct {
		role    enrollment.Role
		file    string
		pending enrollment.PendingMaterial
	}{
		{enrollment.RoleRelay, relayResponseFile, fixture.relay},
		{enrollment.RoleConnector, connectorResponseFile, fixture.connector},
		{enrollment.RoleClient, clientResponseFile, fixture.client},
	} {
		path := filepath.Join(fixture.options.outputDir, target.file)
		assertMode(t, path, 0o600)
		envelope, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(envelope)
		public := summaryByRole[target.role]
		if public.File != target.file || public.SHA256 != hex.EncodeToString(digest[:]) || public.Size != len(envelope) {
			t.Fatalf("wrong digest summary for %s: %+v", target.role, public)
		}
		plaintext, err := enrollment.OpenResponse(envelope, target.pending.ResponseIdentity, fixture.deploymentSigner)
		if err != nil {
			t.Fatalf("open %s response: %v", target.role, err)
		}
		deployment, err := enrollment.ParseBoundDeployment(plaintext, target.pending.RequestBytes, now)
		if err != nil {
			t.Fatalf("parse %s deployment: %v", target.role, err)
		}
		if deployment.Role != target.role || deployment.RouteID != fixture.authority.RouteID {
			t.Fatalf("wrong %s deployment binding: %+v", target.role, deployment)
		}
	}
}

func TestOfflineInvitationOperatorExchangeIsTargetFirstResumableAndCrossBound(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixture(t, now)
	parent := filepath.Dir(fixture.options.outputDir)
	recipientPath := filepath.Join(parent, "recipient.json")
	recipient := recipientRecord{
		Schema: "owntransit.recipient-record.v1", IntendedRecipient: "Example connector custodian",
		IdentityContactReference: "Offline asset register EXAMPLE-42",
	}
	recipientBytes, err := json.Marshal(recipient)
	if err != nil {
		t.Fatal(err)
	}
	recipientBytes = append(recipientBytes, '\n')
	if err := os.WriteFile(recipientPath, recipientBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	bundleRoot := filepath.Join(parent, "invitation")
	runtime := fixture.connector.Payload.Runtime
	issueOptions := issueInvitationOptions{
		authorityDir: filepath.Dir(fixture.options.deploymentSigningKey), role: string(enrollment.RoleConnector),
		releaseID: runtime.ReleaseID, releaseSequence: runtime.ReleaseSequence, artifactSHA256: runtime.ArtifactSHA256,
		goos: runtime.OS, goarch: runtime.Arch, exchangeEndpoint: "wss://relay.example.com/connects/enrollment",
		recipientRecord: recipientPath, outputDir: bundleRoot, now: now,
	}
	summaryBytes, err := issueInvitationBundle(issueOptions)
	if err != nil {
		t.Fatal(err)
	}
	var invitationSummary invitationSummary
	if err := json.Unmarshal(summaryBytes, &invitationSummary); err != nil || invitationSummary.Role != enrollment.RoleConnector || len(invitationSummary.Files) != 3 {
		t.Fatalf("invitation summary=%+v err=%v", invitationSummary, err)
	}
	invitation, err := os.ReadFile(filepath.Join(bundleRoot, invitationFile))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := os.ReadFile(filepath.Join(bundleRoot, operatorReceiptFile))
	if err != nil {
		t.Fatal(err)
	}
	registration, err := os.ReadFile(filepath.Join(bundleRoot, courierRegistrationOut))
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{"invitation": invitation, "courier registration": registration, "public summary": summaryBytes} {
		if bytes.Contains(encoded, []byte(recipient.IntendedRecipient)) || bytes.Contains(encoded, []byte(recipient.IdentityContactReference)) || bytes.Contains(encoded, []byte("PRIVATE KEY")) {
			t.Fatalf("%s leaked offline identity/key material", name)
		}
	}
	if _, err := enrollmentexchange.ParseCourierRegistration(registration, now); err != nil {
		t.Fatalf("parse courier registration: %v", err)
	}
	assertMode(t, bundleRoot, 0o700)
	assertMode(t, filepath.Join(bundleRoot, invitationFile), 0o644)
	assertMode(t, filepath.Join(bundleRoot, operatorReceiptFile), 0o600)
	assertMode(t, filepath.Join(bundleRoot, courierRegistrationOut), 0o600)
	assertMode(t, filepath.Join(bundleRoot, invitationStateFile), 0o600)
	// Missing projections after an interrupted first publication are rebuilt
	// from the exact protected state. No invitation, ciphertext or capability is
	// regenerated on retry.
	if err := os.Remove(filepath.Join(bundleRoot, invitationFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(bundleRoot, exchangeSummaryFile)); err != nil {
		t.Fatal(err)
	}
	issueOptions.now = now.Add(time.Minute)
	resumedBundleSummary, err := issueInvitationBundle(issueOptions)
	if err != nil || !bytes.Equal(resumedBundleSummary, summaryBytes) {
		t.Fatalf("invitation publication resume differs: err=%v", err)
	}
	resumedInvitation, err := os.ReadFile(filepath.Join(bundleRoot, invitationFile))
	if err != nil || !bytes.Equal(resumedInvitation, invitation) {
		t.Fatalf("invitation was regenerated on resume: err=%v", err)
	}
	changed := issueOptions
	changed.artifactSHA256 = strings.Repeat("b", 64)
	if _, err := issueInvitationBundle(changed); err == nil {
		t.Fatal("invitation resume accepted different exact issuance inputs")
	}
	rootOnly := filepath.Join(parent, "root-only-interruption")
	if err := os.Mkdir(rootOnly, 0o700); err != nil {
		t.Fatal(err)
	}
	rootOnlyOptions := issueOptions
	rootOnlyOptions.outputDir = rootOnly
	rootOnlyOptions.now = now
	if _, err := issueInvitationBundle(rootOnlyOptions); err != nil {
		t.Fatalf("root-only issuance interruption did not resume: %v", err)
	}
	cancelInvitation, err := os.ReadFile(filepath.Join(rootOnly, invitationFile))
	if err != nil {
		t.Fatal(err)
	}
	cancelTarget, err := enrollmentexchange.NewTargetSession(cancelInvitation, fixture.connector.RequestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	cancelAction, err := cancelTarget.MailboxAction()
	if err != nil {
		t.Fatal(err)
	}
	cancelRequestPath := filepath.Join(parent, "cancel-request.otreq")
	if err := os.WriteFile(cancelRequestPath, cancelAction.EncryptedRequest, 0o600); err != nil {
		t.Fatal(err)
	}
	cancelRoot := filepath.Join(parent, "cancel-session")
	if _, err := openOperatorSession(operatorOpenOptions{
		receiptPath: filepath.Join(rootOnly, operatorReceiptFile), requestPath: cancelRequestPath, sessionRoot: cancelRoot, now: now,
	}); err != nil {
		t.Fatal(err)
	}
	cancelWords, err := cancelTarget.TargetWords()
	if err != nil {
		t.Fatal(err)
	}
	cancelWords[1] = "wrong"
	if _, err := confirmOperatorSession(operatorConfirmOptions{sessionRoot: cancelRoot, now: now}, strings.NewReader(strings.Join(cancelWords[:], " "))); err == nil {
		t.Fatal("mismatched target words were accepted")
	}
	cancelled, err := enrollmentexchange.LoadOperatorStore(cancelRoot, now)
	if err != nil {
		t.Fatalf("load durably cancelled session: %v", err)
	}
	if cancelled.Phase() != enrollmentexchange.PhaseCancelled {
		t.Fatalf("mismatch phase=%q", cancelled.Phase())
	}
	issueOptions.now = now

	target, err := enrollmentexchange.NewTargetSession(invitation, fixture.connector.RequestBytes, now)
	if err != nil {
		t.Fatal(err)
	}
	action, err := target.MailboxAction()
	if err != nil {
		t.Fatal(err)
	}
	encryptedRequestPath := filepath.Join(parent, "encrypted-request.otreq")
	if err := os.WriteFile(encryptedRequestPath, action.EncryptedRequest, 0o600); err != nil {
		t.Fatal(err)
	}
	operatorRoot := filepath.Join(parent, "operator-session")
	operatorSummaryBytes, err := openOperatorSession(operatorOpenOptions{
		receiptPath: filepath.Join(bundleRoot, operatorReceiptFile), requestPath: encryptedRequestPath,
		sessionRoot: operatorRoot, now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	var operatorSummary operatorSessionSummary
	if err := json.Unmarshal(operatorSummaryBytes, &operatorSummary); err != nil {
		t.Fatal(err)
	}
	if operatorSummary.Role != enrollment.RoleConnector || operatorSummary.InstallationID != fixture.connector.Payload.InstallationID ||
		operatorSummary.RouteID != fixture.authority.RouteID || operatorSummary.IntendedRecipient != recipient.IntendedRecipient ||
		operatorSummary.IdentityContactReference != recipient.IdentityContactReference || operatorSummary.Request.File != operatorRequestFile {
		t.Fatalf("operator review summary = %+v", operatorSummary)
	}
	exportedRequest, err := os.ReadFile(filepath.Join(operatorRoot, operatorRequestFile))
	if err != nil || !bytes.Equal(exportedRequest, fixture.connector.RequestBytes) {
		t.Fatalf("exported verified request differs: err=%v", err)
	}
	assertMode(t, filepath.Join(operatorRoot, operatorRequestFile), 0o600)
	// Opening the same immutable exchange is an exact resume; no request is
	// regenerated and the public review stays byte-for-byte canonical.
	resumedSummary, err := openOperatorSession(operatorOpenOptions{
		receiptPath: filepath.Join(bundleRoot, operatorReceiptFile), requestPath: encryptedRequestPath,
		sessionRoot: operatorRoot, now: now,
	})
	if err != nil || !bytes.Equal(resumedSummary, operatorSummaryBytes) {
		t.Fatalf("operator resume differs: err=%v", err)
	}

	targetWords, err := target.TargetWords()
	if err != nil {
		t.Fatal(err)
	}
	reverseBytes, err := confirmOperatorSession(operatorConfirmOptions{sessionRoot: operatorRoot, now: now}, strings.NewReader(strings.Join(targetWords[:], " ")+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	// A crash after durable confirmation resumes by revealing the same reverse
	// words without reading or accepting another target-word input.
	resumedReverse, err := confirmOperatorSession(operatorConfirmOptions{sessionRoot: operatorRoot, now: now}, nil)
	if err != nil || !bytes.Equal(resumedReverse, reverseBytes) {
		t.Fatalf("confirmed resume differs: err=%v", err)
	}
	reverseWords, err := readComparisonWords(bytes.NewReader(reverseBytes))
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := target.ConfirmProvisionerWords(reverseWords); err != nil || outcome != enrollmentexchange.OutcomeConfirmed {
		t.Fatalf("target reverse confirmation=%q err=%v", outcome, err)
	}

	if _, err := approveInitialRoute(fixture.options); err != nil {
		t.Fatal(err)
	}
	boundRoot := filepath.Join(parent, "bound-response")
	bindOptions := operatorBindOptions{
		sessionRoot: operatorRoot, responsePath: filepath.Join(fixture.options.outputDir, connectorResponseFile),
		relayRequest: fixture.options.relayRequest, connectorRequest: fixture.options.connectorRequest, clientRequest: fixture.options.clientRequest,
		deploymentSignerKey: fixture.options.deploymentSigningKey, outputDir: boundRoot, now: now,
	}
	boundSummaryBytes, err := bindOperatorResponse(bindOptions)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(boundSummaryBytes, receipt) || bytes.Contains(boundSummaryBytes, []byte(recipient.IntendedRecipient)) {
		t.Fatal("bound public summary leaked private operator state")
	}
	if err := os.Remove(filepath.Join(boundRoot, exchangeSummaryFile)); err != nil {
		t.Fatal(err)
	}
	resumedBoundSummary, err := bindOperatorResponse(bindOptions)
	if err != nil || !bytes.Equal(resumedBoundSummary, boundSummaryBytes) {
		t.Fatalf("bound response publication did not resume exactly: err=%v", err)
	}
	bound, err := os.ReadFile(filepath.Join(boundRoot, boundResponseFile))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := target.AcceptBoundResponse(bound)
	if err != nil {
		t.Fatal(err)
	}
	rawResponse, err := os.ReadFile(filepath.Join(fixture.options.outputDir, connectorResponseFile))
	if err != nil || !bytes.Equal(accepted, rawResponse) {
		t.Fatalf("accepted inner response differs: err=%v", err)
	}

	// A different approved connector request must never be cross-bound into the
	// already-confirmed operator transcript.
	other := newApprovalFixture(t, now)
	if _, err := bindOperatorResponse(operatorBindOptions{
		sessionRoot: operatorRoot, responsePath: filepath.Join(fixture.options.outputDir, connectorResponseFile),
		relayRequest: other.options.relayRequest, connectorRequest: other.options.connectorRequest, clientRequest: other.options.clientRequest,
		deploymentSignerKey: fixture.options.deploymentSigningKey, outputDir: filepath.Join(parent, "cross-wired"), now: now,
	}); err == nil {
		t.Fatal("operator bind accepted a request set that omitted the exact session request")
	}
}

func TestApproveInitialRouteRejectsSymlinkedSignerBeforeCreatingOutput(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixture(t, now)
	link := filepath.Join(filepath.Dir(fixture.options.deploymentSigningKey), "signer-link.pem")
	if err := os.Symlink(fixture.options.deploymentSigningKey, link); err != nil {
		t.Fatal(err)
	}
	fixture.options.deploymentSigningKey = link
	if _, err := approveInitialRoute(fixture.options); err == nil {
		t.Fatal("approval accepted a symlinked deployment key")
	}
	if _, err := os.Lstat(fixture.options.outputDir); !os.IsNotExist(err) {
		t.Fatalf("approval touched output before validation: %v", err)
	}
}

func TestApproveInitialRouteRejectsIssuerScopedToAnotherRoute(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixture(t, now)
	otherDirectory := filepath.Join(mustCanonicalTempDir(t), "other-authority")
	if _, err := initAuthority(initAuthorityOptions{outputDir: otherDirectory, now: now}); err != nil {
		t.Fatal(err)
	}
	fixture.options.innerClientIssuerCert = filepath.Join(otherDirectory, innerClientIssuerCertFile)
	fixture.options.innerClientIssuerKey = filepath.Join(otherDirectory, innerClientIssuerKeyFile)
	if _, err := approveInitialRoute(fixture.options); err == nil || !strings.Contains(err.Error(), "scoped to a different route") {
		t.Fatalf("route-mismatched authority result = %v", err)
	}
	if _, err := os.Lstat(fixture.options.outputDir); !os.IsNotExist(err) {
		t.Fatalf("approval touched output before route-scope validation: %v", err)
	}
}

func TestApproveInitialRouteRefusesExistingOutputWithoutChangingIt(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixture(t, now)
	if err := os.Mkdir(fixture.options.outputDir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(fixture.options.outputDir, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := approveInitialRoute(fixture.options); err == nil {
		t.Fatal("approval accepted an existing output directory")
	}
	contents, err := os.ReadFile(marker)
	if err != nil || string(contents) != "keep" {
		t.Fatalf("existing output was changed: contents=%q err=%v", contents, err)
	}
}

func TestOfflineLifecycleSigningIsStrictAtomicAndContainsNoPrivateMaterial(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newLifecycleSigningFixture(t, now)
	parent := mustCanonicalTempDir(t)
	keyPath := filepath.Join(parent, "deployment-key.pem")
	if err := os.WriteFile(keyPath, fixture.signer.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(parent, "policy.json")
	policyJSON, err := json.Marshal(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(policyPath, policyJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	policyOutput := filepath.Join(parent, "policy.signed.json")
	summary, err := signLifecyclePolicy(signLifecyclePolicyOptions{
		policyPath: policyPath, signingKey: keyPath, outputPath: policyOutput, now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(summary, fixture.signer.PrivatePEM) || bytes.Contains(summary, []byte("PRIVATE KEY")) {
		t.Fatal("public policy summary contains signing-key material")
	}
	signedPolicy, err := os.ReadFile(policyOutput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.VerifyLifecyclePolicy(signedPolicy, fixture.signer.Public, now); err != nil {
		t.Fatalf("verify signed lifecycle policy: %v", err)
	}
	assertMode(t, policyOutput, 0o644)
	var stat unix.Stat_t
	if err := unix.Stat(policyOutput, &stat); err != nil || stat.Nlink != 1 {
		t.Fatalf("signed lifecycle output link count = %d, err=%v", stat.Nlink, err)
	}

	rollbackPath := filepath.Join(parent, "rollback.json")
	rollbackJSON, err := json.Marshal(fixture.rollback)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rollbackPath, rollbackJSON, 0o644); err != nil {
		t.Fatal(err)
	}
	rollbackOutput := filepath.Join(parent, "rollback.signed.json")
	summary, err = signRollbackAuthorization(signRollbackOptions{
		authorizationPath: rollbackPath, signingKey: keyPath, outputPath: rollbackOutput, now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(summary, fixture.signer.PrivatePEM) || bytes.Contains(summary, []byte("PRIVATE KEY")) {
		t.Fatal("public rollback summary contains signing-key material")
	}
	signedRollback, err := os.ReadFile(rollbackOutput)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.VerifyRollbackAuthorization(signedRollback, fixture.signer.Public, now); err != nil {
		t.Fatalf("verify signed rollback authorization: %v", err)
	}
	assertMode(t, rollbackOutput, 0o644)

	keepPath := filepath.Join(parent, "keep.signed.json")
	if err := os.WriteFile(keepPath, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := signLifecyclePolicy(signLifecyclePolicyOptions{
		policyPath: policyPath, signingKey: keyPath, outputPath: keepPath, now: now,
	}); err == nil {
		t.Fatal("sign-lifecycle-policy replaced an existing output")
	}
	if kept, err := os.ReadFile(keepPath); err != nil || string(kept) != "keep" {
		t.Fatalf("existing output changed: %q, %v", kept, err)
	}
}

func TestOfflineLifecycleSigningRejectsUnknownFieldsLooseKeysAndSymlinks(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newLifecycleSigningFixture(t, now)
	parent := mustCanonicalTempDir(t)
	keyPath := filepath.Join(parent, "deployment-key.pem")
	if err := os.WriteFile(keyPath, fixture.signer.PrivatePEM, 0o644); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(parent, "policy.json")
	valid, err := json.Marshal(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(",\"unexpected\":true}")...)
	if err := os.WriteFile(policyPath, unknown, 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(parent, "policy.signed.json")
	if _, err := signLifecyclePolicy(signLifecyclePolicyOptions{
		policyPath: policyPath, signingKey: keyPath, outputPath: output, now: now,
	}); err == nil {
		t.Fatal("sign-lifecycle-policy accepted an unknown field")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected policy created output: %v", err)
	}
	if err := os.WriteFile(policyPath, valid, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := signLifecyclePolicy(signLifecyclePolicyOptions{
		policyPath: policyPath, signingKey: keyPath, outputPath: output, now: now,
	}); err == nil {
		t.Fatal("sign-lifecycle-policy accepted a group/world-readable private key")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	keyLink := filepath.Join(parent, "deployment-key-link.pem")
	if err := os.Symlink(keyPath, keyLink); err != nil {
		t.Fatal(err)
	}
	if _, err := signLifecyclePolicy(signLifecyclePolicyOptions{
		policyPath: policyPath, signingKey: keyLink, outputPath: output, now: now,
	}); err == nil {
		t.Fatal("sign-lifecycle-policy followed a private-key symlink")
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		t.Fatalf("rejected signer created output: %v", err)
	}
}

func TestApproveRouteRotationRequiresPostInitialRequestsAndSequence(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	fixture := newApprovalFixtureAtSequence(t, now, 2)
	fixture.options.deploymentSequence = 2
	summaryBytes, err := approveRouteRotation(fixture.options)
	if err != nil {
		t.Fatal(err)
	}
	var summary routeResponseSummary
	if err := json.Unmarshal(summaryBytes, &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "owntransit.provision.route-rotation-responses.v1" || summary.DeploymentSequence != 2 {
		t.Fatalf("invalid rotation summary: %+v", summary)
	}
	for _, target := range []struct {
		name    string
		pending enrollment.PendingMaterial
	}{
		{relayResponseFile, fixture.relay},
		{connectorResponseFile, fixture.connector},
		{clientResponseFile, fixture.client},
	} {
		envelope, err := os.ReadFile(filepath.Join(fixture.options.outputDir, target.name))
		if err != nil {
			t.Fatal(err)
		}
		plaintext, err := enrollment.OpenResponse(envelope, target.pending.ResponseIdentity, fixture.deploymentSigner)
		if err != nil {
			t.Fatal(err)
		}
		deployment, err := enrollment.ParseBoundDeployment(plaintext, target.pending.RequestBytes, now)
		if err != nil {
			t.Fatal(err)
		}
		if deployment.DeploymentSequence != 2 || deployment.CredentialEpoch != 2 {
			t.Fatalf("rotation tuple = deployment %d credential %d", deployment.DeploymentSequence, deployment.CredentialEpoch)
		}
	}

	initial := newApprovalFixture(t, now)
	initial.options.deploymentSequence = 2
	if _, err := approveRouteRotation(initial.options); err == nil {
		t.Fatal("rotation accepted first-sequence requests")
	}
}

type lifecycleSigningFixture struct {
	signer   signing.KeyPair
	policy   enrollment.LifecyclePolicy
	rollback enrollment.RollbackAuthorization
}

func newLifecycleSigningFixture(t *testing.T, now time.Time) lifecycleSigningFixture {
	t.Helper()
	relayCA, err := pki.NewCA("OwnTransit policy relay", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCA, err := pki.NewCA("OwnTransit policy client", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	connectorCA, err := pki.NewCA("OwnTransit policy connector", now, 60*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	installation, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	record, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	pin := identity.FormatSPKIPin(identity.SPKIHash{1})
	trust := enrollment.Trust{
		RelayAdmissionCA: string(relayCA.CertPEM), InnerClientCA: string(clientCA.CertPEM),
		InnerConnectorCA: string(connectorCA.CertPEM),
	}
	return lifecycleSigningFixture{
		signer: signer,
		policy: enrollment.LifecyclePolicy{
			Schema: enrollment.LifecyclePolicySchema, Role: enrollment.RoleClient,
			InstallationID: installation.String(), Sequence: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
			ExpectedStateGeneration: 7, ExpectedStateSHA256: strings.Repeat("a", sha256.Size*2), Trust: trust,
			CapabilityClientRoots: []string{}, RelayServerSPKIPins: []string{pin}, ConnectorSPKIPins: []string{pin},
			RelayClients: []config.AuthorizedPeer{}, RelayRoutes: []config.RelayRoute{},
			RevokedClientInstallationIDs: []string{}, RevokedClientSPKIPins: []string{},
		},
		rollback: enrollment.RollbackAuthorization{
			Schema: enrollment.RollbackAuthorizationSchema, Role: enrollment.RoleClient,
			InstallationID: installation.String(), Sequence: 1, IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(),
			ExpectedStateGeneration: 7, ExpectedStateSHA256: strings.Repeat("a", sha256.Size*2),
			RecordID: record.String(), RecordSHA256: strings.Repeat("b", sha256.Size*2),
			DeploymentSequence: 1, CredentialSequence: 1, ReleaseSequence: 1,
		},
	}
}

type approvalFixture struct {
	options          approveInitialRouteOptions
	authority        authoritySummary
	deploymentSigner ed25519.PublicKey
	relay            enrollment.PendingMaterial
	connector        enrollment.PendingMaterial
	client           enrollment.PendingMaterial
}

func mustCanonicalTempDir(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	return directory
}

func newApprovalFixture(t *testing.T, now time.Time) approvalFixture {
	return newApprovalFixtureAtSequence(t, now, 1)
}

func newApprovalFixtureAtSequence(t *testing.T, now time.Time, sequence uint64) approvalFixture {
	t.Helper()
	parent := mustCanonicalTempDir(t)
	authorityDir := filepath.Join(parent, "authority")
	authorityBytes, err := initAuthority(initAuthorityOptions{outputDir: authorityDir, now: now})
	if err != nil {
		t.Fatal(err)
	}
	var authority authoritySummary
	if err := json.Unmarshal(authorityBytes, &authority); err != nil {
		t.Fatal(err)
	}
	outerCA, err := os.ReadFile(filepath.Join(authorityDir, outerIssuerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	innerConnectorCA, err := os.ReadFile(filepath.Join(authorityDir, innerConnectorCertFile))
	if err != nil {
		t.Fatal(err)
	}
	innerClientCA, err := os.ReadFile(filepath.Join(authorityDir, innerClientIssuerCertFile))
	if err != nil {
		t.Fatal(err)
	}
	publicPEM, err := os.ReadFile(filepath.Join(authorityDir, deploymentSignerPublicFile))
	if err != nil {
		t.Fatal(err)
	}
	deploymentSigner, err := signing.ParsePublic(publicPEM)
	if err != nil {
		t.Fatal(err)
	}
	trust := enrollment.Trust{
		RelayAdmissionCA: string(outerCA),
		InnerConnectorCA: string(innerConnectorCA),
		InnerClientCA:    string(innerClientCA),
	}
	releaseID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	relayID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	connectorID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	clientID, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	runtime := func(role enrollment.Role) enrollment.RuntimeBinding {
		value := enrollment.RuntimeBinding{
			ReleaseID: releaseID.String(), ReleaseSequence: 1,
			ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
			OS:             "linux", Arch: "amd64", Role: role,
			Protocol:            enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		}
		if role == enrollment.RoleConnector {
			value.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
		}
		return value
	}
	request := func(role enrollment.Role, installationID, routeID, connectorInstallationID string) enrollment.PendingMaterial {
		pending, err := enrollment.NewPendingRequest(enrollment.InitOptions{
			Role: role, InstallationID: installationID, RouteID: routeID,
			ConnectorInstallationID: connectorInstallationID, Sequence: sequence,
			Now: now, RequestValidity: time.Hour, Trust: trust,
			DeploymentSigner: deploymentSigner, Runtime: runtime(role),
		})
		if err != nil {
			t.Fatalf("create %s request: %v", role, err)
		}
		return pending
	}
	relay := request(enrollment.RoleRelay, relayID.String(), "", "")
	connector := request(enrollment.RoleConnector, connectorID.String(), authority.RouteID, "")
	client := request(enrollment.RoleClient, clientID.String(), authority.RouteID, connectorID.String())
	requestDir := filepath.Join(parent, "requests")
	if err := os.Mkdir(requestDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeRequest := func(name string, encoded []byte) string {
		path := filepath.Join(requestDir, name)
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return approvalFixture{
		authority: authority, deploymentSigner: deploymentSigner,
		relay: relay, connector: connector, client: client,
		options: approveInitialRouteOptions{
			relayRequest:             writeRequest("relay.otr", relay.RequestBytes),
			connectorRequest:         writeRequest("connector.otr", connector.RequestBytes),
			clientRequest:            writeRequest("client.otr", client.RequestBytes),
			outerIssuerCert:          filepath.Join(authorityDir, outerIssuerCertFile),
			outerIssuerKey:           filepath.Join(authorityDir, outerIssuerKeyFile),
			innerConnectorIssuerCert: filepath.Join(authorityDir, innerConnectorCertFile),
			innerConnectorIssuerKey:  filepath.Join(authorityDir, innerConnectorKeyFile),
			innerClientIssuerCert:    filepath.Join(authorityDir, innerClientIssuerCertFile),
			innerClientIssuerKey:     filepath.Join(authorityDir, innerClientIssuerKeyFile),
			deploymentSigningKey:     filepath.Join(authorityDir, deploymentSignerKeyFile),
			relayURL:                 "wss://relay.example.com/connects", relayListen: enrollment.PackagedRelayListen,
			outputDir: filepath.Join(parent, "responses"), now: now,
		},
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}

func FuzzComparisonWordInputIsStrictAndBounded(f *testing.F) {
	f.Add([]byte("alpha bravo charlie\n"))
	f.Add([]byte("one two"))
	f.Add(bytes.Repeat([]byte("x"), 257))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		words, err := readComparisonWords(bytes.NewReader(encoded))
		if err == nil {
			if len(strings.Fields(string(encoded))) != len(words) {
				t.Fatal("accepted a comparison input without exactly three fields")
			}
		}
	})
}

func FuzzInvitationResumeStateFailsClosed(f *testing.F) {
	f.Add([]byte("{}\n"))
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		_, _, _ = parseInvitationResumeState(encoded, strings.Repeat("a", 64), enrollment.RoleConnector, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	})
}
