//go:build darwin || linux

package enrollmenttarget

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
)

func TestHeldGenerationNeverReopensSubstitutedRecordPath(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleClient]
	result, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := OpenActiveGeneration(root, enrollment.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	value, err := handle.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	originalKey, err := handle.ReadMaterial(value.OuterTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	recordPath := filepath.Join(root, "record-"+result.RecordID)
	movedPath := filepath.Join(root, "adversary-moved-record")
	if err := os.Rename(recordPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(recordPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(recordPath, outerPrivateKeyFile), []byte("adversary-controlled-path-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	heldKey, err := handle.ReadMaterial(value.OuterTLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(heldKey, originalKey) || bytes.Equal(heldKey, []byte("adversary-controlled-path-bytes")) {
		t.Fatal("held runtime reader followed a substituted generation pathname")
	}
	if err := handle.FinalCheck(); err != nil {
		t.Fatalf("descriptor-pinned generation became invalid after pathname substitution: %v", err)
	}
	if replacement, err := OpenActiveGeneration(root, enrollment.RoleClient); err == nil {
		replacement.Close()
		t.Fatal("a new runtime accepted the substituted record pathname")
	}
}

func TestFinalCheckRejectsHeldGenerationContentMutation(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleClient]
	result, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := OpenActiveGeneration(root, enrollment.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	value, err := handle.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handle.ReadMaterial(value.OuterTLS.KeyFile); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "record-"+result.RecordID, outerPrivateKeyFile)
	if err := os.WriteFile(keyPath, []byte("mutated-after-service-snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := handle.FinalCheck(); err == nil {
		t.Fatal("final pre-network check accepted mutated held generation contents")
	}
}

func TestRollbackCannotResurrectTombstonedClientLeaf(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	for _, role := range []enrollment.Role{enrollment.RoleRelay, enrollment.RoleConnector, enrollment.RoleClient} {
		var envelope []byte
		switch role {
		case enrollment.RoleRelay:
			envelope = fixture.responses.RelayEnvelope
		case enrollment.RoleConnector:
			envelope = fixture.responses.ConnectorEnvelope
		case enrollment.RoleClient:
			envelope = fixture.responses.ClientEnvelope
		}
		if _, err := ApplyResponse(fixture.roots[role], envelope, fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	clientRoot := fixture.roots[enrollment.RoleClient]
	old, err := ReadStatus(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	rotationTime := fixture.now.Add(time.Minute)
	relayRequest, err := InitRequest(RequestOptions{RootPath: fixture.roots[enrollment.RoleRelay], Validity: time.Hour, Now: rotationTime})
	if err != nil {
		t.Fatal(err)
	}
	connectorRequest, err := InitRequest(RequestOptions{RootPath: fixture.roots[enrollment.RoleConnector], RouteID: fixture.route.String(), Validity: time.Hour, Now: rotationTime})
	if err != nil {
		t.Fatal(err)
	}
	clientRequest, err := InitRequest(RequestOptions{
		RootPath: clientRoot, RouteID: fixture.route.String(),
		ConnectorInstallationID: fixture.bootstraps[enrollment.RoleConnector].InstallationID,
		Validity:                time.Hour, Now: rotationTime,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := enrollment.ApproveRouteRotation(enrollment.RouteApproval{
		RelayRequest: relayRequest.RequestBytes, ConnectorRequest: connectorRequest.RequestBytes, ClientRequest: clientRequest.RequestBytes,
		RelayURL: "wss://relay.example.com/connects", RelayListen: enrollment.PackagedRelayListen, DeploymentSequence: 2,
		Now: rotationTime, LeafValidity: 30 * 24 * time.Hour, DeploymentValidity: 24 * time.Hour,
		Issuers: fixture.issuers, DeploymentSigner: fixture.signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyResponse(clientRoot, rotated.ClientEnvelope, rotationTime); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(fixture.responses.ClientDeployment.InnerCertificate))
	if block == nil {
		t.Fatal("old client certificate is not PEM")
	}
	oldCertificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	oldPin, err := identity.SPKIPin(oldCertificate)
	if err != nil {
		t.Fatal(err)
	}
	currentClient, err := LoadClient(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	stateBytes, _ := os.ReadFile(filepath.Join(clientRoot, stateFile))
	current, _ := ReadStatus(clientRoot)
	policy := enrollment.LifecyclePolicy{
		Schema: enrollment.LifecyclePolicySchema, Role: enrollment.RoleClient, InstallationID: current.State.InstallationID, Sequence: 1,
		IssuedUnix: rotationTime.Unix(), ExpiresUnix: rotationTime.Add(time.Hour).Unix(),
		ExpectedStateGeneration: current.State.StateGeneration, ExpectedStateSHA256: digestBytes(stateBytes),
		Trust:                 fixture.responses.ClientDeployment.Trust,
		CapabilityClientRoots: []string{}, RelayServerSPKIPins: append([]string(nil), currentClient.OuterTLS.SPKIPins...),
		ConnectorSPKIPins: append([]string(nil), currentClient.InnerTLS.SPKIPins...),
		RelayClients:      []config.AuthorizedPeer{}, RelayRoutes: []config.RelayRoute{},
		RevokedClientInstallationIDs: []string{}, RevokedClientSPKIPins: []string{oldPin},
	}
	policyBytes, err := enrollment.SignLifecyclePolicy(policy, fixture.signer.Private, rotationTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyLifecyclePolicy(clientRoot, policyBytes, rotationTime); err != nil {
		t.Fatal(err)
	}
	stateBytes, _ = os.ReadFile(filepath.Join(clientRoot, stateFile))
	current, _ = ReadStatus(clientRoot)
	authorization, err := enrollment.SignRollbackAuthorization(enrollment.RollbackAuthorization{
		Schema: enrollment.RollbackAuthorizationSchema, Role: enrollment.RoleClient, InstallationID: current.State.InstallationID,
		Sequence: 1, IssuedUnix: rotationTime.Unix(), ExpiresUnix: rotationTime.Add(time.Hour).Unix(),
		ExpectedStateGeneration: current.State.StateGeneration, ExpectedStateSHA256: digestBytes(stateBytes),
		RecordID: old.State.ActiveRecordID, RecordSHA256: old.State.ActiveRecordSHA256,
		DeploymentSequence: old.State.ActiveDeploymentSequence, CredentialSequence: old.State.ActiveCredentialSequence,
		ReleaseSequence: old.State.ActiveReleaseSequence,
	}, fixture.signer.Private, rotationTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(clientRoot, authorization, rotationTime); err == nil {
		t.Fatal("rollback resurrected a tombstoned client credential")
	}
}

func TestSignedCapabilityRootRotationIsVerifierFirstAndRevocationsPersist(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleConnector]
	if _, err := ApplyResponse(root, fixture.responses.ConnectorEnvelope, fixture.now); err != nil {
		t.Fatal(err)
	}
	original, err := ReadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := OpenActiveGeneration(root, enrollment.RoleConnector)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	newClientRoot, err := pki.NewCA("OwnTransit rotated route client", fixture.now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	policy := connectorPolicy(t, fixture, root, newClientRoot, 1, true)
	encoded, err := enrollment.SignLifecyclePolicy(policy, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	result, err := ApplyLifecyclePolicy(root, encoded, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.PolicySequence != 1 || result.TombstoneSequence != 1 {
		t.Fatalf("unexpected policy receipt: %+v", result)
	}
	if err := handle.FinalCheck(); err == nil {
		t.Fatal("held old generation remained network-eligible after policy advancement")
	}
	connector, err := LoadConnector(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(connector.InnerTLS.ClientCAFiles) != 2 || !connector.InnerTLS.ClientCARotation ||
		len(connector.InnerTLS.RevokedClientIDs) != 1 || connector.InnerTLS.RevokedClientIDs[0] != fixture.bootstraps[enrollment.RoleClient].InstallationID {
		t.Fatalf("verifier-first overlap was not rendered: %+v", connector.InnerTLS)
	}
	currentStateBytes, err := os.ReadFile(filepath.Join(root, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	current, err := ReadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := enrollment.SignRollbackAuthorization(enrollment.RollbackAuthorization{
		Schema: enrollment.RollbackAuthorizationSchema, Role: enrollment.RoleConnector,
		InstallationID: current.State.InstallationID, Sequence: 1,
		IssuedUnix: fixture.now.Unix(), ExpiresUnix: fixture.now.Add(time.Hour).Unix(),
		ExpectedStateGeneration: current.State.StateGeneration, ExpectedStateSHA256: digestBytes(currentStateBytes),
		RecordID: original.State.ActiveRecordID, RecordSHA256: original.State.ActiveRecordSHA256,
		DeploymentSequence: original.State.ActiveDeploymentSequence,
		CredentialSequence: original.State.ActiveCredentialSequence, ReleaseSequence: original.State.ActiveReleaseSequence,
	}, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rollback(root, authorization, fixture.now); err != nil {
		t.Fatal(err)
	}
	connector, err = LoadConnector(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(connector.InnerTLS.ClientCAFiles) != 2 || len(connector.InnerTLS.RevokedClientIDs) != 1 {
		t.Fatalf("rollback resurrected pre-policy verifier state: %+v", connector.InnerTLS)
	}
	if _, err := Rollback(root, authorization, fixture.now); err == nil {
		t.Fatal("rollback authorization replay was accepted")
	}

	retire := connectorPolicy(t, fixture, root, newClientRoot, 2, false)
	retireEncoded, err := enrollment.SignLifecyclePolicy(retire, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyLifecyclePolicy(root, retireEncoded, fixture.now); err != nil {
		t.Fatal(err)
	}
	connector, err = LoadConnector(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(connector.InnerTLS.ClientCAFiles) != 1 || connector.InnerTLS.ClientCARotation || len(connector.InnerTLS.RevokedClientIDs) != 1 {
		t.Fatalf("root retirement forgot overlap state or revocations: %+v", connector.InnerTLS)
	}
}

func TestSignedPolicyRejectsDisjointRootReplacementAndStaleStateBinding(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleConnector]
	if _, err := ApplyResponse(root, fixture.responses.ConnectorEnvelope, fixture.now); err != nil {
		t.Fatal(err)
	}
	newClientRoot, err := pki.NewCA("OwnTransit disjoint route client", fixture.now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	disjoint := connectorPolicy(t, fixture, root, newClientRoot, 1, false)
	encoded, err := enrollment.SignLifecyclePolicy(disjoint, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyLifecyclePolicy(root, encoded, fixture.now); err == nil {
		t.Fatal("connector accepted a one-root-to-disjoint-one-root replacement")
	}

	overlap := connectorPolicy(t, fixture, root, newClientRoot, 1, true)
	overlapEncoded, err := enrollment.SignLifecyclePolicy(overlap, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyLifecyclePolicy(root, overlapEncoded, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyLifecyclePolicy(root, overlapEncoded, fixture.now); err == nil {
		t.Fatal("target replayed a signed policy bound to a stale state generation")
	}
}

func TestConcurrentPolicyCompareAndSwapCommitsExactlyOnce(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleConnector]
	if _, err := ApplyResponse(root, fixture.responses.ConnectorEnvelope, fixture.now); err != nil {
		t.Fatal(err)
	}
	nextRoot, err := pki.NewCA("OwnTransit concurrent route client", fixture.now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	policy := connectorPolicy(t, fixture, root, nextRoot, 1, true)
	encoded, err := enrollment.SignLifecyclePolicy(policy, fixture.signer.Private, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for range 2 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, applyErr := ApplyLifecyclePolicy(root, encoded, fixture.now)
			results <- applyErr
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for applyErr := range results {
		if applyErr == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent policy committed %d times, want exactly once", successes)
	}
	status, err := ReadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	if status.State.PolicySequence != 1 {
		t.Fatalf("concurrent state advanced incorrectly: %+v", status.State)
	}
}

func TestExternalAnchorRejectsRestoredStateAndExactJournalRecovers(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	root := fixture.roots[enrollment.RoleClient]
	statePath := filepath.Join(root, stateFile)
	oldState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CancelPending(root); err != nil {
		t.Fatal(err)
	}
	newState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, transactionStateFile), newState, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, oldState, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(root); err == nil {
		t.Fatal("restored state.json bypassed the external rollback anchor")
	}
	recovered, err := RecoverTransaction(root)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Recovered {
		t.Fatalf("exact journal was not recovered: %+v", recovered)
	}
	status, err := ReadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	if status.State.PendingRequest != nil || len(status.State.ConsumedRequestSHA256) != 1 {
		t.Fatalf("recovery resurrected consumed request state: %+v", status.State)
	}
}

func connectorPolicy(t *testing.T, fixture routeTargetFixture, root string, nextRoot pki.Material, sequence uint64, overlap bool) enrollment.LifecyclePolicy {
	t.Helper()
	stateBytes, err := os.ReadFile(filepath.Join(root, stateFile))
	if err != nil {
		t.Fatal(err)
	}
	status, err := ReadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	connector, err := LoadConnector(root)
	if err != nil {
		t.Fatal(err)
	}
	trust := enrollment.Trust{
		RelayAdmissionCA: fixture.responses.ConnectorDeployment.Trust.RelayAdmissionCA,
		InnerConnectorCA: fixture.responses.ConnectorDeployment.Trust.InnerConnectorCA,
		InnerClientCA:    string(nextRoot.CertPEM),
	}
	roots := []string{string(nextRoot.CertPEM)}
	if overlap {
		roots = append(roots, fixture.responses.ConnectorDeployment.Trust.InnerClientCA)
		pins := make([]struct{ pin, pem string }, len(roots))
		for index, encoded := range roots {
			material := fixture.issuers.InnerClient
			if encoded == string(nextRoot.CertPEM) {
				material = nextRoot
			}
			pin, pinErr := pki.CertificatePin(material.Certificate)
			if pinErr != nil {
				t.Fatal(pinErr)
			}
			pins[index] = struct{ pin, pem string }{pin, encoded}
		}
		sort.Slice(pins, func(i, j int) bool { return pins[i].pin < pins[j].pin })
		for index := range pins {
			roots[index] = pins[index].pem
		}
	}
	return enrollment.LifecyclePolicy{
		Schema: enrollment.LifecyclePolicySchema, Role: enrollment.RoleConnector,
		InstallationID: status.State.InstallationID, Sequence: sequence,
		IssuedUnix: fixture.now.Unix(), ExpiresUnix: fixture.now.Add(time.Hour).Unix(),
		ExpectedStateGeneration: status.State.StateGeneration, ExpectedStateSHA256: digestBytes(stateBytes),
		Trust: trust, CapabilityClientRoots: roots,
		RelayServerSPKIPins: append([]string(nil), connector.OuterTLS.SPKIPins...), ConnectorSPKIPins: []string{},
		RelayClients: []config.AuthorizedPeer{}, RelayRoutes: []config.RelayRoute{},
		RevokedClientInstallationIDs: []string{fixture.bootstraps[enrollment.RoleClient].InstallationID},
		RevokedClientSPKIPins:        []string{},
	}
}
