//go:build darwin || linux

package enrollmenttarget

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

func TestBootstrapRejectsDistinctCACertificatesThatReuseOneKey(t *testing.T) {
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	outer, err := pki.NewCA("OwnTransit reused-key outer", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reusedKeyCertificate := *outer.Certificate
	reusedKeyCertificate.SerialNumber = new(big.Int).Add(outer.Certificate.SerialNumber, big.NewInt(1))
	reusedKeyCertificate.Subject.CommonName = "OwnTransit reused-key connector"
	reusedKeyCertificate.RawSubject = nil
	encoded, err := x509.CreateCertificate(
		rand.Reader,
		&reusedKeyCertificate,
		&reusedKeyCertificate,
		outer.Signer.Public(),
		outer.Signer,
	)
	if err != nil {
		t.Fatal(err)
	}
	reusedKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	innerClient, err := pki.NewCA("OwnTransit distinct client", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	release, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "reused-authority-state")
	if _, err := Bootstrap(BootstrapOptions{
		RootPath:           root,
		RollbackAnchorRoot: root + "-anchor",
		Role:               enrollment.RoleRelay,
		Runtime: enrollment.RuntimeBinding{
			ReleaseID: release.String(), ReleaseSequence: 1,
			ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
			OS:             "linux", Arch: "amd64", Role: enrollment.RoleRelay,
			Protocol:            enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		},
		Trust: enrollment.Trust{
			RelayAdmissionCA: string(outer.CertPEM), InnerConnectorCA: string(reusedKeyPEM),
			InnerClientCA: string(innerClient.CertPEM),
		},
		DeploymentSignerPublicPEM: signer.PublicPEM,
		Now:                       now,
	}); err == nil {
		t.Fatal("bootstrap accepted two route authorities backed by one key")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("rejected bootstrap created a state root: %v", err)
	}
}

func TestApplyRejectsRoleSubstitutionThenCommitsOnceAcrossReopen(t *testing.T) {
	fixture := newRouteTargetFixture(t)
	clientRoot := fixture.roots[enrollment.RoleClient]
	clientRequest := fixture.requests[enrollment.RoleClient]
	before, err := ReadStatus(clientRoot)
	if err != nil {
		t.Fatal(err)
	}

	clientPayload, err := enrollment.ParseRequest(clientRequest.RequestBytes, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	wrongPlaintext, err := enrollment.EncodeDeployment(fixture.responses.ConnectorDeployment)
	if err != nil {
		t.Fatal(err)
	}
	wrongEnvelope, err := enrollment.SealResponse(wrongPlaintext, clientPayload.ResponseRecipient, fixture.signer.Private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyResponse(clientRoot, wrongEnvelope, fixture.now); err == nil {
		t.Fatal("client target accepted a correctly encrypted connector deployment")
	}
	afterWrongRole, err := ReadStatus(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterWrongRole.State, before.State) {
		t.Fatalf("rejected response changed state:\n before=%+v\n after=%+v", before.State, afterWrongRole.State)
	}

	result, err := ApplyResponse(clientRoot, fixture.responses.ClientEnvelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Role != enrollment.RoleClient || result.InstallationID != fixture.bootstraps[enrollment.RoleClient].InstallationID ||
		result.RecordID != clientRequest.RecordID || result.DeploymentSequence != 1 || result.CredentialEpoch != 1 ||
		result.RequestSHA256 != clientRequest.RequestSHA256 || result.StateGeneration != before.State.StateGeneration+1 ||
		!result.OneTimeSecretRemoved {
		t.Fatalf("invalid apply receipt: %+v", result)
	}
	value, err := LoadClient(clientRoot)
	if err != nil {
		t.Fatalf("load client after reopening state: %v", err)
	}
	if value.InstallationID != result.InstallationID || value.RouteID != fixture.route.String() ||
		value.ConnectorInstallationID != fixture.bootstraps[enrollment.RoleConnector].InstallationID || value.CredentialEpoch != 1 {
		t.Fatalf("active client config is not target-bound: %+v", value)
	}
	path, err := ClientConfigPath(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(clientRoot, "record-"+result.RecordID, runtimeConfigFile)
	if path != wantPath {
		t.Fatalf("client config path = %q, want %q", path, wantPath)
	}
	if _, err := os.Lstat(filepath.Join(clientRoot, "record-"+result.RecordID, responseIdentityFile)); !os.IsNotExist(err) {
		t.Fatalf("one-time response identity remains after apply: %v", err)
	}

	committed, err := ReadStatus(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyResponse(clientRoot, fixture.responses.ClientEnvelope, fixture.now); err == nil {
		t.Fatal("target accepted an already committed response")
	}
	afterReplay, err := ReadStatus(clientRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(afterReplay.State, committed.State) {
		t.Fatalf("response replay changed state:\n before=%+v\n after=%+v", committed.State, afterReplay.State)
	}
}

func TestEveryRoleLoadsItsManifestVerifiedGenerationAfterReopen(t *testing.T) {
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
			t.Fatalf("apply %s: %v", role, err)
		}
	}

	relay, err := LoadRelay(fixture.roots[enrollment.RoleRelay])
	if err != nil {
		t.Fatal(err)
	}
	if relay.Path != config.RelayPath || len(relay.Routes) != 1 || relay.Routes[0].RouteID != fixture.route.String() {
		t.Fatalf("unsafe active relay config: %+v", relay)
	}
	connector, err := LoadConnector(fixture.roots[enrollment.RoleConnector])
	if err != nil {
		t.Fatal(err)
	}
	if connector.SSHTarget != config.ConnectorSSHTarget ||
		connector.InnerProfile != config.InnerProfileRouteCapability || connector.RouteID != fixture.route.String() {
		t.Fatalf("unsafe active connector config: %+v", connector)
	}
	client, err := LoadClient(fixture.roots[enrollment.RoleClient])
	if err != nil {
		t.Fatal(err)
	}
	if client.InnerProfile != config.InnerProfileRouteCapability || client.RouteID != fixture.route.String() {
		t.Fatalf("unsafe active client config: %+v", client)
	}
	if _, err := LoadConnector(fixture.roots[enrollment.RoleClient]); err == nil {
		t.Fatal("connector loader accepted a client state root")
	}
}

func TestActiveGenerationRejectsContentLinksAndDirectorySubstitution(t *testing.T) {
	t.Run("symlinked parent spelling is canonicalized", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleClient]
		result, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(filepath.Dir(fixture.parent), "state-parent-alias")
		if err := os.Symlink(fixture.parent, alias); err != nil {
			t.Fatal(err)
		}
		spelledRoot := filepath.Join(alias, filepath.Base(root))
		if _, err := LoadClient(spelledRoot); err != nil {
			t.Fatalf("load through symlinked parent spelling: %v", err)
		}
		path, err := ClientConfigPath(spelledRoot)
		if err != nil {
			t.Fatalf("config path through symlinked parent spelling: %v", err)
		}
		want := filepath.Join(root, "record-"+result.RecordID, runtimeConfigFile)
		if path != want {
			t.Fatalf("canonical config path = %q, want %q", path, want)
		}
	})

	t.Run("content tamper", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleConnector]
		result, err := ApplyResponse(root, fixture.responses.ConnectorEnvelope, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "record-"+result.RecordID, runtimeConfigFile)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(contents, ' '), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConnector(root); err == nil {
			t.Fatal("active loader accepted a config that differs from its manifest")
		}
	})

	t.Run("hardlinked runtime file", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleConnector]
		result, err := ApplyResponse(root, fixture.responses.ConnectorEnvelope, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "record-"+result.RecordID, runtimeConfigFile)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(fixture.parent, "outside-config.json")
		if err := os.WriteFile(outside, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(outside, path); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConnector(root); err == nil {
			t.Fatal("active loader accepted a multiply linked runtime file")
		}
	})

	t.Run("symlinked record directory", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleClient]
		result, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now)
		if err != nil {
			t.Fatal(err)
		}
		record := filepath.Join(root, "record-"+result.RecordID)
		saved := filepath.Join(root, "saved-record")
		if err := os.Rename(record, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(saved), record); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadClient(root); err == nil {
			t.Fatal("active loader followed a substituted record-directory symlink")
		}
	})

	t.Run("symlinked root", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleRelay]
		if _, err := ApplyResponse(root, fixture.responses.RelayEnvelope, fixture.now); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(fixture.parent, "relay-root-link")
		if err := os.Symlink(root, link); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRelay(link); err == nil {
			t.Fatal("active loader followed a state-root symlink")
		}
	})
}

func TestApplyRejectsTamperedPendingMaterialWithoutChangingState(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(*testing.T, routeTargetFixture, string)
	}{
		{
			name: "request bytes",
			tamper: func(t *testing.T, fixture routeTargetFixture, record string) {
				path := filepath.Join(record, requestFile)
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(contents, ' '), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlinked outer key",
			tamper: func(t *testing.T, fixture routeTargetFixture, record string) {
				path := filepath.Join(record, outerPrivateKeyFile)
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(fixture.parent, "linked-outer-key.pem")
				if err := os.WriteFile(outside, contents, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(outside, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "symlinked response identity",
			tamper: func(t *testing.T, _ routeTargetFixture, record string) {
				path := filepath.Join(record, responseIdentityFile)
				saved := filepath.Join(record, "saved-response.age-identity")
				if err := os.Rename(path, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Base(saved), path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRouteTargetFixture(t)
			root := fixture.roots[enrollment.RoleClient]
			request := fixture.requests[enrollment.RoleClient]
			before, err := ReadStatus(root)
			if err != nil {
				t.Fatal(err)
			}
			record := filepath.Join(root, "record-"+request.RecordID)
			test.tamper(t, fixture, record)
			if _, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now); err == nil {
				t.Fatal("apply accepted tampered target-only pending material")
			}
			after, err := ReadStatus(root)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after.State, before.State) {
				t.Fatalf("rejected pending-material tamper changed durable state:\n before=%+v\n after=%+v", before.State, after.State)
			}
		})
	}
}

func TestStateAndPendingFilesRejectLinksAndCancelConsumesResponse(t *testing.T) {
	t.Run("state hardlink", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleRelay]
		if err := os.Link(filepath.Join(root, stateFile), filepath.Join(root, "state-copy.json")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadStatus(root); err == nil {
			t.Fatal("status accepted a multiply linked durable state file")
		}
	})

	t.Run("pending request symlink", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleClient]
		request := fixture.requests[enrollment.RoleClient]
		record := filepath.Join(root, "record-"+request.RecordID)
		original := filepath.Join(record, requestFile)
		saved := filepath.Join(record, "saved-request.json")
		if err := os.Rename(original, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Base(saved), original); err != nil {
			t.Fatal(err)
		}
		if _, err := PendingRequest(root); err == nil {
			t.Fatal("pending export followed a request symlink")
		}
	})

	t.Run("cancel and replay", func(t *testing.T) {
		fixture := newRouteTargetFixture(t)
		root := fixture.roots[enrollment.RoleClient]
		request := fixture.requests[enrollment.RoleClient]
		pending, err := PendingRequest(root)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pending.RequestBytes, request.RequestBytes) ||
			bytes.Contains(pending.RequestBytes, []byte("PRIVATE KEY")) || bytes.Contains(pending.RequestBytes, []byte("AGE-SECRET-KEY")) {
			t.Fatal("pending export changed the request or exposed target-only secrets")
		}
		state, err := CancelPending(root)
		if err != nil {
			t.Fatal(err)
		}
		if state.PendingRequest != nil || len(state.ConsumedRequestSHA256) != 1 || state.ConsumedRequestSHA256[0] != request.RequestSHA256 {
			t.Fatalf("cancel did not durably consume request: %+v", state)
		}
		if _, err := os.Lstat(filepath.Join(root, "record-"+request.RecordID)); !os.IsNotExist(err) {
			t.Fatalf("canceled secret record remains after successful cleanup: %v", err)
		}
		beforeReplay, err := ReadStatus(root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyResponse(root, fixture.responses.ClientEnvelope, fixture.now); err == nil {
			t.Fatal("canceled target accepted its archived response")
		}
		afterReplay, err := ReadStatus(root)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(afterReplay.State, beforeReplay.State) {
			t.Fatal("canceled response replay changed durable state")
		}
	})
}

type routeTargetFixture struct {
	parent     string
	now        time.Time
	route      protocol.RouteID
	signer     signing.KeyPair
	issuers    enrollment.Issuers
	roots      map[enrollment.Role]string
	bootstraps map[enrollment.Role]BootstrapResult
	requests   map[enrollment.Role]RequestResult
	responses  enrollment.RouteResponses
	views      map[enrollment.Role]RuntimeViewBinding
}

func newRouteTargetFixture(t *testing.T) routeTargetFixture {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return newRouteTargetFixtureAt(t, parent, 0)
}

func newRouteTargetFixtureAt(t *testing.T, parent string, readerGID uint32) routeTargetFixture {
	t.Helper()
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	outer, err := pki.NewCA("OwnTransit target test outer", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerConnector, err := pki.NewCA("OwnTransit target test connector", now, 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	innerClient, err := pki.NewCA("OwnTransit target test client", now, 365*24*time.Hour)
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
	trust := enrollment.Trust{
		RelayAdmissionCA: string(outer.CertPEM),
		InnerConnectorCA: string(innerConnector.CertPEM),
		InnerClientCA:    string(innerClient.CertPEM),
	}
	roots := make(map[enrollment.Role]string, 3)
	bootstraps := make(map[enrollment.Role]BootstrapResult, 3)
	views := make(map[enrollment.Role]RuntimeViewBinding, 3)
	for _, role := range []enrollment.Role{enrollment.RoleRelay, enrollment.RoleConnector, enrollment.RoleClient} {
		runtime := enrollment.RuntimeBinding{
			ReleaseID: releaseID.String(), ReleaseSequence: 1,
			ArtifactSHA256: strings.Repeat("a", sha256.Size*2),
			OS:             "linux", Arch: "amd64", Role: role,
			Protocol:            enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		}
		if role == enrollment.RoleConnector {
			runtime.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
		}
		root := filepath.Join(parent, string(role)+"-state")
		view := RuntimeViewBinding{}
		if readerGID != 0 {
			view = RuntimeViewBinding{
				RuntimeRoot: root + "-runtime", RuntimeConfigRoot: root + "-runtime",
				AnchorViewRoot: root + "-anchor-view", ReaderGID: readerGID,
			}
		}
		result, err := Bootstrap(BootstrapOptions{
			RootPath: root, Role: role, Runtime: runtime, Trust: trust,
			RollbackAnchorRoot:        root + "-anchor",
			RuntimeViews:              view,
			DeploymentSignerPublicPEM: signer.PublicPEM, Now: now,
		})
		if err != nil {
			t.Fatalf("bootstrap %s: %v", role, err)
		}
		roots[role] = root
		bootstraps[role] = result
		views[role] = view
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		t.Fatal(err)
	}
	requests := make(map[enrollment.Role]RequestResult, 3)
	requests[enrollment.RoleRelay], err = InitRequest(RequestOptions{
		RootPath: roots[enrollment.RoleRelay], Validity: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	requests[enrollment.RoleConnector], err = InitRequest(RequestOptions{
		RootPath: roots[enrollment.RoleConnector], RouteID: route.String(), Validity: time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	requests[enrollment.RoleClient], err = InitRequest(RequestOptions{
		RootPath: roots[enrollment.RoleClient], RouteID: route.String(),
		ConnectorInstallationID: bootstraps[enrollment.RoleConnector].InstallationID,
		Validity:                time.Hour, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	issuers := enrollment.Issuers{
		RelayAdmission: outer, InnerConnector: innerConnector, InnerClient: innerClient,
	}
	responses, err := enrollment.ApproveInitialRoute(enrollment.RouteApproval{
		RelayRequest:     requests[enrollment.RoleRelay].RequestBytes,
		ConnectorRequest: requests[enrollment.RoleConnector].RequestBytes,
		ClientRequest:    requests[enrollment.RoleClient].RequestBytes,
		RelayURL:         "wss://relay.example.com/connects", RelayListen: enrollment.PackagedRelayListen,
		DeploymentSequence: 1, Now: now, LeafValidity: 30 * 24 * time.Hour,
		DeploymentValidity: 24 * time.Hour, Issuers: issuers, DeploymentSigner: signer.Private,
	})
	if err != nil {
		t.Fatal(err)
	}
	return routeTargetFixture{
		parent: parent, now: now, route: route, signer: signer, issuers: issuers,
		roots: roots, bootstraps: bootstraps, requests: requests, responses: responses, views: views,
	}
}
