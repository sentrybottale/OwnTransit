package runtimebundle

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
)

type bundleFixture struct {
	now         time.Time
	deployments map[enrollment.Role]enrollment.Deployment
	keys        map[enrollment.Role]PrivateKeys
	clientID    protocol.ID
	clientSPKI  string
}

func TestRenderAllRolesIsDeterministicAndPrivate(t *testing.T) {
	fixture := newBundleFixture(t)
	directory := "/var/lib/owntransit/generations/00000001"
	wantEndpointBases := map[string]struct{}{
		configBase: {}, outerCertificateBase: {}, outerPrivateKeyBase: {},
		innerCertificateBase: {}, innerPrivateKeyBase: {}, relayAdmissionCABase: {},
		innerClientCABase: {}, innerConnectorCABase: {},
	}
	wantRelayBases := map[string]struct{}{
		configBase: {}, outerCertificateBase: {}, outerPrivateKeyBase: {}, relayAdmissionCABase: {},
	}
	for _, role := range []enrollment.Role{enrollment.RoleRelay, enrollment.RoleConnector, enrollment.RoleClient} {
		t.Run(string(role), func(t *testing.T) {
			revocations := ConnectorRevocations{}
			if role == enrollment.RoleConnector {
				revocations = ConnectorRevocations{ClientIDs: []string{fixture.clientID.String()}, SPKIPins: []string{fixture.clientSPKI}}
			}
			first, err := Render(fixture.deployments[role], directory, fixture.keys[role], revocations, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			second, err := Render(fixture.deployments[role], directory, fixture.keys[role], revocations, fixture.now)
			if err != nil {
				t.Fatal(err)
			}
			if len(first) != len(second) || (role == enrollment.RoleRelay && len(first) != 4) || (role != enrollment.RoleRelay && len(first) != 8) {
				t.Fatalf("file counts = %d/%d", len(first), len(second))
			}
			wantBases := wantEndpointBases
			if role == enrollment.RoleRelay {
				wantBases = wantRelayBases
			}
			seenBases := make(map[string]struct{}, len(first))
			for index := range first {
				if first[index].Path != second[index].Path || first[index].Mode != 0o600 || second[index].Mode != 0o600 || !bytes.Equal(first[index].Contents, second[index].Contents) {
					t.Fatalf("non-deterministic or non-private file %d: %+v / %+v", index, first[index], second[index])
				}
				if filepath.Dir(first[index].Path) != directory {
					t.Fatalf("file escaped generation directory: %q", first[index].Path)
				}
				base := filepath.Base(first[index].Path)
				if _, allowed := wantBases[base]; !allowed {
					t.Fatalf("role %s rendered non-fixed basename %q", role, base)
				}
				if _, duplicate := seenBases[base]; duplicate {
					t.Fatalf("role %s rendered duplicate basename %q", role, base)
				}
				seenBases[base] = struct{}{}
				if index > 0 && first[index-1].Path >= first[index].Path {
					t.Fatalf("files are not strictly ordered: %q then %q", first[index-1].Path, first[index].Path)
				}
			}
			if len(seenBases) != len(wantBases) {
				t.Fatalf("role %s rendered basenames = %v, want %v", role, seenBases, wantBases)
			}
			assertRenderedConfig(t, role, configContents(t, first), revocations)
		})
	}
}

func TestRenderRejectsPrivateKeyMismatchAndUnexpectedInnerKey(t *testing.T) {
	fixture := newBundleFixture(t)
	clientKeys := fixture.keys[enrollment.RoleClient]
	clientKeys.OuterPEM = fixture.keys[enrollment.RoleConnector].OuterPEM
	if _, err := Render(fixture.deployments[enrollment.RoleClient], "/var/lib/owntransit/generations/00000001", clientKeys, ConnectorRevocations{}, fixture.now); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("outer key mismatch error = %v", err)
	}

	relayKeys := fixture.keys[enrollment.RoleRelay]
	relayKeys.InnerPEM = fixture.keys[enrollment.RoleClient].InnerPEM
	if _, err := Render(fixture.deployments[enrollment.RoleRelay], "/var/lib/owntransit/generations/00000001", relayKeys, ConnectorRevocations{}, fixture.now); err == nil || !strings.Contains(err.Error(), "must not contain") {
		t.Fatalf("relay inner-key error = %v", err)
	}
}

func TestRenderRejectsNonCanonicalGenerationPaths(t *testing.T) {
	fixture := newBundleFixture(t)
	for _, directory := range []string{"", "relative/generation", "/", "/var/lib/owntransit/../generation", "/var/lib/owntransit/generation\nspoof"} {
		t.Run(directory, func(t *testing.T) {
			if _, err := Render(fixture.deployments[enrollment.RoleClient], directory, fixture.keys[enrollment.RoleClient], ConnectorRevocations{}, fixture.now); err == nil || !strings.Contains(err.Error(), "generation directory") {
				t.Fatalf("path %q error = %v", directory, err)
			}
		})
	}
}

func TestRenderRejectsRevocationsOutsideConnectorRole(t *testing.T) {
	fixture := newBundleFixture(t)
	revocations := ConnectorRevocations{ClientIDs: []string{fixture.clientID.String()}}
	if _, err := Render(fixture.deployments[enrollment.RoleClient], "/var/lib/owntransit/generations/00000001", fixture.keys[enrollment.RoleClient], revocations, fixture.now); err == nil || !strings.Contains(err.Error(), "invalid for this role") {
		t.Fatalf("client revocation error = %v", err)
	}
}

func TestRelayRuntimeRejectsListenOutsidePackagedContract(t *testing.T) {
	fixture := newBundleFixture(t)
	deployment := fixture.deployments[enrollment.RoleRelay]
	deployment.RelayListen = "127.0.0.1:9087"
	if _, err := Render(deployment, "/var/lib/owntransit/generations/00000001", fixture.keys[enrollment.RoleRelay], ConnectorRevocations{}, fixture.now); err == nil || !strings.Contains(err.Error(), "packaged container contract") {
		t.Fatalf("signed relay deployment mismatch error = %v", err)
	}

	files, err := Render(fixture.deployments[enrollment.RoleRelay], "/var/lib/owntransit/generations/00000001", fixture.keys[enrollment.RoleRelay], ConnectorRevocations{}, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	source := make(map[string][]byte, len(files))
	for _, file := range files {
		source[filepath.Base(file.Path)] = append([]byte(nil), file.Contents...)
	}
	var relay config.Relay
	if err := json.Unmarshal(source[configBase], &relay); err != nil {
		t.Fatal(err)
	}
	relay.Listen = "127.0.0.1:9087"
	source[configBase], err = json.MarshalIndent(relay, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	source[configBase] = append(source[configBase], '\n')
	if _, err := RebaseVerifiedFiles(enrollment.RoleRelay, source, "/var/lib/owntransit/runtime/g-2"); err == nil || !strings.Contains(err.Error(), "packaged container contract") {
		t.Fatalf("rebased relay config mismatch error = %v", err)
	}
}

func TestRenderRejectsUnboundedConnectorRevocations(t *testing.T) {
	fixture := newBundleFixture(t)
	revocations := ConnectorRevocations{ClientIDs: make([]string, config.MaxCapabilityRevocations+1)}
	if _, err := Render(fixture.deployments[enrollment.RoleConnector], "/var/lib/owntransit/generations/00000001", fixture.keys[enrollment.RoleConnector], revocations, fixture.now); err == nil || !strings.Contains(err.Error(), "combined limit") {
		t.Fatalf("unbounded connector revocation error = %v", err)
	}
}

func TestRenderWithPolicyMaterializesOnlyExplicitTwoRootConnectorOverlap(t *testing.T) {
	fixture := newBundleFixture(t)
	nextRoot := mustBundleCA(t, "rotated inner client", fixture.now)
	directory := "/var/lib/owntransit/generations/00000002"
	policy := VerifierPolicy{
		CapabilityClientRoots: []string{
			fixture.deployments[enrollment.RoleConnector].Trust.InnerClientCA,
			string(nextRoot.CertPEM),
		},
	}
	files, err := RenderWithPolicy(
		fixture.deployments[enrollment.RoleConnector], directory,
		fixture.keys[enrollment.RoleConnector], policy, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 9 {
		t.Fatalf("two-root connector rendered %d files, want 9", len(files))
	}
	var value config.Connector
	if err := json.Unmarshal(configContents(t, files), &value); err != nil {
		t.Fatal(err)
	}
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(value.InnerTLS.ClientCAFiles) != 2 || !value.InnerTLS.ClientCARotation ||
		filepath.Base(value.InnerTLS.ClientCAFiles[1]) != innerClientCANextBase {
		t.Fatalf("explicit overlap not bound in config: %+v", value.InnerTLS)
	}

	if _, err := RenderWithPolicy(
		fixture.deployments[enrollment.RoleClient], directory,
		fixture.keys[enrollment.RoleClient], policy, fixture.now,
	); err == nil {
		t.Fatal("client renderer accepted connector capability-root policy")
	}
	duplicate := policy
	duplicate.CapabilityClientRoots = []string{policy.CapabilityClientRoots[0], policy.CapabilityClientRoots[0]}
	if _, err := RenderWithPolicy(
		fixture.deployments[enrollment.RoleConnector], directory,
		fixture.keys[enrollment.RoleConnector], duplicate, fixture.now,
	); err == nil {
		t.Fatal("connector renderer accepted duplicate overlap roots")
	}
}

func assertRenderedConfig(t *testing.T, role enrollment.Role, encoded []byte, revocations ConnectorRevocations) {
	t.Helper()
	switch role {
	case enrollment.RoleRelay:
		var value config.Relay
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode rendered relay config: %v", err)
		}
		if err := value.Validate(); err != nil {
			t.Fatalf("validate rendered relay config: %v", err)
		}
	case enrollment.RoleConnector:
		var value config.Connector
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode rendered connector config: %v", err)
		}
		if err := value.Validate(); err != nil {
			t.Fatalf("validate rendered connector config: %v", err)
		}
		if value.SSHTarget != config.ConnectorSSHTarget || value.InnerProfile != config.InnerProfileRouteCapability ||
			len(value.InnerTLS.Clients) != 0 || len(value.InnerTLS.ClientCAFiles) != 1 || value.InnerTLS.ClientCARotation ||
			len(value.InnerTLS.RevokedClientIDs) != len(revocations.ClientIDs) || len(value.InnerTLS.RevokedClientSPKIs) != len(revocations.SPKIPins) {
			t.Fatalf("unsafe connector config: %+v", value)
		}
		if bytes.Contains(encoded, []byte(`"clients"`)) {
			t.Fatal("connector config contains a positive client-list field")
		}
		if value.CarrierCAFile != "" || value.AllowInsecureCarrier {
			t.Fatal("connector carrier does not use wss with system roots")
		}
	case enrollment.RoleClient:
		var value config.Client
		if err := json.Unmarshal(encoded, &value); err != nil {
			t.Fatalf("decode rendered client config: %v", err)
		}
		if err := value.Validate(); err != nil {
			t.Fatalf("validate rendered client config: %v", err)
		}
		if value.CarrierCAFile != "" || value.AllowInsecureCarrier || value.InnerProfile != config.InnerProfileRouteCapability {
			t.Fatal("client carrier/profile is unsafe")
		}
	}
}

func configContents(t *testing.T, files []File) []byte {
	t.Helper()
	for _, file := range files {
		if filepath.Base(file.Path) == configBase {
			return file.Contents
		}
	}
	t.Fatal("rendered bundle has no config")
	return nil
}

func newBundleFixture(t *testing.T) bundleFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	relayCA := mustBundleCA(t, "relay admission", now)
	innerClientCA := mustBundleCA(t, "inner client", now)
	innerConnectorCA := mustBundleCA(t, "inner connector", now)
	relayID := protocol.ID{1}
	connectorID := protocol.ID{2}
	clientID := protocol.ID{3}
	route := protocol.RouteID{4}
	releaseID := protocol.ID{5}

	relayOuter := mustBundleLeaf(t, relayCA, config.RelayDNSName, x509.ExtKeyUsageServerAuth, now)
	connectorOuterName := config.OuterConnectorDNSName(route)
	connectorOuter := mustBundleLeaf(t, relayCA, connectorOuterName, x509.ExtKeyUsageClientAuth, now)
	connectorInnerName := config.CapabilityConnectorDNSName(connectorID, route)
	connectorInner := mustBundleLeaf(t, innerConnectorCA, connectorInnerName, x509.ExtKeyUsageServerAuth, now)
	clientOuterName := config.OuterClientDNSName(clientID)
	clientOuter := mustBundleLeaf(t, relayCA, clientOuterName, x509.ExtKeyUsageClientAuth, now)
	clientInnerName := config.ClientCapabilityDNSName(clientID, connectorID, route, 1)
	clientInner := mustBundleLeaf(t, innerClientCA, clientInnerName, x509.ExtKeyUsageClientAuth, now)

	relayPin := mustBundlePin(t, relayOuter.Certificate)
	connectorOuterPin := mustBundlePin(t, connectorOuter.Certificate)
	connectorInnerPin := mustBundlePin(t, connectorInner.Certificate)
	clientOuterPin := mustBundlePin(t, clientOuter.Certificate)
	clientInnerPin := mustBundlePin(t, clientInner.Certificate)
	trust := enrollment.Trust{
		RelayAdmissionCA: string(relayCA.CertPEM), InnerClientCA: string(innerClientCA.CertPEM), InnerConnectorCA: string(innerConnectorCA.CertPEM),
	}

	base := func(role enrollment.Role, installationID protocol.ID, nonceByte byte) enrollment.Deployment {
		runtime := enrollment.RuntimeBinding{
			ReleaseID: releaseID.String(), ReleaseSequence: 1, ArtifactSHA256: strings.Repeat("0", 64),
			OS: "linux", Arch: "amd64", Role: role, Protocol: enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		}
		if role == enrollment.RoleClient {
			runtime.OS, runtime.Arch = "darwin", "arm64"
		}
		if role == enrollment.RoleConnector {
			runtime.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
		}
		return enrollment.Deployment{
			Schema: enrollment.DeploymentSchema, Protocol: enrollment.DeploymentProtocol,
			MinimumLifecycle: enrollment.CurrentLifecycleGeneration, Role: role,
			InstallationID: installationID.String(), ConnectorInstallationID: connectorID.String(),
			RequestNonce: protocol.ID{nonceByte}.String(), RequestSHA256: strings.Repeat("0", 64),
			RequestSequence: 1, DeploymentSequence: 1, CredentialEpoch: 1, Runtime: runtime,
			IssuedUnix: now.Unix(), ExpiresUnix: now.Add(time.Hour).Unix(), RouteID: route.String(), Trust: trust,
		}
	}

	relay := base(enrollment.RoleRelay, relayID, 11)
	relay.RelayListen = enrollment.PackagedRelayListen
	relay.OuterDNSName, relay.OuterCertificate = config.RelayDNSName, string(relayOuter.CertPEM)
	relay.Relay = &enrollment.RelayAuthorization{
		Clients: []config.AuthorizedPeer{{DNSName: clientOuterName, SPKIPins: []string{clientOuterPin}}},
		Routes:  []config.RelayRoute{{RouteID: route.String(), DNSName: connectorOuterName, SPKIPins: []string{connectorOuterPin}}},
	}
	connector := base(enrollment.RoleConnector, connectorID, 12)
	connector.RelayURL = "wss://relay.example.com/connects"
	connector.OuterDNSName, connector.OuterCertificate = connectorOuterName, string(connectorOuter.CertPEM)
	connector.InnerDNSName, connector.InnerCertificate = connectorInnerName, string(connectorInner.CertPEM)
	connector.Connector = &enrollment.ConnectorAuthorization{
		RelayServerPins: []string{relayPin}, InnerAuthorizationProfile: config.InnerProfileRouteCapability,
	}
	client := base(enrollment.RoleClient, clientID, 13)
	client.RelayURL = "wss://relay.example.com/connects"
	client.OuterDNSName, client.OuterCertificate = clientOuterName, string(clientOuter.CertPEM)
	client.InnerDNSName, client.InnerCertificate = clientInnerName, string(clientInner.CertPEM)
	client.Client = &enrollment.ClientAuthorization{
		RelayServerPins: []string{relayPin}, ConnectorDNSName: connectorInnerName, ConnectorSPKIPins: []string{connectorInnerPin},
	}

	for role, deployment := range map[enrollment.Role]enrollment.Deployment{
		enrollment.RoleRelay: relay, enrollment.RoleConnector: connector, enrollment.RoleClient: client,
	} {
		if err := deployment.Validate(now); err != nil {
			t.Fatalf("fixture %s deployment: %v", role, err)
		}
	}
	return bundleFixture{
		now: now, clientID: clientID, clientSPKI: clientInnerPin,
		deployments: map[enrollment.Role]enrollment.Deployment{
			enrollment.RoleRelay: relay, enrollment.RoleConnector: connector, enrollment.RoleClient: client,
		},
		keys: map[enrollment.Role]PrivateKeys{
			enrollment.RoleRelay:     PrivateKeys{OuterPEM: relayOuter.KeyPEM},
			enrollment.RoleConnector: PrivateKeys{OuterPEM: connectorOuter.KeyPEM, InnerPEM: connectorInner.KeyPEM},
			enrollment.RoleClient:    PrivateKeys{OuterPEM: clientOuter.KeyPEM, InnerPEM: clientInner.KeyPEM},
		},
	}
}

func mustBundleCA(t *testing.T, name string, now time.Time) pki.Material {
	t.Helper()
	material, err := pki.NewCA(name, now, 48*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func mustBundleLeaf(t *testing.T, issuer pki.Material, name string, usage x509.ExtKeyUsage, now time.Time) pki.Material {
	t.Helper()
	material, err := pki.IssueLeaf(issuer, name, usage, now, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func mustBundlePin(t *testing.T, certificate *x509.Certificate) string {
	t.Helper()
	pin, err := identity.SPKIPin(certificate)
	if err != nil {
		t.Fatal(err)
	}
	return pin
}
