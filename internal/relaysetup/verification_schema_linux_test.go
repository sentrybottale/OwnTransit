//go:build linux

package relaysetup

import (
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
)

func TestManagedVerificationJournalSchemas(t *testing.T) {
	previous := fixtureSpec(t, "work", 9089)
	next := previous
	next.port = 9088
	next.legacyDataLabel = "alpha"
	image := "sha256:" + strings.Repeat("a", 64)
	e := verificationEvidence{URL: next.url, Engine: "/usr/bin/podman", Port: next.port, DataRootDigest: planDigest(next.dataRoot()), RouteDigest: strings.Repeat("a", 64), Required: VerificationLocal403, Identity: pairrelay.ServerInfo{ServerName: pairrelaycmd.RelayServerName, CAPEM: []byte("public fixture CA"), LeafSPKISHA256: "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}, Digests: map[string]string{}}
	for _, name := range relayIdentityFiles {
		e.Digests[name] = strings.Repeat("b", 64)
	}
	if !next.validVerificationEvidence(e) {
		t.Fatal("valid bounded verification evidence rejected")
	}
	for _, schema := range []string{"owntransit.relay-upgrade.v1", "owntransit.relay-upgrade.v2", "owntransit.relay-upgrade.v3"} {
		j := upgradeIntent{Schema: schema, Previous: next.config(next.url, e.Engine, image), Verification: &e}
		if next.validUpgradeVerification(j) {
			t.Fatal("legacy upgrade acquired local403 permission")
		}
		j.Verification = nil
		if !next.validUpgradeVerification(j) {
			t.Fatal("unchanged legacy upgrade rejected")
		}
	}
	j := upgradeIntent{Schema: "owntransit.relay-upgrade.v4", Previous: next.config(next.url, e.Engine, image)}
	if next.validUpgradeVerification(j) {
		t.Fatal("new upgrade omitted identity baseline")
	}
	j.Verification = &e
	if !next.validUpgradeVerification(j) {
		t.Fatal("new upgrade evidence rejected")
	}
	for _, mutate := range []func(*verificationEvidence){func(e *verificationEvidence) { e.Required = "ignore-errors" }, func(e *verificationEvidence) { e.RouteDigest = "" }, func(e *verificationEvidence) { e.URL = "wss://other.example/connects" }, func(e *verificationEvidence) { e.Port++ }, func(e *verificationEvidence) { e.DataRootDigest = planDigest(defaultInstance().dataRoot()) }, func(e *verificationEvidence) { e.Identity.CAPEM = nil }, func(e *verificationEvidence) { e.Identity.LeafSPKISHA256 = "invalid" }, func(e *verificationEvidence) { e.Digests = nil }} {
		bad := e
		mutate(&bad)
		j.Verification = &bad
		if next.validUpgradeVerification(j) {
			t.Fatal("invalid verification baseline accepted")
		}
	}
	old := legacySpec("alpha", next.url, next.port)
	source := migrationSource{Label: "alpha", Engine: e.Engine, Image: image, ContainerID: strings.Repeat("c", 64), Port: next.port, Unit: old.legacyUnit(image, e.Engine), Identity: e.Identity, Digests: e.Digests, Verification: VerificationLocal403, RouteDigest: e.RouteDigest}
	m := migrationIntent{Schema: "owntransit.relay-migration.v2", Phase: "prepared", Source: source, PreviousBinding: previous.binding(), NextBinding: next.binding(), Next: next.config(next.url, e.Engine, image)}
	if err := validateMigration(m); err != nil {
		t.Fatal("valid migration baseline rejected", err)
	}
	m.Schema = "owntransit.relay-migration.v1"
	if validateMigration(m) == nil {
		t.Fatal("legacy migration acquired local403 evidence")
	}
	m.Source.Verification = ""
	m.Source.RouteDigest = ""
	if err := validateMigration(m); err != nil {
		t.Fatal("original migration journal rejected", err)
	}
	m.Schema = "owntransit.relay-migration.v2"
	if validateMigration(m) == nil {
		t.Fatal("new migration omitted verification baseline")
	}
}
