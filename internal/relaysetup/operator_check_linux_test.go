//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Never enabled by ordinary tests/CI. This explicitly authorized operator
// check uses the real engine and systemd, and can restart ONLY the managed
// OwnTransit relay. The rollback mode deliberately fails public verification.
func TestAuthorizedOperatorRelayCheck(t *testing.T) {
	if os.Getenv("OWNTRANSIT_OPERATOR_RELAY_CHECK") != "authorized" {
		t.Skip("requires explicit operator authorization")
	}
	exe, err := os.Executable()
	if err != nil || os.Geteuid() != 0 || filepath.Dir(exe) != "/usr/local/libexec/owntransit-relay-setup-check" {
		t.Fatal("operator test must use protected root-owned executable")
	}
	if _, err := protectedMetadata(exe, 128<<20); err != nil {
		t.Fatal(err)
	}
	if unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		t.Fatal("cannot disable diagnostic dumps")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	root, err := stateRoot()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := root.TryLock("setup.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	current, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	existing, err := inspect(ctx, current.Engine, managedContainer)
	if err != nil || !existing.State.Running || existing.Image != current.Image || !ownRelay(existing) {
		t.Fatalf("real engine inspection failed: %v", err)
	}
	if err := verifyRunningRelay(ctx, current, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	t.Log("Real engine inspection normalized successfully; saved image is running and public protocol verification passed.")
	if os.Getenv("OWNTRANSIT_OPERATOR_RELAY_STAGE") == "inspect" {
		return
	}
	if os.Getenv("OWNTRANSIT_OPERATOR_RELAY_STAGE") != "rollback" {
		t.Fatal("stage must be inspect or rollback")
	}
	next := current
	next.Image = os.Getenv("OWNTRANSIT_OPERATOR_RELAY_IMAGE")
	if !validImage(next.Image) || next.Image == current.Image {
		t.Fatal("explicit different rollback-test image required")
	}
	originalUnit, _, err := protectedFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	originalConfig, err := root.ReadFile("setup.json", 8192)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := os.MkdirTemp(managedRoot, "operator-backup-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "unit"), originalUnit, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backup, "setup.json"), originalConfig, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot := func() map[string][32]byte {
		out := map[string][32]byte{}
		for _, name := range []string{"token-hmac.key", "relay-ca-cert.pem", "relay-ca-key.pem", "relay-cert.pem", "relay-key.pem"} {
			p := filepath.Join(managedRoot, "data", "relay", name)
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal("cannot inspect relay identity file")
			}
			out[p] = sha256.Sum256(b)
			clear(b)
		}
		err := filepath.WalkDir("/etc/nginx", func(p string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.Type().IsRegular() && strings.HasSuffix(p, ".conf") {
				b, e := os.ReadFile(p)
				if e != nil {
					return e
				}
				out[p] = sha256.Sum256(b)
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		return out
	}
	before := snapshot()
	originalProbe, originalTimeout := probeServer, routeProbeTimeout
	routeProbeTimeout = 2 * time.Second
	probeServer = func(context.Context, string) (pairrelay.ServerInfo, error) {
		return pairrelay.ServerInfo{}, errors.New("intentional operator rollback test")
	}
	var output bytes.Buffer
	err = upgradeManaged(ctx, root, current, next, &output)
	probeServer, routeProbeTimeout = originalProbe, originalTimeout
	if err == nil {
		t.Fatal("intentional failed upgrade unexpectedly succeeded")
	}
	restored, err := loadConfig()
	if err != nil || restored != current {
		t.Fatal("previous selection was not restored")
	}
	actualUnit, _, err := protectedFile(unitPath)
	if err != nil || !bytes.Equal(actualUnit, originalUnit) {
		t.Fatal("previous unit not restored")
	}
	actualConfig, err := root.ReadFile("setup.json", 8192)
	if err != nil || !bytes.Equal(actualConfig, originalConfig) {
		t.Fatal("previous setup config not restored")
	}
	if err := verifyRunningRelay(ctx, current, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	after := snapshot()
	if len(before) != len(after) {
		t.Fatal("configuration inventory changed")
	}
	for p, digest := range before {
		if after[p] != digest {
			t.Fatal("relay identity or nginx configuration changed")
		}
	}
	if _, err := root.ReadFile("upgrade.json", 8192); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("rollback journal was not completed")
	}
	t.Log("Real Podman/systemd cutover and forced-failure rollback passed; previous image/unit/config restored, key and nginx-config hashes unchanged.")
}
