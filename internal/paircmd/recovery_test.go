//go:build darwin || linux

package paircmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func recoveryRelayInfo(t *testing.T, base string) pairrelay.ServerInfo {
	t.Helper()
	path := filepath.Join(filepath.Dir(base), "relay-fixture")
	_, err := pairrelaycmd.Init(path, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := pairrelaycmd.StateInfo(path)
	if err != nil {
		t.Fatal(err)
	}
	var info pairrelay.ServerInfo
	if err := json.Unmarshal(encoded, &info); err != nil {
		t.Fatal(err)
	}
	return info
}

func TestFinishClientNeverClaimsReadyWithoutEndToEndCheck(t *testing.T) {
	old := checkClient
	t.Cleanup(func() { checkClient = old })
	for _, failure := range []error{nil, errors.New("fixture transport failure")} {
		var output, diag bytes.Buffer
		called := false
		checkClient = func(ctx context.Context, path string, dial pairrelay.DialFunc) error {
			called = true
			if output.Len() != 0 || !strings.Contains(diag.String(), "UNDER CONSTRUCTION") || path != "/private fixture/client" || dial != nil {
				t.Fatal("success preceded real check or changed target")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("check was unbounded")
			}
			return failure
		}
		err := finishClient(context.Background(), &output, &diag, "/private fixture/client-bin", "/private fixture/client", "/private fixture/client", "")
		if !called || !errors.Is(err, failure) {
			t.Fatal("check result ignored")
		}
		if failure != nil && strings.Contains(output.String(), "READY") {
			t.Fatal("failed check reported ready")
		}
		if failure == nil && (!strings.Contains(output.String(), "TUNNEL READY") || !strings.Contains(output.String(), "SSH login still uses your own keys") || !strings.Contains(output.String(), "ProxyCommand=")) {
			t.Fatal("successful check lost usable SSH handoff")
		}
	}
}

func TestReceiverCodeLookupAndRecoveryKeepNamedIdentityAndPrivateCodeLocal(t *testing.T) {
	base := tunnelFixture(t)
	if err := ensureTunnelRoot(base); err != nil {
		t.Fatal(err)
	}
	relay := recoveryRelayInfo(t, base)
	var namedID string
	var namedCode []byte
	defer func() { clear(namedCode) }()
	for _, name := range []string{"default", "laptop"} {
		path, _ := tunnelState(base, name)
		attempt, err := pairruntime.InitializeReceiverWithOffer(path, "wss://relay.example/connects", relay)
		if err != nil {
			t.Fatal(err)
		}
		if name == "laptop" {
			namedID, namedCode = attempt.ReceiverID, append([]byte(nil), attempt.Code...)
		}
		clear(attempt.Code)
	}
	path, name, err := receiverByID(base, namedID)
	if err != nil || name != "laptop" || path == base {
		t.Fatal("public receiver ID selected the wrong local tunnel")
	}
	var out, diag bytes.Buffer
	if err := showReceiverCode(&out, &diag, "/opt/connector fixture", path, path, name); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(out.Bytes(), namedCode) != 1 || bytes.Contains(diag.Bytes(), namedCode) || !strings.Contains(out.String(), "SAME pending code") || !strings.Contains(out.String(), "--tunnel laptop") || !strings.Contains(out.String(), "--receiver-id "+namedID) {
		t.Fatal("recovery omitted exact commands or leaked code")
	}
	for _, invalid := range []string{"", "../laptop", "not-an-id"} {
		if _, _, err := receiverByID(base, invalid); err == nil {
			t.Fatal("invalid public ID selected a receiver")
		}
	}
	if err := os.Symlink(path, filepath.Join(tunnelRoot(base), "alias")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiverByID(base, namedID); err == nil {
		t.Fatal("receiver lookup followed an untrusted alias")
	}
}

func TestMissingCodePrintsExplicitReplacementNotSilentReset(t *testing.T) {
	base := tunnelFixture(t)
	relay := recoveryRelayInfo(t, base)
	attempt, err := pairruntime.InitializeReceiverWithOffer(base, "wss://relay.example/connects", relay)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(attempt.Code)
	if err := os.Remove(filepath.Join(base, "authority", "private-pairing-code.v1")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(base, "authority", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if err := showReceiverCode(&out, &diag, "/opt/connector", base, base, ""); err == nil {
		t.Fatal("invented a missing code")
	}
	if out.Len() != 0 || !strings.Contains(diag.String(), "--replace") || !strings.Contains(diag.String(), "NEW approval command") {
		t.Fatal("missing code led to another dead end")
	}
	after, err := os.ReadFile(filepath.Join(base, "authority", "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("missing-code recovery reset the receiver")
	}
}

func TestBusyOrChangedReceiverNeverRevealsCodeOrSuggestsReplacement(t *testing.T) {
	base := tunnelFixture(t)
	info := recoveryRelayInfo(t, base)
	attempt, err := pairruntime.InitializeReceiverWithOffer(base, "wss://relay.example/connects", info)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(attempt.Code)
	root, err := securefs.OpenRoot(filepath.Join(base, "authority"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lock, err := root.TryLock("state.lock")
	if err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	if err := showReceiverCode(&out, &diag, "/opt/connector", base, base, ""); err == nil || out.Len() != 0 || strings.Contains(diag.String(), "--replace") || !strings.Contains(diag.String(), "pair code --state") {
		t.Fatal("busy recovery exposed a code or suggested identity replacement")
	}
	lock.Close()
	diag.Reset()
	if err := showReceiverCode(&out, &diag, "/opt/connector", base, base, "", "different-public-receiver"); err == nil || out.Len() != 0 || !strings.Contains(diag.String(), "identity changed") {
		t.Fatal("stale receiver ID disclosed a different code")
	}
}

func TestPrivateCodeAccidentallyUsedAsRelayIsNotEchoed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("client commands reject root")
	}
	base := tunnelFixture(t)
	secret := "otpair2." + strings.Repeat("x", 49)
	var out, diag bytes.Buffer
	if result := Run(false, []string{"setup", "--state", base, "--relay", secret}, strings.NewReader(""), &out, &diag); result != 2 {
		t.Fatal("invalid relay flag was accepted")
	}
	if bytes.Contains(out.Bytes(), []byte(secret)) || bytes.Contains(diag.Bytes(), []byte(secret)) {
		t.Fatal("private input echoed into recovery commands")
	}
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid relay created local state")
	}
}
