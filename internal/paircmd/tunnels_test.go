//go:build darwin || linux

package paircmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

func tunnelFixture(t *testing.T) string {
	t.Helper()
	p, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(p, "owntransit-pair")
}

func TestNamedTunnelSelectionCannotEscapeOrAliasDefault(t *testing.T) {
	base := tunnelFixture(t)
	for _, name := range []string{"", "..", "../default", "a/b", "a\\b", "UPPER", "all", "-a", "a%h", "a\nunit", "$(id)", strings.Repeat("a", 33)} {
		if _, err := tunnelState(base, name); err == nil {
			t.Fatalf("invalid tunnel name accepted: %q", name)
		}
		if name != "" {
			if _, err := receiverUnit(name); err == nil {
				t.Fatal("invalid service name accepted")
			}
		}
	}
	if got, err := tunnelState(base, "default"); err != nil || got != base {
		t.Fatal("default identity moved")
	}
	a, _ := tunnelState(base, "alpha")
	b, _ := tunnelState(base, "bravo")
	if a == b || a == base || b == base || filepath.Dir(a) != tunnelRoot(base) {
		t.Fatal("named paths overlap")
	}
	if err := ensureTunnelRoot(base); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("named preparation changed default state")
	}
}

func TestNamedTunnelRootRejectsSymlink(t *testing.T) {
	base := tunnelFixture(t)
	other := t.TempDir()
	if err := os.Symlink(other, tunnelRoot(base)); err != nil {
		t.Fatal(err)
	}
	if err := ensureTunnelRoot(base); err == nil {
		t.Fatal("named state followed a symlink")
	}
	entries, err := os.ReadDir(other)
	if err != nil || len(entries) != 0 {
		t.Fatal("symlink target changed")
	}
}

func TestTunnelListKeepsLocalScopeAndDoesNotCreateState(t *testing.T) {
	base := tunnelFixture(t)
	var output bytes.Buffer
	if err := listTunnels(base, false, &output); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tunnelRoot(base)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("list created state")
	}
	if err := ensureTunnelRoot(base); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default", "alpha", "bravo"} {
		path, _ := tunnelState(base, name)
		root, err := securefs.CreateRoot(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = root.CreateExclusive("policy.json", []byte(`{"schema":"owntransit.paired-policy.v2","generation":1,"locked":true,"peer_floor":0}`), 0600); err != nil {
			t.Fatal(err)
		}
		root.Close()
	}
	output.Reset()
	if err := listTunnels(base, false, &output); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default", "alpha", "bravo"} {
		if !strings.Contains(output.String(), name+"  alarmed") {
			t.Fatal("missing local tunnel status")
		}
	}
	if strings.Contains(output.String(), "private") || strings.Contains(output.String(), "policy.json") {
		t.Fatal("list exposed internal contents")
	}
}

func TestNamedServiceDerivationAndNoClobber(t *testing.T) {
	template := []byte("[Unit]\nConditionPathIsDirectory=/var/lib/owntransit-pair\n[Service]\nExecStart=/opt/package/owntransit-connector pair serve --state /var/lib/owntransit-pair\nReadWritePaths=/var/lib/owntransit-pair\n")
	unit, err := namedReceiverUnit(template, "laptop-2")
	if err != nil || bytes.Count(unit, []byte("/var/lib/owntransit-tunnels/laptop-2")) != 3 || bytes.Contains(unit, []byte(originalReceiverState)) {
		t.Fatal("service selected a wrong state path")
	}
	for _, bad := range []string{"default", "all", "../x", "a%h"} {
		if _, err := namedReceiverUnit(template, bad); err == nil {
			t.Fatal("unsafe instance name accepted")
		}
	}
	if _, err := namedReceiverUnit([]byte("arbitrary unit"), "alpha"); err == nil {
		t.Fatal("unrecognized template accepted")
	}
	path := filepath.Join(t.TempDir(), "unit.service")
	if err := publishReceiverUnit(path, unit); err != nil {
		t.Fatal(err)
	}
	if err := publishReceiverUnit(path, []byte("different")); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing service was overwritten")
	}
	b, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(b, unit) {
		t.Fatal("existing service contents changed")
	}
}

func TestNamedConnectCommandKeepsTunnelSelection(t *testing.T) {
	var output bytes.Buffer
	printConnect(&output, "Paired.", "/opt/bin/owntransit", "", "office")
	if !strings.Contains(output.String(), "pair proxy --tunnel office") || strings.Contains(output.String(), "--state") {
		t.Fatal("printed command lost tunnel selector")
	}
}

func TestAmbiguousTunnelSelectorsRejectBeforeAccess(t *testing.T) {
	receiver := os.Geteuid() == 0
	if receiver && runtime.GOOS != "linux" {
		t.Skip("client cannot run as root")
	}
	for _, args := range [][]string{
		{"alarm", "--tunnel", "alpha", "--tunnel", "bravo"},
		{"alarm", "--tunnel=alpha", "--state", "/private/other"},
		{"status", "--tunnel", ""},
		{"list", "--tunnel", "default"},
		{"alarm", "--tunnel", "../private-code-do-not-display"},
	} {
		var out, diagnostics bytes.Buffer
		if code := Run(receiver, args, strings.NewReader(""), &out, &diagnostics); code != 2 {
			t.Fatalf("invalid selection returned %d", code)
		}
		if out.Len() != 0 || strings.Contains(diagnostics.String(), "private-code-do-not-display") {
			t.Fatal("invalid selection exposed input or produced output")
		}
	}
}
