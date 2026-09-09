package development

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Invalid selectors must stop before root/host checks and all download work.
func TestRelayBootstrapRejectsAmbiguousOrCrossRoleScope(t *testing.T) {
	for _, args := range [][]string{
		{"relay", "--instance"},
		{"relay", "--instance", ""},
		{"relay", "--instance", "../default"},
		{"relay", "--instance", "all"},
		{"relay", "--instance", "UPPER"},
		{"relay", "--instance", strings.Repeat("a", 33)},
		{"relay", "--instance=alpha", "--instance", "bravo"},
		{"relay", "--instance", "alpha", "--instance=alpha"},
		{"client", "--instance", "alpha"},
		{"connector", "--instance", "alpha"},
		{"relay", "--uninstall", "--uninstall"},
		{"relay", "--uninstall", "wss://relay.example/connects"},
		{"relay", "wss://relay.example/connects", "wss://other.example/connects"},
		{"relay", "--unknown"},
	} {
		out, err := exec.Command("sh", append([]string{"../../install-preview-linux.sh"}, args...)...).CombinedOutput()
		if err == nil || bytes.Contains(out, []byte("run through sudo")) || bytes.Contains(out, []byte("Linux is required")) || bytes.Contains(out, []byte("Downloading")) {
			t.Fatalf("selector was not rejected before host operations: %v err=%v output=%s", args, err, out)
		}
	}
}

// Run the actual post-install shell handoff with an inert executable. This
// catches the curl entrypoint accidentally converting an omitted selector into
// --instance default even when the Go command itself preserves URL selection.
func TestRelayBootstrapSetupHandoffPreservesSelectorPresence(t *testing.T) {
	source, err := os.ReadFile("../../install-preview-linux.sh")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(source), "if test \"$role\" = relay && test \"$action\" = install; then\n  set -- setup\n")
	if start < 0 {
		t.Fatal("relay setup handoff missing")
	}
	end := strings.LastIndex(string(source), "\n}\nmain \"$@\"")
	if end < start {
		t.Fatal("cannot delimit relay setup handoff")
	}
	fixture := filepath.Join(t.TempDir(), "relay-fixture")
	if err := os.WriteFile(fixture, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	fragment := strings.ReplaceAll(string(source[start:end]), "/usr/local/bin/owntransit-relay-preview", "'"+strings.ReplaceAll(fixture, "'", "'\\''")+"'")
	for _, tc := range []struct{ set, name, want string }{
		{"no", "default", "setup\n--url\nwss://office.example/connects\n"},
		{"yes", "default", "setup\n--instance\ndefault\n--url\nwss://office.example/connects\n"},
		{"yes", "office", "setup\n--instance\noffice\n--url\nwss://office.example/connects\n"},
	} {
		t.Run(tc.set+"-"+tc.name, func(t *testing.T) {
			script := "set -eu\nrole=relay\naction=install\nsetup_url=wss://office.example/connects\ninstance_set=" + tc.set + "\nrelay_instance=" + tc.name + "\n" + fragment
			out, err := exec.Command("sh", "-c", script).CombinedOutput()
			if err != nil || string(out) != tc.want {
				t.Fatalf("handoff changed selector: err=%v got=%q want=%q", err, out, tc.want)
			}
		})
	}
}

func TestRelayBootstrapAcceptsExplicitInstanceBeforeOrAfterURL(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("valid argument parsing is checked only without installation authority")
	}
	for _, args := range [][]string{
		{"relay", "wss://relay.example/connects"},
		{"relay", "--instance", "alpha", "wss://relay.example/connects"},
		{"relay", "wss://relay.example/connects", "--instance=alpha"},
		{"relay", "--instance", "default", "--uninstall"},
		{"relay", "--uninstall", "--instance", "alpha"},
		{"relay", "--uninstall"},
	} {
		out, err := exec.Command("sh", append([]string{"../../install-preview-linux.sh"}, args...)...).CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("run through sudo")) {
			t.Fatalf("valid arguments failed before the root gate: %v err=%v output=%s", args, err, out)
		}
	}
}
