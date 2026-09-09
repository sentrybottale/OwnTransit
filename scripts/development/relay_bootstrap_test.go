package development

import (
	"bytes"
	"os"
	"os/exec"
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
