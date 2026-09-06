//go:build darwin || linux

package paircmd

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

func TestConnectOutputIsShortAndSelectsExactClientAndState(t *testing.T) {
	var out bytes.Buffer
	printConnect(&out, "OwnTransit paired.", "/opt/bin/owntransit-preview", "")
	want := "OwnTransit paired. Connect:\n  ssh -o 'ProxyCommand=/opt/bin/owntransit-preview pair proxy' USER@SSH_ALIAS\nUse your SSH account, key and verified host identity.\n"
	if out.String() != want {
		t.Fatalf("unexpected success text: %q", out.String())
	}
	// Decode both shell layers without opening SSH or executing the path.
	state := "/example/a 'quote' $var $(false); `false` %h"
	out.Reset()
	printConnect(&out, "Already paired; keys unchanged.", "/example/client binary", state)
	line := strings.Split(out.String(), "\n")[1]
	outer := exec.Command("sh", "-c", "set -- "+strings.TrimSpace(line)+"; printf '%s' \"$3\"")
	option, err := outer.Output()
	if err != nil {
		t.Fatal(err)
	}
	proxy := strings.TrimPrefix(string(option), "ProxyCommand=")
	// OpenSSH resolves %% to a literal percent, not another token expansion.
	proxy = strings.ReplaceAll(proxy, "%%", "%")
	inner := exec.Command("sh", "-c", "set -- "+proxy+"; printf '%s\\n' \"$@\"")
	args, err := inner.Output()
	if err != nil || string(args) != "/example/client binary\npair\nproxy\n--state\n"+state+"\n" {
		t.Fatal("connection example did not retain literal arguments")
	}
}
