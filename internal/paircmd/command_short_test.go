//go:build darwin || linux

package paircmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/pairoffer"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
)

func TestShortCodePromptRejectsOtherProfilesAndRetainsExactCode(t *testing.T) {
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	code, _, err := pairoffer.New(secret, []byte("synthetic public advertisement"))
	clear(secret[:])
	if err != nil {
		t.Fatal("could not create disposable code")
	}
	defer clear(code)
	for _, tc := range []struct {
		name, bad, hint string
	}{
		{"old-public", "otrelay1." + strings.Repeat("x", 8192), "older public VPS code"},
		{"old-private", "otpair1." + strings.Repeat("x", 3000), "--legacy-codes"},
		{"shell-command", "owntransit pair setup", "Paste only the complete"},
		{"leading-space", " " + string(code), "Paste only the complete"},
		{"trailing-space", string(code) + " ", "Paste only the complete"},
		{"nonterminal-framing", "\x1b[200~" + string(code) + "\x1b[201~", "Paste only the complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.NewReader(tc.bad + "\n" + string(code) + "\n")
			var output bytes.Buffer
			got, err := readShortPairingCode(context.Background(), input, bufio.NewReader(input), &output)
			defer clear(got)
			if err != nil || !bytes.Equal(got, code) {
				t.Fatal("code correction did not preserve the exact valid code")
			}
			text := output.String()
			if !strings.Contains(text, tc.hint) || strings.Count(text, "Private receiver code (") != 2 {
				t.Fatal("missing profile-specific correction guidance")
			}
			if strings.Contains(text, tc.bad) || bytes.Contains(output.Bytes(), code) {
				t.Fatal("private input reached diagnostics")
			}
		})
	}
}

func TestClientSetupSelectsOneCodeUnlessLegacyExplicit(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("client commands deliberately reject root")
	}
	for _, legacy := range []bool{false, true} {
		state, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		state = filepath.Join(state, "client")
		args := []string{"setup", "--state", state, "--relay", "wss://relay.example/connects"}
		if legacy {
			args = append(args, "--legacy-codes")
		}
		var output, diagnostics bytes.Buffer
		if got := Run(false, args, strings.NewReader(""), &output, &diagnostics); got != 1 {
			t.Fatal("empty setup did not stop")
		}
		if output.Len() != 0 {
			t.Fatal("unfinished setup printed success output")
		}
		if _, err := os.Lstat(state); !os.IsNotExist(err) {
			t.Fatal("input-only setup created pairing state")
		}
		text := diagnostics.String()
		if !strings.Contains(text, "OwnTransit "+buildinfo.Version+" client setup") {
			t.Fatal("actual executable version missing")
		}
		if !strings.Contains(text, "THIS MACHINE: CLIENT COMPUTER") {
			t.Fatal("client prompt did not identify the local machine's role")
		}
		if legacy {
			if !strings.Contains(text, "legacy two-code setup") || !strings.Contains(text, "VPS registration code (") || strings.Contains(text, "Private receiver code (") {
				t.Fatal("explicit legacy setup selected the wrong prompt")
			}
		} else if !strings.Contains(text, "one private code") || !strings.Contains(text, "Private receiver code (otpair2., 56 characters, hidden):") || strings.Contains(text, "VPS registration code (") {
			t.Fatal("default setup requested legacy codes")
		}
	}
}

func TestSetupBannersNameTheMachineWithoutChangingCodeProfiles(t *testing.T) {
	for _, receiver := range []bool{false, true} {
		var output bytes.Buffer
		printSetupBanner(&output, receiver, false)
		want := "THIS MACHINE: CLIENT COMPUTER"
		if receiver {
			want = "THIS MACHINE: RECEIVING SSH MACHINE"
		}
		if !strings.Contains(output.String(), want) || !strings.Contains(output.String(), "one private code (otpair2., 56 characters)") || strings.Contains(output.String(), "otrelay1.") {
			t.Fatalf("role or one-code banner changed: %s", output.String())
		}
	}
}

func TestClientRootRejectionNamesTheCorrectMachines(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root rejection is exercised in the isolated Linux root suite")
	}
	var output, diagnostics bytes.Buffer
	if code := Run(false, []string{"setup"}, strings.NewReader(""), &output, &diagnostics); code != 1 || output.Len() != 0 {
		t.Fatal("root client setup did not reject before setup")
	}
	for _, text := range []string{"CLIENT COMPUTER", "without sudo", "move to your RECEIVING SSH MACHINE", "on that receiving machine"} {
		if !strings.Contains(diagnostics.String(), text) {
			t.Fatalf("wrong-role rejection omitted %q: %s", text, diagnostics.String())
		}
	}
	if strings.Contains(diagnostics.String(), "sudo sh -s -- client") {
		t.Fatal("wrong-role rejection suggested installing a client on the VPS")
	}
}

func TestLegacyCodesFlagIsLimitedToNewSetup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("client commands deliberately reject root")
	}
	for _, operation := range []string{"proxy", "resume", "status", "list", "alarm"} {
		var diagnostics bytes.Buffer
		if got := Run(false, []string{operation, "--legacy-codes"}, strings.NewReader(""), &bytes.Buffer{}, &diagnostics); got != 2 {
			t.Fatalf("%s accepted a setup-only profile flag", operation)
		}
	}
}

type discoveryFixture struct {
	failure error
	calls   []string
}

func (fixture *discoveryFixture) CheckOfferSupport(context.Context) error {
	fixture.calls = append(fixture.calls, "support")
	return fixture.failure
}

func (fixture *discoveryFixture) FetchServerInfo(context.Context) (pairrelay.ServerInfo, error) {
	fixture.calls = append(fixture.calls, "info")
	return pairrelay.ServerInfo{}, nil
}

func TestReceiverDiscoveryRequiresOfferSupportBeforeReturningInfo(t *testing.T) {
	for _, tc := range []struct {
		require bool
		failure error
		calls   string
	}{
		{true, nil, "support,info"},
		{true, pairrelay.ErrUnavailable, "support"},
		{true, context.Canceled, "support"},
		{false, pairrelay.ErrUnavailable, "info"},
	} {
		fixture := &discoveryFixture{failure: tc.failure}
		_, err := discoverServerInfo(context.Background(), fixture, tc.require)
		if strings.Join(fixture.calls, ",") != tc.calls || (tc.require && !errors.Is(err, tc.failure)) || (!tc.require && err != nil) {
			t.Fatal("receiver discovery skipped or fell back from the required profile check")
		}
	}
}
