//go:build darwin || linux

package paircmd

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairruntime"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

func menuClientFixture(t *testing.T, base, name string, pending bool) string {
	t.Helper()
	if name != defaultTunnel {
		if err := ensureTunnelRoot(base); err != nil {
			t.Fatal(err)
		}
	}
	path, err := tunnelState(base, name)
	if err != nil {
		t.Fatal(err)
	}
	root, err := securefs.CreateRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.CreateExclusive("policy.json", []byte(`{"schema":"owntransit.paired-policy.v2","generation":1,"locked":false,"peer_floor":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	state := `{"schema":"owntransit.paired-client.v1","origin":"wss://relay.example/connects","token":"AQ=="`
	if pending {
		state += `,"pending":"AQ=="`
	}
	state += `}`
	if err := root.CreateExclusive("client.json", []byte(state), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMenuSelectionConfirmationBoundsAndCancellation(t *testing.T) {
	for _, target := range []bool{false, true} {
		for _, test := range []struct {
			input string
			want  []string
			code  int
		}{
			{"", nil, 0}, {"0\n", nil, 0}, {strings.Repeat("bad\n", 5), nil, 1}, {"1234\n", nil, 1},
			{"2\n1\n", []string{"continue", "--tunnel", "alpha"}, 0},
			{"4\n2\nbravo\n", []string{"remove", "--tunnel", "bravo"}, 0},
			{"5\n1\nwrong\n0\n", nil, 0}, {"5\n1\nalpha\n", []string{"killswitch", "--tunnel", "alpha"}, 0},
			{"6\n2\nbravo\n", []string{"restore", "--tunnel", "bravo"}, 0},
			{"1\nalpha\nfresh\n", []string{"new", "--tunnel", "fresh"}, 0},
			{"3\n0\n", nil, 0},
		} {
			base := tunnelFixture(t)
			menuClientFixture(t, base, "alpha", true)
			menuClientFixture(t, base, "bravo", false)
			input := strings.NewReader(test.input)
			var out, diag bytes.Buffer
			var action []string
			got := runMenu(context.Background(), target, base, input, bufio.NewReader(input), &out, &diag, func(args []string) int { action = args; return 0 })
			if got != test.code || !reflect.DeepEqual(action, test.want) {
				t.Fatalf("selection result %d %v; want %d %v", got, action, test.code, test.want)
			}
			if strings.Contains(out.String(), "TUNNEL READY") || strings.Contains(out.String(), "pair proxy") {
				t.Fatal("menu invented readiness or a compatibility command")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	input := strings.NewReader("1\nnew\n")
	if got := runMenu(ctx, false, tunnelFixture(t), input, bufio.NewReader(input), &bytes.Buffer{}, &bytes.Buffer{}, func([]string) int { t.Fatal("cancelled menu ran action"); return 1 }); got != 0 {
		t.Fatal("cancelled menu did not exit")
	}
}

func TestMenuKeepsOriginalInputAndBufferedSecretForDispatch(t *testing.T) {
	base := tunnelFixture(t)
	input := strings.NewReader("1\nfresh\nsynthetic-private-answer\n")
	reader := bufio.NewReader(input)
	var out, diag bytes.Buffer
	code := runMenu(context.Background(), false, base, input, reader, &out, &diag, func(args []string) int {
		if !reflect.DeepEqual(args, []string{"new", "--tunnel", "fresh"}) {
			t.Fatal("wrong action")
		}
		value, err := readLine(context.Background(), input, reader, &diag, "Private code: ", 56)
		if err != nil || string(value) != "synthetic-private-answer" {
			t.Fatal("dispatch discarded buffered secret")
		}
		clear(value)
		return 0
	})
	if code != 0 || strings.Contains(out.String()+diag.String(), "synthetic-private-answer") {
		t.Fatal("menu echoed secret input")
	}
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("menu alone created state")
	}
}

func TestMenuContinueResumesExactPendingRequestAndChecksReadiness(t *testing.T) {
	oldResume, oldCheck := resumeClient, checkClient
	t.Cleanup(func() { resumeClient = oldResume; checkClient = oldCheck })
	for _, pending := range []bool{false, true} {
		base := tunnelFixture(t)
		path := menuClientFixture(t, base, defaultTunnel, pending)
		before, _ := os.ReadFile(filepath.Join(path, "client.json"))
		for _, failure := range []error{nil, errors.New("fixture probe failure")} {
			resumed, checked := false, false
			var out, diag bytes.Buffer
			resumeClient = func(ctx context.Context, selected string, dial pairrelay.DialFunc) error {
				if selected != path || dial != nil {
					t.Fatal("resume changed selection")
				}
				resumed = true
				return nil
			}
			checkClient = func(ctx context.Context, selected string, dial pairrelay.DialFunc) error {
				if selected != path || (pending && !resumed) || out.Len() != 0 {
					t.Fatal("check skipped resume or success preceded probe")
				}
				checked = true
				return failure
			}
			err := continueTunnel(context.Background(), false, path, "default", path, "owntransit-client", &out, &diag)
			if !errors.Is(err, failure) || !checked || resumed != pending {
				t.Fatal("continue did not perform saved-state action")
			}
			if (failure == nil) != strings.Contains(out.String(), "TUNNEL READY") {
				t.Fatal("readiness did not match actual check")
			}
		}
		after, _ := os.ReadFile(filepath.Join(path, "client.json"))
		if !bytes.Equal(before, after) {
			t.Fatal("continue regenerated saved request")
		}
	}
}

func TestMenuContinueCannotRestoreRemovedOrAlarmedTunnel(t *testing.T) {
	oldCheck := checkClient
	t.Cleanup(func() { checkClient = oldCheck })
	checkClient = func(context.Context, string, pairrelay.DialFunc) error {
		t.Fatal("blocked tunnel reached carrier probe")
		return nil
	}
	for _, remove := range []bool{false, true} {
		base := tunnelFixture(t)
		path := menuClientFixture(t, base, defaultTunnel, false)
		var err error
		if remove {
			err = pairruntime.RemoveLocal(context.Background(), path, false, nil)
		} else {
			err = pairruntime.SetLocked(context.Background(), path, false, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		var out, diag bytes.Buffer
		if err := continueTunnel(context.Background(), false, path, "default", path, "owntransit-client", &out, &diag); err == nil {
			t.Fatal("continue reopened removed/alarmed tunnel")
		}
	}
}
