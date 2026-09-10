package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/relaysetup"
)

func TestManagedRelaySelectorsFailBeforeOperations(t *testing.T) {
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"setup", "--instance", "../default"},
		{"setup", "--instance", ""},
		{"setup", "--instance", "all"},
		{"setup", "--instance", "MixedCase"},
		{"setup", "--instance", "office", "--instance", "home"},
		{"setup", "--url", "wss://relay.example/connects", "--url", "wss://other.example/connects"},
		{"setup", "--url", "http://relay.example/connects"},
		{"setup", "--state", "/private/state"},
		{"setup", "--package-lock-fd", "9"},
		{"register", "--instance", "office", "not-a-receiver-id"},
		{"register", "--instance", "office", "--url", "wss://office.example/connects", "not-a-receiver-id"},
		{"register", "--url", "", id.String()},
		{"register", "--url", "http://office.example/connects", id.String()},
		{"approve", "--instance", "office", "--url", "wss://office.example/connects", id.String()},
		{"approve", "--url", "http://office.example/connects", id.String()},
		{"approve", "not-a-receiver-id"},
		{"register", "--url", "wss://office.example/connects", "--url", "wss://other.example/connects", "not-a-receiver-id"},
		{"list", "--instance", "office"},
		{"list", "unexpected"},
		{"uninstall-all-managed", "--instance", "office"},
		{"uninstall-all-managed", "--package-lock-fd", "8"},
		{"uninstall-all-managed", "--package-lock-fd", "9", "--package-lock-fd", "9"},
		{"cleanup-container", "--instance", "office"},
		{"unknown"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, diag bytes.Buffer
			ops := managedOperations{lockPackage: func(int) (io.Closer, error) {
				t.Fatal("invalid selector reached package state")
				return nil, nil
			}}
			if code := executeManagedRelay(context.Background(), args, strings.NewReader(""), &out, &diag, ops); code != 2 {
				t.Fatalf("code=%d, diagnostics=%s", code, diag.String())
			}
			if out.Len() != 0 {
				t.Fatalf("invalid selector produced normal output: %q", out.String())
			}
		})
	}
}

func TestManagedPromptCancellationDoesNotWaitForEnter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, writer := io.Pipe()
	defer input.Close()
	defer writer.Close()
	started := make(chan struct{})
	done := make(chan error, 1)
	reader := &managedPromptReader{input: input, started: started}
	go func() {
		_, err := readManagedLine(ctx, bufio.NewReader(reader), 16)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("prompt did not begin reading")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("prompt cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled prompt still waits for Enter")
	}
}

type managedPromptReader struct {
	input   io.Reader
	started chan struct{}
}

func (reader *managedPromptReader) Read(data []byte) (int, error) {
	close(reader.started)
	return reader.input.Read(data)
}

func TestManagedRelayDispatchKeepsScopeAndLegacyDefault(t *testing.T) {
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
		lock int
	}{
		{[]string{"setup", "--url", "wss://relay.example/connects"}, "setup::wss://relay.example/connects", 0},
		{[]string{"setup", "--instance", "default", "--url", "wss://relay.example/connects"}, "setup:default:wss://relay.example/connects", 0},
		{[]string{"setup", "--instance", "office", "--url", "wss://office.example/connects"}, "setup:office:wss://office.example/connects", 0},
		{[]string{"register", id.String()}, "register:default:" + id.String(), 0},
		{[]string{"register", "--instance", "office", id.String()}, "register:office:" + id.String(), 0},
		{[]string{"register", "--url", "https://OFFICE.example:443/connects", id.String()}, "register-url:wss://office.example/connects:" + id.String(), 0},
		{[]string{"approve", id.String()}, "register:default:" + id.String(), 0},
		{[]string{"approve", "--instance", "office", id.String()}, "register:office:" + id.String(), 0},
		{[]string{"approve", "--url", "wss://office.example/connects", id.String()}, "register-url:wss://office.example/connects:" + id.String(), 0},
		{[]string{"uninstall-managed", "--instance", "office"}, "uninstall:office", 0},
		{[]string{"uninstall-managed", "--instance", "office", "--package-lock-fd", "9"}, "uninstall:office", 9},
		{[]string{"uninstall-all-managed", "--package-lock-fd", "9"}, "uninstall-all", 9},
		{[]string{"cleanup-container", "/usr/bin/podman", "sha256:" + strings.Repeat("a", 64)}, "cleanup:default", -1},
		{[]string{"cleanup-container", "--instance", "office", "/usr/bin/podman", "sha256:" + strings.Repeat("a", 64)}, "cleanup:office", -1},
		{[]string{"list"}, "list", -1},
	} {
		t.Run(tc.want, func(t *testing.T) {
			var out, diag bytes.Buffer
			called, locked := "", -1
			ops := managedOperations{
				lockPackage: func(fd int) (io.Closer, error) { locked = fd; return io.NopCloser(strings.NewReader("")), nil },
				prepareSetup: func(_ context.Context, name, url string) (relaysetup.SetupPlan, error) {
					called = "setup:" + name + ":" + url
					return relaysetup.SetupPlan{Instance: name, URL: url, Kind: "managed", Port: 9087}, nil
				},
				applySetup: func(context.Context, relaysetup.SetupPlan, bool, io.Writer) (relaysetup.SetupResult, error) {
					return relaysetup.SetupResult{Verification: relaysetup.VerificationPublic}, nil
				},
				register: func(_ context.Context, name, receiver string) (string, error) {
					called = "register:" + name + ":" + receiver
					return "fixture-relay-code", nil
				},
				registerURL: func(_ context.Context, url, receiver string) (string, error) {
					called = "register-url:" + url + ":" + receiver
					return "fixture-relay-code", nil
				},
				cleanup:      func(_ context.Context, name, _, _ string) error { called = "cleanup:" + name; return nil },
				uninstall:    func(_ context.Context, name string) error { called = "uninstall:" + name; return nil },
				uninstallAll: func(context.Context) error { called = "uninstall-all"; return nil },
				list:         func(context.Context, io.Writer) error { called = "list"; return nil },
			}
			if code := executeManagedRelay(context.Background(), tc.args, strings.NewReader(""), &out, &diag, ops); code != 0 || called != tc.want || locked != tc.lock {
				t.Fatalf("code=%d call=%q lock=%d diagnostics=%s", code, called, locked, diag.String())
			}
			if tc.args[0] == "approve" && (!strings.Contains(out.String(), "Receiver approved") || strings.Contains(out.String()+diag.String(), "fixture-relay-code")) {
				t.Fatal("approval must confirm success without printing a relay code")
			}
		})
	}
}

func TestManagedRelaySetupPromptExplainsInstanceAndNoSwitch(t *testing.T) {
	var out, diag bytes.Buffer
	called := false
	ops := managedOperations{
		lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
		prepareSetup: func(_ context.Context, name, url string) (relaysetup.SetupPlan, error) {
			called = name == "office" && url == "wss://office.example/connects"
			return relaysetup.SetupPlan{Instance: name, URL: url, Kind: "managed", Port: 9088}, nil
		},
		applySetup: func(context.Context, relaysetup.SetupPlan, bool, io.Writer) (relaysetup.SetupResult, error) {
			return relaysetup.SetupResult{Verification: relaysetup.VerificationPublic}, nil
		},
	}
	code := executeManagedRelay(context.Background(), []string{"setup", "--instance", "office"}, strings.NewReader("wss://office.example/connects\n"), &out, &diag, ops)
	if code != 0 || !called || !strings.Contains(out.String(), "office") || !strings.Contains(out.String(), "Public relay URL") {
		t.Fatalf("code=%d called=%v output=%s diagnostics=%s", code, called, out.String(), diag.String())
	}
}

func TestManagedRelayURLFirstDisplayedFlowAndMachineHandoff(t *testing.T) {
	var out, diag bytes.Buffer
	applied := false
	ops := managedOperations{
		lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
		prepareSetup: func(_ context.Context, instance, url string) (relaysetup.SetupPlan, error) {
			if instance != "" || url != "wss://office.example/connects" {
				t.Fatalf("unqualified URL lookup got instance=%q URL=%q", instance, url)
			}
			return relaysetup.SetupPlan{Instance: "office", URL: url, Kind: "reserved", Port: 9088}, nil
		},
		applySetup: func(_ context.Context, plan relaysetup.SetupPlan, consent bool, _ io.Writer) (relaysetup.SetupResult, error) {
			if plan.Instance != "office" || plan.Kind != "reserved" || consent {
				t.Fatalf("selected reservation changed or invented consent: %#v consent=%v", plan, consent)
			}
			applied = true
			return relaysetup.SetupResult{Verification: relaysetup.VerificationPublic}, nil
		},
	}
	code := executeManagedRelay(context.Background(), []string{"setup"}, strings.NewReader("sudo owntransit-relay setup\nwss://office.example/connects\n"), &out, &diag, ops)
	if code != 0 || !applied {
		t.Fatalf("code=%d applied=%v diagnostics=%s", code, applied, diag.String())
	}
	transcript := out.String()
	for _, text := range []string{"Public relay URL", "Selected local relay: office", "Relay component configured", "UNDER CONSTRUCTION", "RECEIVING SSH MACHINE", "sudo sh -s -- connector", "sudo owntransit-connector-preview pair setup", "one private code"} {
		if !strings.Contains(transcript, text) {
			t.Fatalf("missing %q in displayed flow: %s", text, transcript)
		}
	}
	if strings.Index(transcript, "Public relay URL") > strings.Index(transcript, "Selected local relay") || strings.Contains(transcript, "--instance default") || strings.Contains(transcript, "sudo sh -s -- client") || !strings.Contains(diag.String(), "does not accept shell commands") {
		t.Fatalf("URL-first correction or receiver handoff lost: %s %s", transcript, diag.String())
	}
}

func TestManagedRelayMigrationConsentIsExactAndPassedToBackend(t *testing.T) {
	for _, answer := range []string{"yes\n", "", "no\n", "YES\n", strings.Repeat("x", 17) + "\n"} {
		t.Run(strings.TrimSpace(answer), func(t *testing.T) {
			var out, diag bytes.Buffer
			applied := false
			ops := managedOperations{
				lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
				prepareSetup: func(_ context.Context, instance, url string) (relaysetup.SetupPlan, error) {
					return relaysetup.SetupPlan{Instance: "office", URL: url, Kind: "migration", Port: 9088, LegacyUnit: "owntransit-relay-pair-office.service", LegacyContainer: "owntransit-relay-pair-office", LegacyState: "/var/lib/owntransit-relay-pair-office"}, nil
				},
				applySetup: func(_ context.Context, plan relaysetup.SetupPlan, consent bool, _ io.Writer) (relaysetup.SetupResult, error) {
					if !consent || plan.Kind != "migration" || plan.Instance != "office" {
						t.Fatal("migration did not carry exact selection and confirmed consent")
					}
					applied = true
					return relaysetup.SetupResult{Verification: relaysetup.VerificationPublic}, nil
				},
			}
			code := executeManagedRelay(context.Background(), []string{"setup"}, strings.NewReader("wss://office.example/connects\n"+answer), &out, &diag, ops)
			if applied != (answer == "yes\n") || (code == 0) != applied {
				t.Fatalf("answer=%q applied=%v code=%d diagnostics=%s", answer, applied, code, diag.String())
			}
			for _, text := range []string{"Source service: owntransit-relay-pair-office.service", "Source container: owntransit-relay-pair-office", "Retained relay state: /var/lib/owntransit-relay-pair-office", "removes the old service", "Type yes"} {
				if !strings.Contains(out.String(), text) {
					t.Fatalf("adoption review omitted %q: %s", text, out.String())
				}
			}
		})
	}
}

func TestManagedRelayExplicitConflictDoesNotSwitchAndProvidesRetry(t *testing.T) {
	var out, diag bytes.Buffer
	ops := managedOperations{
		lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
		prepareSetup: func(_ context.Context, instance, url string) (relaysetup.SetupPlan, error) {
			if instance != "default" || url != "wss://office.example/connects" {
				t.Fatal("explicit selector was changed")
			}
			return relaysetup.SetupPlan{}, errors.New("this URL is reserved for local instance office")
		},
		applySetup: func(context.Context, relaysetup.SetupPlan, bool, io.Writer) (relaysetup.SetupResult, error) {
			t.Fatal("conflict applied")
			return relaysetup.SetupResult{}, nil
		},
	}
	code := executeManagedRelay(context.Background(), []string{"setup", "--instance", "default", "--url", "wss://office.example/connects"}, strings.NewReader(""), &out, &diag, ops)
	if code != 1 || !strings.Contains(diag.String(), "THIS VPS") || !strings.Contains(diag.String(), "list") || !strings.Contains(diag.String(), "setup --instance default --url wss://office.example/connects") {
		t.Fatalf("conflict lost exact retry: code=%d output=%s", code, diag.String())
	}
}

func TestManagedRelayReservedApprovalExplainsHowToFinishSetup(t *testing.T) {
	id, err := protocol.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	ops := managedOperations{
		lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
		registerURL: func(_ context.Context, url, receiver string) (string, error) {
			if url != "wss://office.example/connects" || receiver != id.String() {
				t.Fatal("reserved approval changed its URL or receiver")
			}
			return "", errors.New("local relay office has a retained URL/port reservation but setup is incomplete")
		},
	}
	code := executeManagedRelay(context.Background(), []string{"approve", "--url", "wss://office.example/connects", id.String()}, strings.NewReader(""), &out, &diag, ops)
	if code != 1 || out.Len() != 0 {
		t.Fatalf("incomplete relay reported approval success: code=%d output=%s", code, out.String())
	}
	for _, text := range []string{"THIS VPS", "setup is incomplete", "setup --url wss://office.example/connects", "rerun that exact approval command"} {
		if !strings.Contains(diag.String(), text) {
			t.Fatalf("incomplete setup lacks operational hint %q: %s", text, diag.String())
		}
	}
}

func TestManagedRelayFinalVerificationUsesApplyResult(t *testing.T) {
	for _, tc := range []struct {
		name, planned, final string
		wantCode             int
	}{
		{"local-remains-local", relaysetup.VerificationLocal403, relaysetup.VerificationLocal403, 0},
		{"local-improves-to-public", relaysetup.VerificationLocal403, relaysetup.VerificationPublic, 0},
		{"new-local-result", "", relaysetup.VerificationLocal403, 0},
		{"missing-result", relaysetup.VerificationPublic, "", 1},
		{"unknown-result", relaysetup.VerificationPublic, "other", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, diag bytes.Buffer
			kind := "new"
			if tc.planned == relaysetup.VerificationLocal403 {
				kind = "migration"
			}
			ops := managedOperations{
				lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
				prepareSetup: func(context.Context, string, string) (relaysetup.SetupPlan, error) {
					return relaysetup.SetupPlan{Instance: "office", URL: "wss://office.example/connects", Kind: kind, Port: 19088, Verification: tc.planned, LegacyUnit: "owntransit-relay-pair-office.service", LegacyContainer: "owntransit-relay-pair-office", LegacyState: "/var/lib/owntransit-relay-pair-office"}, nil
				},
				applySetup: func(_ context.Context, plan relaysetup.SetupPlan, confirmed bool, _ io.Writer) (relaysetup.SetupResult, error) {
					if plan.Verification != tc.planned || confirmed != (kind == "migration") {
						t.Fatal("reviewed verification or migration consent changed")
					}
					if kind == "migration" && !strings.Contains(out.String(), "Adopt this exact relay using local verification, with public reachability unverified from THIS VPS?") {
						t.Fatal("local-only adoption was not disclosed before consent")
					}
					return relaysetup.SetupResult{Verification: tc.final}, nil
				},
			}
			code := executeManagedRelay(context.Background(), []string{"setup", "--url", "wss://office.example/connects"}, strings.NewReader("yes\n"), &out, &diag, ops)
			if code != tc.wantCode {
				t.Fatalf("code=%d diagnostics=%s", code, diag.String())
			}
			text := out.String()
			if tc.final == relaysetup.VerificationPublic {
				if !strings.Contains(text, "Relay component configured. Relay URL:") || strings.Contains(text, "configured with local verification only") {
					t.Fatal("improved public result was not used")
				}
			} else if tc.final == relaysetup.VerificationLocal403 {
				for _, wanted := range []string{"configured with local verification only", "Public reachability is unverified from THIS VPS", "HTTP 403", "networks allowed by this website", "remaining public reachability check", "RECEIVING SSH MACHINE", "one private code"} {
					if !strings.Contains(text, wanted) {
						t.Fatalf("local result omitted %q", wanted)
					}
				}
				if strings.Contains(text, "THIS VPS is finished. Relay URL:") || strings.Contains(text, "public READY") {
					t.Fatal("local verification claimed public readiness")
				}
			} else if strings.Contains(text, "is finished") || !strings.Contains(diag.String(), "no recognized verification result") {
				t.Fatal("missing verification result reported success")
			}
		})
	}
}

func TestManagedRelayLocalVerificationConsentCanBeDeclined(t *testing.T) {
	var out, diag bytes.Buffer
	ops := managedOperations{
		lockPackage: func(int) (io.Closer, error) { return io.NopCloser(strings.NewReader("")), nil },
		prepareSetup: func(context.Context, string, string) (relaysetup.SetupPlan, error) {
			return relaysetup.SetupPlan{Instance: "office", URL: "wss://office.example/connects", Kind: "migration", Verification: relaysetup.VerificationLocal403}, nil
		},
		applySetup: func(context.Context, relaysetup.SetupPlan, bool, io.Writer) (relaysetup.SetupResult, error) {
			t.Fatal("declined local verification reached apply")
			return relaysetup.SetupResult{}, nil
		},
	}
	if code := executeManagedRelay(context.Background(), []string{"setup", "--url", "wss://office.example/connects"}, strings.NewReader("no\n"), &out, &diag, ops); code != 1 || !strings.Contains(diag.String(), "adoption cancelled") || strings.Contains(out.String(), "is finished") {
		t.Fatal("declined local verification was not cancelled")
	}
}
