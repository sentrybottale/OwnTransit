package main

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
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
		{[]string{"setup", "--url", "wss://relay.example/connects"}, "setup:default:wss://relay.example/connects", 0},
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
				setup: func(_ context.Context, name, url string, _ io.Writer) error {
					called = "setup:" + name + ":" + url
					return nil
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
		setup: func(_ context.Context, name, url string, _ io.Writer) error {
			called = name == "office" && url == "wss://office.example/connects"
			return nil
		},
	}
	code := executeManagedRelay(context.Background(), []string{"setup", "--instance", "office"}, strings.NewReader("wss://office.example/connects\n"), &out, &diag, ops)
	if code != 0 || !called || !strings.Contains(out.String(), "office") || !strings.Contains(out.String(), "Public relay URL") {
		t.Fatalf("code=%d called=%v output=%s diagnostics=%s", code, called, out.String(), diag.String())
	}
}
