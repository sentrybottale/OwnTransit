package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
)

func TestClientVersionIsOffline(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	proxyCalled := false
	checkCalled := false
	commands := clientCommands{
		version: func(destination io.Writer) error {
			_, err := io.WriteString(destination, "version-document\n")
			return err
		},
		checkConfig: func(string) error {
			checkCalled = true
			return nil
		},
		proxy: func(string, io.Reader, io.Writer) error {
			proxyCalled = true
			return nil
		},
	}

	if code := executeClient([]string{"version"}, strings.NewReader(""), &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeClient(version) = %d, diagnostics=%q", code, diagnostics.String())
	}
	if proxyCalled || checkCalled {
		t.Fatal("version invoked a config or network command")
	}
	if output.String() != "version-document\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestClientVerifyReaderGIDIsExactAndOffline(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	verified := 0
	commands := clientCommands{
		verifyReader: func(expected int) error {
			verified = expected
			return nil
		},
		proxy: func(string, io.Reader, io.Writer) error {
			return errors.New("unexpected proxy")
		},
	}
	if code := executeClient([]string{"verify-reader-gid", "5000"}, strings.NewReader("secret"), &output, &diagnostics, commands); code != 0 {
		t.Fatalf("executeClient(verify-reader-gid) = %d, diagnostics=%q", code, diagnostics.String())
	}
	if verified != 5000 || output.Len() != 0 || diagnostics.Len() != 0 {
		t.Fatalf("verified=%d stdout=%q stderr=%q", verified, output.String(), diagnostics.String())
	}

	for _, arguments := range [][]string{
		{"verify-reader-gid"},
		{"verify-reader-gid", "0"},
		{"verify-reader-gid", "-1"},
		{"verify-reader-gid", "5000", "extra"},
	} {
		diagnostics.Reset()
		if code := executeClient(arguments, strings.NewReader(""), &output, &diagnostics, commands); code != 2 {
			t.Fatalf("arguments=%v code=%d diagnostics=%q", arguments, code, diagnostics.String())
		}
	}
}

func TestVerifyClientReaderGIDUsesEffectiveNotRealGroup(t *testing.T) {
	actual := syscall.Getegid()
	if err := verifyClientReaderGID(actual); err != nil {
		t.Fatalf("verifyClientReaderGID(actual=%d): %v", actual, err)
	}
	mismatch := actual + 1
	if mismatch == 0 {
		mismatch = 1
	}
	if err := verifyClientReaderGID(mismatch); err == nil {
		t.Fatalf("verifyClientReaderGID(%d) accepted effective GID %d", mismatch, actual)
	}
}

func TestClientProxyExplicitAndLegacyModesPreserveRawStdout(t *testing.T) {
	for _, test := range []struct {
		name      string
		arguments []string
	}{
		{name: "explicit", arguments: []string{"proxy", "-config", "client.json"}},
		{name: "legacy no subcommand", arguments: []string{"-config", "client.json"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			var diagnostics bytes.Buffer
			commands := clientCommands{
				version:     func(io.Writer) error { return errors.New("unexpected version") },
				checkConfig: func(string) error { return errors.New("unexpected config check") },
				proxy: func(configPath string, input io.Reader, destination io.Writer) error {
					if configPath != "client.json" {
						t.Fatalf("config path = %q", configPath)
					}
					_, err := io.Copy(destination, input)
					return err
				},
			}
			if code := executeClient(test.arguments, strings.NewReader("raw-ssh-bytes"), &output, &diagnostics, commands); code != 0 {
				t.Fatalf("executeClient(proxy) = %d, diagnostics=%q", code, diagnostics.String())
			}
			if output.String() != "raw-ssh-bytes" || diagnostics.Len() != 0 {
				t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
			}
		})
	}
}

func TestClientCheckConfigDoesNotProxy(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	checkedPath := ""
	commands := clientCommands{
		version: func(io.Writer) error { return errors.New("unexpected version") },
		checkConfig: func(configPath string) error {
			checkedPath = configPath
			return nil
		},
		proxy: func(string, io.Reader, io.Writer) error {
			return errors.New("unexpected proxy")
		},
	}
	code := executeClient([]string{"check-config", "-config", "client.json"}, strings.NewReader(""), &output, &diagnostics, commands)
	if code != 0 || checkedPath != "client.json" {
		t.Fatalf("executeClient(check-config) = %d, path=%q, diagnostics=%q", code, checkedPath, diagnostics.String())
	}
	if output.String() != "owntransit: configuration valid\n" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestClientRelayURLOverrideIsDirectConfigOnly(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	overridePath := ""
	overrideURL := ""
	runtimeCalled := false
	commands := clientCommands{
		version:     func(io.Writer) error { return nil },
		checkConfig: func(string) error { return nil },
		proxy: func(string, io.Reader, io.Writer) error {
			return errors.New("ordinary proxy called")
		},
		proxyOverride: func(path, relayURL string, _ io.Reader, _ io.Writer) error {
			overridePath, overrideURL = path, relayURL
			return nil
		},
		proxyRuntime: func(string, string, int, io.Reader, io.Writer) error {
			runtimeCalled = true
			return nil
		},
	}
	url := "wss://relay.example.com/carrier"
	code := executeClient([]string{"proxy", "-config", "client.json", "-relay-url", url}, strings.NewReader(""), &output, &diagnostics, commands)
	if code != 0 || overridePath != "client.json" || overrideURL != url {
		t.Fatalf("direct override = %d, path=%q url=%q diagnostics=%q", code, overridePath, overrideURL, diagnostics.String())
	}
	diagnostics.Reset()
	code = executeClient([]string{
		"proxy", "-runtime-root", "/runtime", "-anchor-view-root", "/anchor", "-reader-gid", "1234", "-relay-url", url,
	}, strings.NewReader(""), &output, &diagnostics, commands)
	if code != 2 || runtimeCalled || !strings.Contains(diagnostics.String(), "direct-config proxy mode") {
		t.Fatalf("runtime override = %d, runtimeCalled=%v diagnostics=%q", code, runtimeCalled, diagnostics.String())
	}
}

func TestClientReadOnlyViewsUseHeldRuntimeWithoutTouchingStdout(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	proxyRoot, proxyAnchor := "", ""
	proxyGID := 0
	commands := clientCommands{
		proxy: func(string, io.Reader, io.Writer) error {
			return errors.New("pathname proxy must not run")
		},
		proxyRuntime: func(root, anchor string, gid int, input io.Reader, destination io.Writer) error {
			proxyRoot, proxyAnchor, proxyGID = root, anchor, gid
			_, err := io.Copy(destination, input)
			return err
		},
	}
	code := executeClient(
		[]string{"proxy", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234"},
		strings.NewReader("ssh-stream"),
		&output,
		&diagnostics,
		commands,
	)
	if code != 0 || proxyRoot != "/runtime" || proxyAnchor != "/anchor" || proxyGID != 1234 {
		t.Fatalf("runtime proxy = %d, root=%q anchor=%q gid=%d diagnostics=%q", code, proxyRoot, proxyAnchor, proxyGID, diagnostics.String())
	}
	if output.String() != "ssh-stream" || diagnostics.Len() != 0 {
		t.Fatalf("unexpected streams: stdout=%q stderr=%q", output.String(), diagnostics.String())
	}
}

func TestClientDoctorIsCarrierOnlyAndUsesNoSSHStreams(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	doctorCalls := 0
	proxyCalls := 0
	commands := clientCommands{
		doctor: func(path string) error {
			doctorCalls++
			if path != "client.json" {
				t.Fatalf("doctor config = %q", path)
			}
			return nil
		},
		proxy: func(string, io.Reader, io.Writer) error {
			proxyCalls++
			return nil
		},
	}
	code := executeClient([]string{"doctor", "--config", "client.json"}, strings.NewReader("must-not-be-read"), &output, &diagnostics, commands)
	if code != 0 || doctorCalls != 1 || proxyCalls != 0 || diagnostics.Len() != 0 {
		t.Fatalf("doctor code=%d doctor=%d proxy=%d stdout=%q stderr=%q", code, doctorCalls, proxyCalls, output.String(), diagnostics.String())
	}
	if output.String() != "OwnTransit carrier READY; SSH was not attempted.\n" {
		t.Fatalf("doctor output = %q", output.String())
	}
}

func TestSSHConfigSnippetUsesOnlyFixedInstalledProxyAndNeverEdits(t *testing.T) {
	for _, test := range []struct {
		goos string
		path string
	}{
		{goos: "darwin", path: "/Library/OwnTransit/bin/owntransit"},
		{goos: "linux", path: "/usr/local/bin/owntransit-proxy"},
	} {
		var output bytes.Buffer
		if err := writeSSHConfigSnippet(&output, "printer-room", "root", test.goos); err != nil {
			t.Fatal(err)
		}
		want := "Host printer-room\n  HostName printer-room\n  User root\n  ProxyCommand " + test.path + "\n"
		if output.String() != want || strings.Contains(output.String(), "/Documents/") {
			t.Fatalf("%s snippet = %q", test.goos, output.String())
		}
	}
	for _, unsafe := range []string{"", "*", "bad name", "line\nHost evil", "-option", ".."} {
		if err := writeSSHConfigSnippet(io.Discard, unsafe, "", "linux"); err == nil {
			t.Fatalf("unsafe alias %q accepted", unsafe)
		}
	}
}

func TestClientSSHConfigCommandIsOffline(t *testing.T) {
	var output bytes.Buffer
	var diagnostics bytes.Buffer
	called := 0
	commands := clientCommands{
		sshConfig: func(alias, user string, destination io.Writer) error {
			called++
			if alias != "box" || user != "admin" {
				t.Fatalf("alias/user = %q/%q", alias, user)
			}
			_, err := io.WriteString(destination, "snippet\n")
			return err
		},
		proxy:  func(string, io.Reader, io.Writer) error { return errors.New("network proxy invoked") },
		doctor: func(string) error { return errors.New("network doctor invoked") },
	}
	if code := executeClient([]string{"ssh-config", "--user", "admin", "box"}, strings.NewReader("secret"), &output, &diagnostics, commands); code != 0 {
		t.Fatalf("ssh-config code=%d stderr=%q", code, diagnostics.String())
	}
	if called != 1 || output.String() != "snippet\n" || diagnostics.Len() != 0 {
		t.Fatalf("called=%d stdout=%q stderr=%q", called, output.String(), diagnostics.String())
	}
}

func TestLinuxInstalledRuntimeSourceIsFixedAndRequiresSetgid(t *testing.T) {
	source, err := installedClientRuntimeSource("linux", 4321)
	if err != nil {
		t.Fatal(err)
	}
	if source.runtimeRoot != "/var/lib/owntransit/client/runtime" || source.anchorViewRoot != "/var/lib/owntransit/client/anchor-view" || source.readerGID != 4321 {
		t.Fatalf("installed source = %+v", source)
	}
	darwin, err := installedClientRuntimeSource("darwin", 4321)
	if err != nil {
		t.Fatal(err)
	}
	if darwin.runtimeRoot != "/Library/OwnTransit/client/runtime" || darwin.anchorViewRoot != "/Library/OwnTransit/client/anchor-view" || darwin.readerGID != 4321 {
		t.Fatalf("darwin installed source = %+v", darwin)
	}
	for _, test := range []struct {
		goos string
		gid  int
	}{{"windows", 4321}, {"linux", 0}, {"darwin", -1}} {
		if _, err := installedClientRuntimeSource(test.goos, test.gid); err == nil {
			t.Fatalf("unsafe installed source accepted: %+v", test)
		}
	}
}

func TestCourierCredentialCommandsExposeOnlyRelayHash(t *testing.T) {
	for _, command := range []string{"courier-credential-init", "courier-credential-rotate"} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		called := ""
		operation := func(path string) (string, error) {
			called = path
			return strings.Repeat("a", 64), nil
		}
		commands := clientCommands{courierCredentialInit: operation, courierCredentialRotate: operation}
		code := executeClient([]string{command, "--store", "/private/courier"}, strings.NewReader("raw-secret-must-not-be-read"), &output, &diagnostics, commands)
		if code != 0 || called != "/private/courier" || output.String() != strings.Repeat("a", 64)+"\n" || diagnostics.Len() != 0 {
			t.Fatalf("%s code=%d called=%q stdout=%q stderr=%q", command, code, called, output.String(), diagnostics.String())
		}
	}
}

func TestCourierCommandsDispatchOnlyProtectedPathsAndUseGenericStreams(t *testing.T) {
	tests := []struct {
		arguments []string
		want      string
		install   func(*clientCommands, *string, *string)
	}{
		{
			arguments: []string{"courier-register", "--registration", "/private/registration", "--credential-store", "/private/credential"},
			want:      "OwnTransit courier mailbox registered.\n",
			install: func(commands *clientCommands, first, second *string) {
				commands.courierRegister = func(registration, credential string) error { *first, *second = registration, credential; return nil }
			},
		},
		{
			arguments: []string{"courier-fetch-request", "--registration", "/private/registration", "--out", "/private/request"},
			want:      "OwnTransit encrypted request fetched.\n",
			install: func(commands *clientCommands, first, second *string) {
				commands.courierFetchRequest = func(registration, output string) error { *first, *second = registration, output; return nil }
			},
		},
		{
			arguments: []string{"courier-upload-response", "--registration", "/private/registration", "--response", "/private/response"},
			want:      "OwnTransit bound response uploaded.\n",
			install: func(commands *clientCommands, first, second *string) {
				commands.courierUploadResponse = func(registration, response string) error { *first, *second = registration, response; return nil }
			},
		},
	}
	for _, test := range tests {
		var output, diagnostics bytes.Buffer
		var first, second string
		commands := clientCommands{}
		test.install(&commands, &first, &second)
		if code := executeClient(test.arguments, strings.NewReader("never-read"), &output, &diagnostics, commands); code != 0 {
			t.Fatalf("%v code=%d stderr=%q", test.arguments, code, diagnostics.String())
		}
		if first != "/private/registration" || second == "" || output.String() != test.want || diagnostics.Len() != 0 {
			t.Fatalf("%v first=%q second=%q stdout=%q stderr=%q", test.arguments, first, second, output.String(), diagnostics.String())
		}
	}
}

func TestPrivilegedProxyBoundaryRejectsCourierBeforeArgumentParsing(t *testing.T) {
	for _, authorizer := range []func(string, []string) error{
		clientCommandAuthorizer("/usr/local/bin/owntransit-proxy", 501, 501, 20, 20),
		clientCommandAuthorizer("/usr/local/bin/owntransit", 501, 501, 20, 4321),
	} {
		called := false
		commands := clientCommands{
			authorizeCommand: authorizer,
			courierRegister: func(string, string) error {
				called = true
				return nil
			},
		}
		var output, diagnostics bytes.Buffer
		secretLookingPath := "/private/DO-NOT-ECHO"
		code := executeClient([]string{"courier-register", "--registration", secretLookingPath, "--credential-store", "/private/credential"}, strings.NewReader("never-read"), &output, &diagnostics, commands)
		if code != 1 || called || output.Len() != 0 || strings.Contains(diagnostics.String(), secretLookingPath) {
			t.Fatalf("code=%d called=%v stdout=%q stderr=%q", code, called, output.String(), diagnostics.String())
		}
	}
}

func TestPrivilegedProxyBoundaryAllowsOnlyFixedRuntimeForms(t *testing.T) {
	authorize := clientCommandAuthorizer("owntransit-proxy", 501, 501, 20, 4321)
	for _, command := range []string{"version", "proxy", "doctor", "check-config"} {
		if err := authorize(command, nil); err != nil {
			t.Fatalf("fixed %s rejected: %v", command, err)
		}
	}
	if err := authorize("verify-reader-gid", []string{"4321"}); err != nil {
		t.Fatalf("exact effective reader check rejected: %v", err)
	}
	for _, test := range []struct {
		command   string
		arguments []string
	}{
		{"proxy", []string{"--config=/tmp/attacker"}},
		{"doctor", []string{"--runtime-root=/tmp/attacker"}},
		{"verify-reader-gid", []string{"4322"}},
		{"ssh-config", []string{"alias"}},
		{"courier-fetch-request", nil},
		{"setup", []string{"private.otinvite"}},
	} {
		if err := authorize(test.command, test.arguments); err == nil {
			t.Fatalf("privileged proxy accepted %s %v", test.command, test.arguments)
		}
	}
}

func TestInstalledMacFrontendAllowsOnlyUnprivilegedAdministrativeCommands(t *testing.T) {
	authorize := clientCommandAuthorizer("/Library/OwnTransit/bin/owntransit-cli", 501, 501, 20, 20)
	for _, command := range []string{"version", "ssh-config", "setup", "courier-credential-init", "courier-credential-rotate", "courier-register", "courier-fetch-request", "courier-upload-response"} {
		if err := authorize(command, []string{"caller arguments are parsed later"}); err != nil {
			t.Fatalf("normal frontend rejected %s: %v", command, err)
		}
	}
	for _, command := range []string{"proxy", "doctor", "check-config", "verify-reader-gid"} {
		if err := authorize(command, nil); err == nil {
			t.Fatalf("normal frontend exposed %s", command)
		}
	}
	if err := clientCommandAuthorizer("/Library/OwnTransit/bin/owntransit-cli", 501, 501, 20, 5001)("version", nil); err == nil {
		t.Fatal("setgid normal frontend execution was accepted")
	}
}

func TestClientRuntimeViewFailureAndConfigConflictNeverUsePathnameProxy(t *testing.T) {
	for index, arguments := range [][]string{
		{"proxy", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234"},
		{"proxy", "--runtime-root", "/runtime", "--anchor-view-root", "/anchor", "--reader-gid", "1234", "--config", "client.json"},
	} {
		var output bytes.Buffer
		var diagnostics bytes.Buffer
		runtimeCalls := 0
		pathnameProxyCalled := false
		commands := clientCommands{
			proxy: func(string, io.Reader, io.Writer) error {
				pathnameProxyCalled = true
				return nil
			},
			proxyRuntime: func(string, string, int, io.Reader, io.Writer) error {
				runtimeCalls++
				return errors.New("invalid active state")
			},
		}
		code := executeClient(arguments, strings.NewReader("secret ssh input"), &output, &diagnostics, commands)
		wantRuntimeCalls := 1 - index
		if code == 0 || pathnameProxyCalled || runtimeCalls != wantRuntimeCalls || output.Len() != 0 {
			t.Fatalf("arguments=%v code=%d runtimeCalls=%d pathnameProxy=%v stdout=%q stderr=%q", arguments, code, runtimeCalls, pathnameProxyCalled, output.String(), diagnostics.String())
		}
	}
}
