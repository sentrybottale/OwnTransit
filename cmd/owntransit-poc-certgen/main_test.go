package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
)

func TestRunCreatesSeparatedValidConfigurations(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	if err := run(testOptions(root)); err != nil {
		t.Fatal(err)
	}
	relayConfig, err := config.LoadRelay(filepath.Join(root, "relay", "config.json"))
	if err != nil {
		t.Fatalf("relay config: %v", err)
	}
	if relayConfig.Limits.PendingPerClient != config.DefaultRelayPendingPerClient ||
		relayConfig.Limits.ActivePerClient != config.DefaultRelayActivePerClient {
		t.Fatalf("relay per-client limits = %d/%d", relayConfig.Limits.PendingPerClient, relayConfig.Limits.ActivePerClient)
	}
	connectorConfig, err := config.LoadConnector(filepath.Join(root, "connector", "config.json"))
	if err != nil {
		t.Fatalf("connector config: %v", err)
	}
	assertConnectorRuntimePaths(t, connectorConfig, defaultConnectorRuntimeDir)
	if connectorConfig.InnerProfile != config.InnerProfileRouteCapability || connectorConfig.InstallationID == "" || len(connectorConfig.InnerTLS.Clients) != 0 || len(connectorConfig.InnerTLS.ClientCAFiles) != 1 {
		t.Fatal("generated connector does not use the route capability profile")
	}
	clientConfig, err := config.LoadClient(filepath.Join(root, "client", "config.json"))
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	if clientConfig.InstallationID == "" || clientConfig.OuterTLS.IssuerCAFile == "" || clientConfig.InnerTLS.IssuerCAFile == "" {
		t.Fatal("generated client config does not use strict local identity validation")
	}
	if clientConfig.InnerProfile != config.InnerProfileRouteCapability || clientConfig.ConnectorInstallationID != connectorConfig.InstallationID || clientConfig.CredentialEpoch == 0 {
		t.Fatal("generated client is not bound to the connector capability profile")
	}
	if relayConfig.OuterTLS.IssuerCAFile == "" || connectorConfig.OuterTLS.IssuerCAFile == "" || connectorConfig.InnerTLS.IssuerCAFile == "" {
		t.Fatal("generated relay or connector config does not use strict local identity validation")
	}
	for _, endpoint := range []string{"relay", "connector", "client"} {
		matches, err := filepath.Glob(filepath.Join(root, endpoint, "*ca-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("issuer key copied into %s: %v", endpoint, matches)
		}
	}
	for _, key := range []string{
		"relay/outer-server-key.pem",
		"connector/outer-connector-key.pem",
		"connector/inner-connector-key.pem",
		"client/outer-client-key.pem",
		"client/inner-client-key.pem",
	} {
		info, err := os.Stat(filepath.Join(root, key))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %o", key, info.Mode().Perm())
		}
	}
}

func TestRunRefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := run(testOptions(root))
	if err == nil {
		t.Fatal("overwrote a nonempty credential directory")
	}
	contents, err := os.ReadFile(filepath.Join(root, "existing"))
	if err != nil || string(contents) != "keep" {
		t.Fatal("existing file changed")
	}
}

func TestRunRequiresRelayURL(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	value := testOptions(root)
	value.relayURL = ""
	if err := run(value); err == nil {
		t.Fatal("run accepted an empty relay URL")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("output path was touched before relay URL validation: %v", err)
	}
}

func TestRunRequiresRelayListen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	value := testOptions(root)
	value.relayListen = ""
	if err := run(value); err == nil {
		t.Fatal("run accepted an empty relay listen address")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("output path was touched before relay listen validation: %v", err)
	}
}

func TestRunRejectsUnsafeRelayListen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	value := testOptions(root)
	value.relayListen = "203.0.113.10:9087"
	if err := run(value); err == nil {
		t.Fatal("run accepted a non-loopback, non-unspecified relay listen address")
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("output path was touched before relay listen validation: %v", err)
	}
}

func TestRunRendersCustomConnectorRuntimePaths(t *testing.T) {
	root := filepath.Join(t.TempDir(), "secrets")
	value := testOptions(root)
	value.connectorRuntimeDir = "/var/lib/owntransit-example/runtime"
	if err := run(value); err != nil {
		t.Fatal(err)
	}

	connectorConfig, err := config.LoadConnector(filepath.Join(root, "connector", "config.json"))
	if err != nil {
		t.Fatalf("connector config: %v", err)
	}
	assertConnectorRuntimePaths(t, connectorConfig, value.connectorRuntimeDir)
}

func TestRunRejectsUnsafeConnectorRuntimePaths(t *testing.T) {
	tests := []string{
		"",
		"run/owntransit",
		"/",
		"/run/owntransit/",
		"/run//owntransit",
		"/run/../etc/owntransit",
		"/run/owntransit\nspoofed-log-line",
		string([]byte{'/', 'r', 'u', 'n', '/', 0xff}),
	}
	for _, runtimeDir := range tests {
		t.Run(runtimeDir, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "secrets")
			value := testOptions(root)
			value.connectorRuntimeDir = runtimeDir
			if err := run(value); err == nil {
				t.Fatalf("run accepted connector runtime directory %q", runtimeDir)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("output path was touched before runtime directory validation: %v", err)
			}
		})
	}
}

func TestValidateConnectorRuntimeDirAcceptsCanonicalAbsolutePaths(t *testing.T) {
	for _, runtimeDir := range []string{defaultConnectorRuntimeDir, "/var/lib/owntransit-example/runtime", "/srv/connector credentials"} {
		if err := validateConnectorRuntimeDir(runtimeDir); err != nil {
			t.Errorf("validateConnectorRuntimeDir(%q): %v", runtimeDir, err)
		}
	}
}

func testOptions(outputDir string) options {
	return options{
		outputDir:           outputDir,
		relayURL:            "wss://relay.example.com/connects",
		relayListen:         "127.0.0.1:9087",
		connectorRuntimeDir: defaultConnectorRuntimeDir,
		caValidity:          365 * 24 * time.Hour,
		validity:            24 * time.Hour,
	}
}

func assertConnectorRuntimePaths(t *testing.T, value config.Connector, runtimeDir string) {
	t.Helper()
	if len(value.InnerTLS.ClientCAFiles) != 1 {
		t.Fatalf("inner client CA paths = %v, want one", value.InnerTLS.ClientCAFiles)
	}
	paths := map[string]string{
		"outer certificate": value.OuterTLS.CertFile,
		"outer key":         value.OuterTLS.KeyFile,
		"outer CA":          value.OuterTLS.CAFile,
		"outer issuer CA":   value.OuterTLS.IssuerCAFile,
		"inner certificate": value.InnerTLS.CertFile,
		"inner key":         value.InnerTLS.KeyFile,
		"inner client CA":   value.InnerTLS.ClientCAFiles[0],
		"inner issuer CA":   value.InnerTLS.IssuerCAFile,
	}
	wantNames := map[string]string{
		"outer certificate": "outer-connector-cert.pem",
		"outer key":         "outer-connector-key.pem",
		"outer CA":          "relay-admission-ca-cert.pem",
		"outer issuer CA":   "relay-admission-ca-cert.pem",
		"inner certificate": "inner-connector-cert.pem",
		"inner key":         "inner-connector-key.pem",
		"inner client CA":   "inner-client-ca-cert.pem",
		"inner issuer CA":   "inner-connector-ca-cert.pem",
	}
	for name, got := range paths {
		want := runtimeDir + "/" + wantNames[name]
		if got != want {
			t.Errorf("%s path = %q, want %q", name, got, want)
		}
	}
}
