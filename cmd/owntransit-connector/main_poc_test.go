//go:build owntransit_poc_ssh

package main

import "testing"

func TestExplicitPOCExecutableReportsCompiledSSH2222Target(t *testing.T) {
	if compiledConnectorTarget != "tcp4 127.0.0.1:2222" {
		t.Fatalf("compiledConnectorTarget = %q, want explicit development target", compiledConnectorTarget)
	}
}
