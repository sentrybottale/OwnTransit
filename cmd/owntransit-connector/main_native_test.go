//go:build !owntransit_poc_ssh

package main

import "testing"

func TestProductionConnectorExecutableReportsOnlyLoopbackSSH22(t *testing.T) {
	if compiledConnectorTarget != "tcp4 127.0.0.1:22" {
		t.Fatalf("compiled connector target = %q", compiledConnectorTarget)
	}
}
