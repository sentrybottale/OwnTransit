//go:build !owntransit_poc_ssh

package config

import "testing"

func TestConnectorSSHTargetProductionDefault(t *testing.T) {
	if ConnectorSSHTarget != "127.0.0.1:22" {
		t.Fatalf("ConnectorSSHTarget = %q, want production SSH endpoint", ConnectorSSHTarget)
	}
}
