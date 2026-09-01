//go:build owntransit_poc_ssh

package config

import "testing"

func TestConnectorSSHTargetExplicitPOCProfile(t *testing.T) {
	if ConnectorSSHTarget != "127.0.0.1:2222" {
		t.Fatalf("ConnectorSSHTarget = %q, want explicit POC endpoint", ConnectorSSHTarget)
	}
}
