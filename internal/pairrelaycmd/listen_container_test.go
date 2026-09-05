//go:build (darwin || linux) && owntransit_relay_container

package pairrelaycmd

import "testing"

func TestContainerHTTPListenUsesOnlyPackagedContainerPort(t *testing.T) {
	if HTTPListen != "0.0.0.0:9087" {
		t.Fatalf("container HTTP listen = %q", HTTPListen)
	}
}
