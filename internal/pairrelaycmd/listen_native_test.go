//go:build (darwin || linux) && !owntransit_relay_container

package pairrelaycmd

import "testing"

func TestNativeHTTPListenIsExistingLoopbackUpstream(t *testing.T) {
	if HTTPListen != "127.0.0.1:9087" {
		t.Fatalf("native HTTP listen = %q", HTTPListen)
	}
}
