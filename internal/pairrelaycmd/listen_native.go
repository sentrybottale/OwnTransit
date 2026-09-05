//go:build (darwin || linux) && !owntransit_relay_container

package pairrelaycmd

// HTTPListen preserves the existing host upstream and never creates a public
// native listener.
const HTTPListen = "127.0.0.1:9087"
