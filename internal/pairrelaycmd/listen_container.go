//go:build (darwin || linux) && owntransit_relay_container

package pairrelaycmd

// HTTPListen is reachable only inside the explicitly tagged relay container.
// The packaged rootless Podman boundary publishes it on host 127.0.0.1:9087.
const HTTPListen = "0.0.0.0:9087"
