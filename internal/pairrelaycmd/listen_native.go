//go:build (darwin || linux) && !owntransit_relay_container

package pairrelaycmd

import "github.com/sentrybottale/owntransit/internal/pairrelay"

// HTTPListen preserves the existing host upstream and never creates a public
// native listener.
const HTTPListen = "127.0.0.1:9087"

func ingressMode() pairrelay.IngressMode { return pairrelay.IngressLoopbackProxy }
