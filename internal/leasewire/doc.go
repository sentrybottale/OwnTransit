// Package leasewire implements a bounded, explicitly versioned authorization
// lease channel inside an already authenticated end-to-end TLS connection.
//
// Wire contract (all integers are unsigned big-endian): each frame starts with
// "OTLW", version byte 1, type byte, and a uint16 payload length. DATA is 1..16384
// bytes. CHALLENGE is context[32], sender-generation[8], nonce[32], requested
// duration-nanoseconds[8]. GRANT is context[32], issuer-generation[8], requester-
// generation[8], nonce[32], granted-duration-nanoseconds[8]. LOCK is context[32]
// and generation[8]. Unknown versions, types and lengths close the connection.
//
// The directional context is SHA-256 of a fixed domain, length-delimited ALPN,
// pair ID, sender ID and recipient ID, then the fresh 32-byte inner TLS exporter.
// TLS authenticates every frame; this hash is only an unambiguous binding, not
// a signature or new trust anchor. The caller must enforce the ALPN and obtain
// the exporter only after exact mutual TLS peer authorization. There is no
// legacy negotiation or fallback in this package.
//
// One outstanding random challenge is retained per endpoint. A grant can only
// shorten the requester's bounded duration. Its deadline is the challenge's
// issuance time plus the granted duration, never the grant's arrival time. Both
// monotonic elapsed time and wall time can expire this deadline; neither can
// extend the other's budget. Backward clock movement or a wall/elapsed mismatch
// greater than 250ms closes the connection. Expiry is checked before forwarding
// and by an independent 25ms watcher. Scheduling and a functioning local OS remain
// assumptions; full host snapshots, cloned state and host-root compromise cannot
// be repaired here.
//
// WaitReady requires a valid peer grant and successful transmission of our
// grant. It does not prove that the peer application received every transmitted
// byte. The caller must gate the fixed local SSH dial on this fresh readiness,
// register the connection with its local lock manager without an admission
// race, and close its local SSH socket when Done closes. DATA activity cannot
// renew a lease. Control and DATA queues are bounded; a stalled DATA consumer
// can cause lease expiry, never an authorization extension.
//
// Policy locks and policy-generation changes close existing connections.
// Policy polling is at most 100ms apart while its callback returns promptly;
// explicit local lock operations should call Lock on every registered
// connection for immediate cancellation. A stalled policy callback does not
// block the independent expiry watcher. Peer LOCK and missing grants terminate
// only the current carrier and do not write a persistent local lock. Automatic
// retries require a fresh authenticated TLS stream and fresh challenges; they
// must never reconnect/replay the old SSH byte stream. The caller owns all
// durable state, local unlock decisions, credential validity and lifetime caps.
package leasewire
