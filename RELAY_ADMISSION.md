# Relay admission and publication hardening

This unreleased patch addresses two public-client availability failures in the
current receiver-owned Relay. It keeps the existing public WebSocket, framing,
pairing, TLS and private endpoint-state formats.

## Admission through the selected reverse proxy

Previously, every public client behind one proxy shared the Relay's eight-slot
pre-authentication TCP-peer bucket. Eight stalled upgrades could block unrelated
clients until the attacker stopped refreshing them.

The selected Nginx, Caddy or Apache route now overwrites `OwnTransit-Peer-IP` with
its original TCP peer. Nginx uses `$realip_remote_addr`, Caddy uses `{remote_host}`,
and Apache uses `CONN_REMOTE_ADDR`; request-supplied forwarding addresses do not
select that value. The Relay accepts this private-hop metadata only in its
locally selected proxy ingress, from loopback or the packaged private bridge.
It requires one canonical IP and retains the independent global concurrency,
rate, peer-table and handshake-deadline limits.

The Apache route also replaces `Connection` with `upgrade`, preventing a client
from nominating the private-hop field for removal by the proxy. Nginx already
replaces that header, and the Caddy overwrite survives the same client nomination.

Nginx requires its RealIP module and Apache requires `mod_headers` alongside
the usual proxy modules. Provider validation fails safely when that support is
unavailable; the prior route and service selection are retained.

This metadata is an availability hint from a transit component. It never
authorizes an endpoint, an inner TLS peer, enrollment, a route or an SSH target.
A compromised proxy remains able to deny service.

## Pending and approved publications

Public advertisements prove their own structure and signature, so anyone can
generate them. Previously, 256 unapproved publications could occupy the entire
shared map for 24 hours and prevent a new receiver from publishing.

Unapproved advertisements and offers now share a separate bounded pending
cache, with 64 entries and a two-minute lifetime by default. At capacity, a new
pending publication evicts a pending entry instead of failing because of a
day-long allocation. Approved and observed receivers use protected capacity
only when their exact IDs and admission-root digest match saved local policy.
Both cache lifetimes end no later than the advertisement's signed expiry.

Local approval promotes the exact entry only after policy persistence succeeds.
Removal disables public offer lookup and retains one bounded local copy for
explicit reapproval; public publications cannot refresh that retained copy.
Existing token delivery and runtime
authorization remain separate, so ordinary reconnects do not require a fresh
pairing code or a still-valid one-use advertisement.

## Upgrade and rollback

Install the updated Relay software, then use **Start or update this relay** for
the existing selected Relay URL. Local setup must reconcile the selected website
route as well as the image. Other sites and endpoint pairings are outside that
operation. A custom or ambiguous route that cannot be reconciled safely fails
before it is treated as protected admission.

An old route without the header continues using the old shared bucket. Updating
only the container therefore does not establish source fairness. The setup
transaction retains route rollback material and refuses to overwrite site
changes made outside that transaction.

Older Relay binaries ignore the new private-hop header and can use the updated
route, but their original availability weaknesses return. Finish or recover an
interrupted setup with the updated management executable before downgrading;
older management code cannot recover the new route-change journal. No endpoint
key rotation, origin replacement or authenticated wire migration is required.

## Validation

Regression fixtures exercise eight stalled upgrades from one real source address
through a shared proxy, successful admission from a second source, overwritten
spoofed headers, strict metadata parsing, publication saturation, approved-entry
survival, signed expiry, removal/reapproval and retained-token recovery. Managed
route fixtures cover provider configuration, idempotent updates and rollback.
The required race and vet checks run with both production and POC SSH profiles.

The conditional raw-command issue in the separately shipped historical 0.1.0
administrator-led profile is not changed here. Removing its raw approval commands
would also remove its only fresh issuance path. A future change must supply
ceremony-gated issuance and activation before claiming that workflow remains
usable. Current 1.0.4 Client/Target setup does not ship those commands.
