# Renewal recovery in 1.0.4

A retained pairing must survive an outage that spans a renewal request's
one-hour validity window, whether the Target committed the request or never
received it. Version 1.0.3 recovered only the committed case. Version 1.0.4
adds an authenticated, read-only generation query for the other case and for
ambiguous lost responses. Initial pairing is still a separate one-use ceremony;
this extension cannot create a pairing or revive an expired pairing code.

## Authority and bounded state

The extension is explicitly identified as `owntransit-renewal-status/1`.
Its request and response have separate `owntransit.renewal-status.*.v1` schemas
for signed payloads, signed envelopes and encrypted envelopes. Signatures use
the distinct `OwnTransit renewal status request v1` and
`OwnTransit renewal status response v1` domains. Existing carrier framing,
WebSocket subprotocol, TLS ALPN, pairing/renewal messages and private-state
schemas remain unchanged. Existing relays carry the same bounded opaque blobs.

The Client signs a query with its retained long-term pairing key and encrypts
it to the pinned Target age recipient. It binds the exact receiver, route,
origin and client, the retained pending request digest and its known base
generation, a fresh random nonce, a fresh response recipient and a one-minute
window. The query and response use the existing strict canonical JSON,
512-KiB padding class and one-MiB wire bounds. Unknown fields and schemas fail.

The Target checks its local and peer locks/revocation, authenticates the query
against the already paired key, validates its scope and freshness, and reads
its generation under the same authority lock used by renewal commits. It can
answer only when its generation is the query's base generation or exactly one
higher. It signs and encrypts a reply binding the whole query ciphertext digest,
pending request digest, same scope and exact query window. It performs no
state write, credential issuance or SSH dial. A claimed generation is not
accepted from the Relay, an unsigned error, silence or a timeout.

The Client accepts only a reply for that fresh query and pinned Target. The
reply can prepare a new ordinary renewal at the authenticated generation plus
one; it cannot activate credentials. The Client atomically saves the new
request and new operational keys in the existing pending fields while retaining
its previous active pairing, keys, authorization and trust together. Only a
currently valid ordinary signed renewal response and normal certificate/key/
trust checks replace that active set. Fresh runtime mTLS, session authorization
and the fixed local Target dial still precede READY and SSH bytes.

## Loss, delay, restart and repeated expiry

Each opening first tries the exact retained ordinary request, for at most ten
seconds. Transient dialing failures retry that same request with bounded backoff
so older Targets retain ordinary reconnect behavior. A valid response or the 1.0.3 expired committed receipt takes the
existing path. If the exchange fails, the remaining part of the existing
30-second opening budget may perform one status reconciliation and fresh
renewal. HTTP 429 does not start another immediate status operation. Status and
fresh-request retries retain bounded backoff; local cancellation/alarm applies
throughout. A permanently unavailable or malicious Relay can still deny service.

A snapshot does **not** assert that an old request can never commit. If an old
request arrives after the query and commits first, the ordinary next-generation
check rejects the competing replacement. The next opening obtains a fresh
snapshot and recovers. A replayed query/reply cannot grant credentials, roll
back a generation or cause an unbounded request history to accumulate. Replies
from a previous opening do not match its new response recipient/query digest.

The query is transient; losing it changes no durable state. Before the fresh
request is saved, restart retains the original request. After the atomic save,
restart retains exactly the fresh request and matching keys. After Target
commit but before Client activation, its normal exact retry returns the cached
response. If either the new request or its response expires again, another
opening can reconcile again. No finite fallback-request list is exhausted.

Only one locally pending generation may be ahead of the last authenticated
base. The extension refuses larger gaps rather than treating arbitrary stale
backups, concurrent cloned Clients, or rolled-back Target authority as current
state. Whole-state rollback/cloning and compromised endpoints remain outside
this recovery guarantee. Expired issuer roots and deliberate revocation still
fail closed; the extension does not renew or replace those authorities.

## Upgrade, mixed versions and rollback

Upgrade the **Target and Client to 1.0.4**, preferably Target first, to recover
an expired uncommitted request. Continue their existing named tunnel; do not
create a new pairing. The Relay needs no upgrade for this extension. Installation
and activation are separate local-role operations; updating a Target executable
requires continuing/restarting its selected service to run that executable.

- Old Client + new Target: ordinary pairing, renewal and 1.0.3 receipt behavior
  remain supported. The old Client does not gain status recovery.
- New Client + old Target: ordinary renewal and committed-receipt recovery remain
  supported. An unsupported status query is rejected. Its absence leaves the
  retained request and trust untouched; it never selects weaker authentication.
- Both new: repeated uncommitted expiry and ambiguous competing commits can
  reconcile without re-pairing, subject to current local policy and connectivity.
- Binary rollback: no new durable fields or authority schema are introduced.
  A 1.0.3 Client can parse and resume a fresh staged ordinary renewal or use
  completed credentials. Rolling either endpoint back can restore the previous
  failure if status recovery is needed again. Rollback does not undo a committed
  generation, clear an alarm, or permit replacing state with an older backup.

## Review and regression coverage

| Case | Required result |
|---|---|
| Pending request never delivered and expired | Authenticate current Target generation; issue fresh credentials |
| Committed response lost or expired | Retain exact-receipt recovery and status reconciliation |
| Repeated request/response expiry | Recover without accumulating fallback records |
| Delayed old request commits after snapshot | Reject competing generation, then reconcile on retry |
| Lost status reply or unsupported Target | Preserve pending material and active credentials |
| Restart before fresh exchange / after Target commit | Resume exact durable request and keys |
| Forged, crossed, stale, future, unknown or malformed status | Reject before staging or issuance |
| Wrong signing key, recipient, scope, query or request digest | Reject |
| Generation rollback, jump or exhaustion | Reject |
| Local cancellation, removal, alarm or Target revocation | No recovery admission or SSH dial |
| Existing v1 renewal/state readers | Status is not a credential grant; staged state remains ordinary v1 |
| Software upgrade from 1.0.3 | Preserve identities, managed service confinement and SSH ownership |

The scope is renewal/reconnect recovery, its authorization boundaries and the
release/upgrade path. Source tests and native checks are not an independent
cryptographic assessment or proof that a particular live tunnel has recovered.
