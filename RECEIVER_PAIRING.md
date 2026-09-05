# Receiver-owned pairing and circuit breaker

Status: implemented in the 0.1.1 development source, with integrated SSH tests.
See [the command walkthrough](PAIRING_INSTALL.md). It is not available in the
immutable 0.1.0 downloads. Local agent review and repository tests are not an
independent external security assessment. Legacy setup remains a separately
selected, unchanged profile; there is no automatic conversion of its authority.

## Product flow

The trusted receiving SSH machine's connector owns authorization for its route.
There is no separate endpoint provisioner or administrator ceremony in this new
mode. The relay remains fully malicious and carries no endpoint authority.

1. On the receiving machine, initialize the connector with the chosen relay
   origin. It creates its identities locally, retains them durably, opens an
   outbound rendezvous, and shows a public receiver ID and a separate private
   pairing code.
2. On the relay, register the public RECEIVER ID. The relay produces its routing
   and admission code. It never receives the private endpoint pairing code.
3. On the client, enter the relay details, relay code and private receiver code.
   The endpoints perform the authenticated exchange and save their pairing.
4. Fresh runtime mutual TLS and a successful fixed loopback SSH-port dial produce
   carrier READY. OpenSSH then performs its own host/user authentication.

The private code moves directly from the receiving machine to the intended
client through existing authenticated SSH/local-console access. It authorizes
the device that possesses it; it does not establish a person's identity.
Normal reconnection, certificate renewal and authorization refresh require no
user interaction. Lost identities or deliberate replacement require a new
explicit local pairing operation.

## Three different values

| Value | Purpose | Relay may know it? |
|---|---|---|
| Public receiver ID | Locate and bind a receiving connector's public identity | Yes |
| Relay code | Routing/admission to the selected relay | Yes; assume it can forge it |
| Private pairing code | One-use authority to pair a client with the expected receiver | No |

Use 256 bits of operating-system randomness for the private code, with a bounded
canonical encoding binding the receiver identity, pairing attempt and expiry.
It is copied and pasted, not shortened to a numeric PIN or comparison words.
Read it interactively; never accept it through argv, environment variables or
URLs, and never log it. Displaying it to the initiating local user is deliberate
secret disclosure, not ordinary diagnostic output.

A stolen valid code can authorize the thief before the intended client. Expiry,
private storage and atomic single-use handling limit exposure but cannot tell
two valid code holders apart. A public receiver ID or relay code alone must
never authorize pairing.

## Cryptographic construction

Prefer reuse of the existing standard signing, age-encrypted request/response,
CSR validation, TLS 1.3 and durable-record primitives. Do not invent a cipher or
derive long-term endpoint keys from the display code.

The receiver publishes a bounded signed advertisement containing its public
identity, route, public endpoint trust material and pairing-encryption recipient.
The client authenticates this advertisement using the independently obtained
receiver identity bound into its private code before encrypting the request.

The request contains target-generated public keys/CSRs, a fresh attempt nonce
and proof of private-code possession inside authenticated ciphertext. Bind the
exact receiver/client keys, roles, selected protocol, pairing attempt, route
and relay origin to the approved transcript. The receiver returns a signed
response encrypted only to that client. No private endpoint key is exported.

The receiver's privileged pairing operation may own narrowly route-scoped
issuer/deployment keys to reuse existing certificate machinery. These keys
belong in a protected store inaccessible to the unprivileged byte-forwarding
process. They confer no software-release signing authority. No issuer or
deployment-signing private key belongs on the relay.

A bounded relay-authenticated routing token can replace a writable relay
registry. Its claims can identify a receiver, route, public admission root,
limits and expiry. Because the relay owns its token key, it can forge admission
and routing; this must never establish inner endpoint authorization. Separate
relay-server trust from receiver-owned endpoint-admission trust explicitly.

Outer and inner runtime TLS 1.3 mTLS remain independent. Pairing transports
only setup messages. It never dials the SSH socket. Every data carrier must
complete current inner peer authorization before the connector dials literal
`tcp4 127.0.0.1:22`, then emits READY inside that inner stream.

## Durable pairing and renewal

The essential state transition is:

```text
pending -> atomically bound to one exact peer + code spent -> paired
pending -> cancelled/expired
```

Commit the peer binding, consumed code and state generation in one recoverable
local transaction. A crash or lost acknowledgement can resume only that exact
binding. An invalid unauthenticated message cannot reserve the code. Concurrent
valid claimants cannot both win. Spent, expired and cancelled codes never reopen.
Retries do not extend expiry or regenerate identities.

Retain a separate long-term pairing authentication key for automatic renewal.
Renewal requires possession of an already-authorized pairing key, fresh
challenges, exact route/peer binding and current local policy. Revoked or locked
pairs cannot renew. Short-lived operational TLS credentials rotate independently
of the initial pairing code. A relay error cannot erase pins, create a code,
replace an identity, select a weaker protocol or authorize new trust roots.

## Automatic authorization and emergency shutdown

Connection permission is the conjunction of committed pairing, fresh runtime
mTLS, unexpired peer authorization and local policy allowing the connection.
There is no user prompt during normal refresh or reconnect.

Use three distinct states:

- **Locally locked:** persistent; only an explicit local operation can clear it.
- **Authorization unavailable:** close affected traffic and retry automatically
  with the same trusted identity. Packet loss does not create a permanent lock.
- **Peer explicitly locked at generation G:** close that peer's traffic and
  reject older grants. A later authenticated peer generation may allow a new
  connection, but cannot override this endpoint's own local lock.

A local kill operation first blocks admission and renewal under a synchronized
authorization boundary. It durably records the lock and advances its policy
generation, cancels handshakes/dials, and closes affected active transports and
connector loopback sockets. It reports success only after persistence and local
shutdown complete. Every active client ProxyCommand must participate. Checking
a marker only at process startup is insufficient.

An authenticated peer kill notification may accelerate remote shutdown, but a
malicious relay can suppress it. Short peer-authorization leases therefore bound
the time before the opposite endpoint must close its side. An initial candidate
policy is a 60-second maximum lease, renewed every 20 seconds; these are proposed
values to test, not a measured guarantee or a user-facing setting to babysit.

Lease requirements:

1. The recipient sends a fresh challenge and records its local elapsed-time
   deadline. Validity starts at challenge issuance, NEVER delayed response
   arrival. Permit only one outstanding challenge per authorization scope.
2. Authenticate responses through the pinned end-to-end peer identity. Bind
   pair, roles, protocol, policy generation and the exact live data-session
   context. A grant for one session cannot refresh another.
3. Enforce the local maximum duration even if the peer requests a longer grant.
   Expiry is the earliest of lease, credential/session limits and local shutdown.
   Ordinary SSH bytes, SSH keepalives and relay heartbeats cannot extend it.
4. Use active expiry cancellation plus forwarding/admission synchronization;
   merely returning bytes with an expiry error can still let a copier forward
   those bytes. Close both inner transport and local SSH socket as applicable.
5. Keep authorization control separate from raw SSH bytes, using a bounded,
   explicitly identified end-to-end exchange bound to the data session. Never
   insert control messages into ProxyCommand stdout.
6. Discard leases/challenges on process restart and require fresh authorization.
   Preserve locks and policy-generation high-water marks. Wall-clock rollback
   must not extend validity. Suspend/resume must force fresh authorization when
   elapsed validity cannot be established safely on that platform.

With a functioning endpoint, remote shutdown is bounded by the maximum remaining
lease plus scheduling/shutdown latency. It is not guaranteed simultaneous or
instantaneous across a hostile relay. Unlock requires fresh authentication; an
old allow/unlock message cannot override a newer locked generation.

TLS already authenticates records continuously. TLS 1.3 KeyUpdate changes traffic
keys; it is not a new endpoint identity check. Each new carrier uses a fresh
handshake without resumption/0-RTT in the initial profile. Do not destroy live
SSH streams simply to simulate reauthentication, and never reconnect/replay an
old SSH byte stream into a replacement carrier.

## Additional defenses worth keeping

- Strict bounded parsing, fixed cardinality/resource budgets, handshake timeouts
  and per-authenticated-peer quotas before any target dial.
- Root-protected authority/policy state separated from the unprivileged data
  process; least-privilege endpoint services and a restricted relay container.
- Local event-only audit records for pairing, expiry, lock, unlock and rejected
  identity changes. No SSH payloads, private codes, keys or bearer-token logs.
- Explicit peer revocation that closes existing authorization and also blocks
  renewal/recovery routes; code retirement persists through ordinary rollback.
- Separate software-release trust and bounded, authenticated installation. The
  relay cannot authorize software, endpoint policy, pairing reset or recovery.

## Compatibility and implementation proof

This requires a new explicitly selected pairing/control profile, strict schemas
and authentication domains. Keep legacy v1 bytes and administrator semantics
unchanged; never implement this as a bypass flag for the existing setup command.
The SSH copy loop, fixed target, standard cryptographic primitives and much of
the runtime activation machinery can be reused, but authorization-lease gating
and control exchanges require additional code and tests.

Existing v1 connectors do not possess their former provisioner's authority
keys. Migration must create receiver-owned authority and explicitly re-pair
clients; no automatic authority conversion or pin replacement. Preserve
existing access until an explicit cutover has proved the new path. No SSH key,
account, configuration or website migration is part of OwnTransit pairing.

Before release, exercise malicious-relay substitutions; stolen-code/racing
claimants; crashes at each commit boundary; lost acknowledgement before/after
commit; expiry and cancellation; delayed/stockpiled lease responses; wrong
session/route/origin; reconnect, restart and suspend; kill/admission races;
revocation versus renewal; and mixed-version/downgrade attempts. Tests must
prove no premature SSH dial, no second winning peer, no renewed old grant and
no reappearing spent code. These are implementation tests, not a certification
program or a requirement for new physical machines.

Full endpoint-state rollback/cloning, compromised endpoint root and an
unresponsive operating system remain outside the guarantee. A kill cannot
retract delivered bytes or ensure an SSH-started process terminates. OpenSSH
still owns SSH identities, account access, authorization and host recovery.

References: [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html),
[NIST zero-trust architecture](https://csrc.nist.gov/pubs/sp/800/207/final),
[legacy compatibility](COMPATIBILITY.md).
