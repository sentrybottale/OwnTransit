# OwnTransit security policy

## Release status

OwnTransit has no supported production release. The tunnel, route-capability
profile, initial target-generated enrollment/apply path, signed verifier-first
lifecycle policy, route-rotation issuance, revocation overlays, external
rollback anchor, exact-record rollback and signed release/policy verification
exist in source. Guided exchange and manager-bound package activation also
exist in the v1 release candidate. They remain unqualified security and
operating primitives: authenticated distribution, clean-host lifecycle and
recovery drills, signer/issuer custody and independent review remain shipment
gates.

Do not rely on the current tree as a system's only transport path. SSH and host
recovery are operator responsibilities and must remain independently available.

## Reporting a vulnerability

When this repository is published on GitHub, use its private security-advisory
feature. Do not open a public issue for a suspected vulnerability, secret or
deployment exposure. Include:

- affected revision and component;
- minimal reproduction or malformed input;
- expected and observed security boundary;
- whether endpoint, relay or local privileges are required; and
- any evidence that a credential or real deployment may be affected.

Until the repository has a canonical public owner/contact, keep the report
private and do not send secrets through ordinary issue trackers.

## Security boundary

OwnTransit assumes the public reverse proxy, relay host, process, configuration
and relay keys are fully compromised. They may observe metadata, ignore
admission rules, cross-wire attempts and deny service. They must remain unable
to decrypt or forge the independently keyed inner client-to-connector TLS
stream.

Each endpoint-to-relay leg uses an outer TLS carrier, and the endpoints create
a separate inner TLS 1.3 mTLS stream through it. SSH is independently encrypted
inside that stream. Compromise of the relay can therefore expose metadata and
availability, but it must not collapse either the inner OwnTransit boundary or
the separate SSH boundary.

Both endpoint roles originate every OwnTransit connection. Neither exposes an
OwnTransit listener or requires a public address; only the relay is publicly
reachable.

The client, connector, offline issuers and software/deployment signers are
explicit OwnTransit trust anchors. OpenSSH host/user keys and policy form a
separate, operator-owned security boundary inside the carried stream; they are
not OwnTransit credentials. A compromise of either endpoint is not hidden by the
relay threat model.

OwnTransit owns only the encrypted byte carrier and its endpoint credentials.
It never creates, selects, stores or edits SSH identities, accounts,
authorization, client/server configuration, forwarding or recovery.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component and key boundaries.

## Security invariants

- TLS 1.3 only; mutual authentication on both outer and inner boundaries. Outer
  mTLS is admission defense in depth, not trusted authorization once the relay
  is malicious.
- Exact OwnTransit role, EKU and SAN authorization everywhere. Outer profiles
  and the client's connector check retain exact SPKI pins. A capability-profile
  connector instead requires the exact route-specific client CA plus strict
  connector/route/epoch SAN binding and local revocation state; it has no
  positive client list.
- Newly enrolled runtimes validate each local key/leaf against its explicit
  issuer, exact configured role name and validity window before opening a
  network connection.
- Session resumption disabled for the authenticated profiles. The capability
  profile uses a distinct ALPN, so it cannot fall back to legacy exact-pin TLS.
- Connector local dial occurs only after successful inner authentication.
- Production target is build-fixed to literal `tcp4 127.0.0.1:22`.
- Strict fixed-size rendezvous frames and bounded state/time/resource use,
  including fixed-cardinality DNS-keyed client admission state, a one-per-second
  OPEN rate with burst four, relay per-client pending/active quotas, and a
  post-handshake connector per-client active quota whose zero-count entries are
  deleted.
- No endpoint, issuer, release or deployment secrets on the relay.
- No relay-controlled enrollment, target, software update or rollback channel.
- Proxy stdout contains only SSH bytes.
- Unique endpoint keys per physical installation.
- A distinct offline client-capability root per connector/route; never a global
  capability issuer. One root is normal and a second is accepted only during an
  explicit signed-state rotation overlap.
- Signed, sequenced and reversible release/config/credential tuples before v1.

Initial public trust may be transported tentatively through the invitation,
but the exact transcript becomes trusted only through an independently
established, bidirectionally authenticated out-of-band procedure. The relay and
enrollment response may carry no authority to replace issuer roots, the
deployment verifier, release trust or rollback floors. There is no TOFU mode
for those anchors.

The route-capability profile intentionally accepts any unrevoked client leaf
issued by that route root. This removes connector-side per-client configuration
and leaves OpenSSH to decide login authorization, but it makes theft of that
route issuer sufficient to mint new capabilities for the route. The legacy
exact-pin migration profile has stronger issuer-compromise resistance because a
new leaf also needs a preinstalled SPKI pin. This tradeoff is explicit, scoped
to one connector/route, and not hidden behind an empty allowlist.

## Current stop-ship classes

- end-to-end integration and clean-host qualification of the implemented
  verifier-first leaf/root rotation, revocation, floor and exact-record
  rollback primitives;
- expiry monitoring, authenticated revocation distribution, third-generation
  retirement and two-location issuer/signing recovery rehearsals;
- clean-host qualification of the manager-held compare-and-swap spanning
  signed release verification, external release-policy anchor advancement,
  package selector publication and service integration;
- independent review and real-host qualification of the complete trusted
  bootstrap and guided hostile-mailbox ceremony;
- authenticated native distribution and qualified connector/client privilege
  boundaries on every supported platform;
- interrupted-transaction, disk-full, power-loss and clean-host platform
  qualification; and
- independent implementation review and penetration testing.

Initial enrollment working in source does not close these gates. In particular,
the connector's lack of a positive client list increases the importance of
offline route-issuer custody, bounded revocation state and a rehearsed issuer
rotation procedure.

## Known implementation limitations

The current source has additional fail-closed limitations that must remain
visible during release work:

- Endpoint lifecycle activation now uses descriptor-held runtime generations,
  a final pre-network check, root-published read-only views and a separately
  rooted exact-state rollback anchor. Those pieces have not passed the native
  package, privilege, reboot, interruption and hostile-filesystem matrix.
- Release bundle and policy verification, external release-policy anchor
  compare-and-swap and selector publication are bound by one manager-held
  transaction. That boundary has not passed clean-host privilege, interruption
  and recovery qualification; a detached verified decision remains
  intentionally unusable as install authorization.
- Bootstrap release ID, artifact digest, platform and architecture are
  authenticated operator inputs; `owntransitctl` does not yet measure the
  installed executable and derive those values itself.
- Anchor-first endpoint recovery can finish an exact interrupted transition,
  but authenticated garbage collection, third-record retirement and complete
  clean-room recovery policy are not integrated or qualified.
- The initial provisioner creates distinct keys but stores the three issuer
  keys and deployment signer unencrypted beneath one private `0700` directory.
  This proves logical key separation, not two-location custodial separation.
- Consumed-request history is bounded at 4096 entries and then fails closed;
  authenticated compaction has not been designed.

These are local endpoint, lifecycle and custody concerns. They do not give a
malicious relay inner-stream plaintext, accepted endpoint-forgery authority or
connector target-selection authority.

## Secrets and examples

Never commit real keys, tokens, passwords, passphrases, endpoint bundles,
fingerprints, hostnames, public IPs or deployment logs. Public examples use
only reserved names and documentation address ranges.

If a real secret ever enters a commit, deleting the working-tree file is not
remediation. Revoke/rotate it first, then clean the publication history through
a separately reviewed process.

## Cryptography policy

Use the standard-library TLS 1.3 implementation and reviewed standard envelope
and signing constructions. Do not introduce custom encryption, home-grown key
derivation, ambiguous signed serialization or a new handshake pattern without a
written threat analysis, test vectors, negative tests and independent review.
