# OwnTransit credential lifecycle

This document defines the intended public v1 credential contract. It contains
no deployment inventory, private endpoints, access commands, or credential
identifiers.

OwnTransit credentials protect the carrier. They do not replace or manage
OpenSSH host keys, user keys, accounts, authorization, forwarding, or recovery.

## Trust authorities

Each route has three independent offline certificate authorities:

- the outer relay-admission CA, which issues the relay server leaf and the
  outbound client and connector admission leaves;
- the inner connector CA, which issues the connector's end-to-end TLS server
  leaf; and
- the inner client-capability CA, which issues client capabilities for one
  connector and one route.

The deployment-signing key is separate from all three issuer keys. Software
release signing is a separate authority again. No client, connector, relay, or
online service receives an issuer, deployment-signing, or release-signing
private key.

There is deliberately no global client-capability issuer. Compromise of a
route's inner client-capability CA can mint capabilities for that route, so its
scope, offline custody, expiry, revocation, and rotation are part of the
authorization boundary.

## Bootstrap trust

Before enrollment, each target must authenticate the expected issuer
certificate pins, deployment-verifier identity, compatible release identity,
role and runtime binding through an independently established,
bidirectionally authenticated out-of-band procedure. Those bytes may arrive
tentatively in an invitation; delivery does not make them trusted. The
enrollment response cannot authenticate its own verifier. The public relay,
DNS, a download redirect and TOFU are not bootstrap authorities.

The operator compares the target-generated request digest through the same or
another trusted channel before approval. A copied request is public material,
but substituting one must be detectable before issuance.

## Initial enrollment

The source tree implements the initial three-target enrollment transaction:

1. Each intended target creates a unique installation ID, fresh outer and
   inner private keys, CSRs proving possession, a request nonce, and an
   ephemeral response-recipient key. Operational private keys never leave the
   target.
2. The offline operator verifies all three request digests and checks the
   relay, connector, client, route, and release bindings.
3. The offline provisioner issues only the requested leaves. It signs each
   deployment and encrypts the response to that target's one-time recipient.
4. The target accepts only the response bound to its retained request,
   bootstrap authorities, role, installation ID, nonce, sequence, release, and
   runtime profile.
5. Apply validates the CSR/public-key match, certificate chain, Ed25519 key
   profile, EKU, exact identity, validity, pins, and monotonic state. It writes
   a complete write-once lifecycle generation before atomically selecting it
   as active.
6. The endpoints prove the OwnTransit inner TLS carrier and the connector's
   fixed loopback socket separately from any OpenSSH login test.

The 0.1.0 implementation also includes a bounded guided exchange, resumable
target state, runtime-bound carrier proof and local retirement after `READY`.
Initial three-target enrollment and guided client setup are within its
candidate scope. An official stable handoff still has to authenticate its exact
release assets and carry an independently verified signed qualification record
whose hard supported-platform gates pass. Broader recovery and the end-to-end
operator rotation ceremony below are operational scope, not authority
delegated to the relay.

## Route capability identity

The connector does not maintain a positive list of client certificates or
client IDs. For one route it accepts a client certificate only under the exact
locally installed inner client-capability CA, the capability ALPN, the required
client-auth EKU, and the canonical identity:

```text
i-<client-id>.r-<route-id>.c-<connector-id>.e-<16-hex-epoch>.client-cap.v1.owntransit.invalid
```

The client independently requires the exact connector SPKI pin and canonical
connector identity:

```text
i-<connector-id>.r-<route-id>.connector.v1.owntransit.invalid
```

These are authenticated certificate names under the reserved `.invalid`
suffix, not DNS discovery names. Every identifier and the nonzero epoch uses
one canonical encoding. A capability for another client, connector, route, or
epoch is a different identity and must fail before the connector dials
`tcp4 127.0.0.1:22`.

A bounded, authenticated tombstone set may reject named client installation
IDs or SPKI pins without becoming a positive allowlist. Ordinary connector
state carries exactly one inner client-capability root; exactly two distinct
roots are allowed only during an explicit root-overlap ceremony.

## Rotation and revocation

The required rotation design is verifier-first overlap, never in-place
overwrite:

1. Generate new operational keys and CSRs on the target.
2. Install the new verifier while retaining the old verifier. Connector-leaf
   rotation overlaps exact connector pins; capability-root rotation overlaps
   exactly two roots.
3. Activate a complete new release/config/credential record.
4. Prove the new inner carrier and preserve the exact previous record only
   while rollback policy still authorizes it.
5. Remove and tombstone the superseded identity or root, advance the signed
   rollback floor, and prove that new sessions using the old identity fail.

Credential, deployment, and release sequences are independent monotonic
high-water marks. Durable state binds the active record digest and its exact
sequence tuple. Revocation and rollback floors must survive ordinary binary or
configuration rollback. Established sessions have finite idle and absolute
limits because changing a verifier affects new handshakes, not already
authenticated streams.

The repository implements strict signed lifecycle-policy and rollback records,
verifier-first policy application, post-initial route approval, cumulative
revocation/tombstone state, an external exact-state rollback anchor, derived
rollback generations that retain current denials, and interrupted anchor-first
transaction recovery. The initial-enrollment approval remains first-sequence
only; rotation uses its separate post-initial approval path.

OwnTransit 0.1.0 does not promise automated expiry monitoring or a turnkey
clean-room credential-recovery service. Package/service coordination is
manager-held in source, while authenticated revocation distribution,
third-generation retirement, operator receipt review, two-location custody and
clean-room recovery remain operator procedures that require their own review
and rehearsal. Do not manually sequence internal commands and describe the
result as an automated or independently certified rotation or recovery
ceremony.

## Custody and recovery

Keep offline issuers, deployment and release signers, encrypted inventory,
rollback floors, and revocation records in two independently recoverable
custody locations. Keep the ciphertext and its decryption credentials
separate. A clean-room exercise must reconstruct issuance, verification,
rotation, revocation, and durable OwnTransit state without the development
workstation.

This recovery boundary covers OwnTransit only. OpenSSH and host recovery remain
entirely operator-owned. No real credential value, fingerprint, target
inventory, or access procedure belongs in the public repository.
