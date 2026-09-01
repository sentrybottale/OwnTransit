# OwnTransit v1 shipping plan

Status: **v1 release candidate**. The tunnel, guided client exchange,
target-local credential lifecycle, signed package transaction and publication
boundaries exist in source. Production status still requires real
supported-host qualification, release-key/custody execution, independent
reproduction and outside security/legal review.

## Product contract

OwnTransit v1 is a subscriptionless, SSH-only encrypted carrier:

> Your SSH. Your keys. Untrusted transit.

Both endpoint roles originate every OwnTransit connection. Neither the client
nor connector exposes an OwnTransit listener or needs a public address. Only
the relay is publicly reachable.

The relay and its host, reverse proxy, process, configuration, and keys are
treated as fully compromised. They may observe IP addresses, timing, sizes, and
route correlations; cross-wire, delay, replay, or drop traffic; and deny
service. They must not obtain carrier plaintext, forge an accepted endpoint,
choose a connector target, issue a capability, enroll a target, or authorize an
upgrade or rollback.

The transport is encrypted twice independently of SSH:

1. each endpoint uses TLS 1.3 mTLS to reach the public relay; and
2. the client establishes a distinct TLS 1.3 mTLS stream through that relay to
   the connector.

OpenSSH then runs inside the inner stream with its own encryption, server and
user authentication, accounts, authorization, forwarding, and recovery. Those
are operator responsibilities. OwnTransit never creates, selects, stores, or
edits SSH keys, users, `authorized_keys`, SSH configuration, or recovery state.

The connector has one build-fixed destination: literal
`tcp4 127.0.0.1:22`. No runtime setting, environment variable, DNS result,
relay message, or client input may alter it.

V1 is not a VPN, network interface, service mesh, DNS system, controller,
identity provider, dashboard, multi-service reverse proxy, or enterprise Zero
Trust platform. It has no P2P path, SSO, device posture, or automatic updater.

## Compatibility contract

V1 preserves the authenticated legacy inputs in `COMPATIBILITY.md` byte for
byte, including protocol and ALPN values, rendezvous framing, READY marker,
WebSocket subprotocol, certificate-name formats, route/session encoding, and
version bytes.

The public route-capability profile is separately identified as
`owntransit-route-capability/1` and negotiates its own inner ALPN. It never
silently reinterprets an old exact-pin profile. Any future wire change requires
an explicit version, mixed-version tests, downgrade analysis, migration, and
rollback design.

## Capability authorization

The connector deliberately has no positive client certificate or client-ID
allowlist. A client is authorized only when all of these independently match:

- the capability-specific inner ALPN;
- the exact locally installed inner client-capability CA for this route;
- a strict Ed25519 client-auth certificate profile;
- the connector and route bound into local configuration; and
- the exact canonical client identity and nonzero credential epoch:

```text
i-<client-id>.r-<route-id>.c-<connector-id>.e-<16-hex-epoch>.client-cap.v1.owntransit.invalid
```

The client independently requires the connector's exact SPKI pin, server-auth
profile, and canonical connector identity:

```text
i-<connector-id>.r-<route-id>.connector.v1.owntransit.invalid
```

The `.invalid` suffix makes these authenticated certificate identities, not DNS
discovery names. A route-capability issuer is offline and scoped to one
connector/route authorization domain. There is no global capability CA. A
compromised route issuer can mint capabilities inside its scope, which is why
issuer custody, expiry, tombstones, rotation, and rollback floors are release
requirements.

Ordinary connector state installs exactly one client-capability root. Exactly
two distinct roots are allowed only for a verifier-first root-rotation overlap.
A bounded authenticated tombstone set may deny client installation IDs or SPKI
pins without becoming a positive allowlist.

## Public release artifacts

The v1 release candidate contains exactly these logical
artifacts:

| Artifact | Platform | Responsibility |
|---|---|---|
| `owntransit` | macOS arm64 | On-demand outbound stdio carrier for an operator-owned OpenSSH ProxyCommand |
| `owntransit-launcher` | macOS arm64 | Fixed setgid launcher bound to one local UID, GeneratedUID, release and client digest |
| `owntransit` | Linux amd64 | The same outbound-only client carrier |
| `owntransit-connector` | Linux amd64 | Outbound-only daemon with the fixed loopback SSH target |
| `owntransit-relay` | Linux amd64 OCI image | Hostile rendezvous and byte-copy relay; no inner TLS termination |
| `owntransitctl` | macOS arm64 and Linux amd64 | Target-local enrollment and lifecycle state |
| `owntransit-provision` | macOS arm64 and Linux amd64 | Offline route authority and response creation |

The release manifest records the two clients, the macOS launcher, connector,
relay, and both platform builds of the two administrative tools as nine
separate artifact records. Each record binds its bytes, SHA-256 digest, size,
role, platform, format, and named SBOM evidence. Licenses are independent
evidence.

Other architectures are unsupported until their native package, clean-host,
upgrade, rollback, and qualification matrices pass. Cross-compilation alone is
not support evidence.

## Intended command surface

The public client interface remains narrow:

```text
owntransit version
owntransit setup invitation.otinvite
owntransit setup --resume
owntransit setup --cancel
owntransit ssh-config [--user user] alias
```

`setup` is the guided recipient workflow: the invitation path is required on
the first run, `--resume` continues the exact retained request, and `--cancel`
terminally abandons it before activation. `ssh-config` prints a fixed
ProxyCommand stanza but never edits the user's files. Runtime doctor/proxy and
configuration validation remain protected installed-entry or
engineering/packaging interfaces, not paths or JSON the SSH user selects.

The usability target is a practical IT operator who can install a package and
use SSH, not a PKI specialist. After authenticated installation, the normal
path is one setup command, one short verified call, and the separate exact SSH
command or config stanza supplied by the OwnTransit administrator.

Proxy mode writes only raw SSH bytes to stdout. Prompts, logs, and diagnostics
go to stderr. A package installs a literal, root-owned, no-shell launcher with
no interpolated hostname, port, username, environment variable, or shell
fragment. OwnTransit may print a ProxyCommand example but never edits SSH
configuration.

The connector and relay expose equivalent offline inspection and explicit run
commands for their own roles. The target-local lifecycle surface includes:

```text
owntransitctl bootstrap
owntransitctl enroll-init
owntransitctl pending
owntransitctl apply
owntransitctl cancel
owntransitctl status
owntransitctl verify
owntransitctl recover
owntransitctl policy-apply
owntransitctl rollback
owntransitctl package-apply
owntransitctl package-rollback
owntransitctl package-recover
```

Ordinary non-purging uninstall is an explicit platform package operation, not a
remote lifecycle command. All privileged client setup steps use the fixed
authenticated `owntransitctl` selected by the package manager and accept their
bounded sensitive frames over stdin, never through caller-selected state
paths, argv or environment variables.

## Enrollment and bootstrap

There is no safe zero-touch initial trust. The operator and recipient must
authenticate the software release identity, route issuer pins, deployment
verifier, role and runtime binding through an independently established,
bidirectionally authenticated out-of-band procedure. The bytes may arrive
tentatively in an invitation; the relay, DNS, a download redirect or the
enrollment response itself cannot supply that trust.

The implemented initial path is:

1. Each target bootstraps only its local role and trusted public identities.
2. The target generates a unique installation ID, fresh OwnTransit private
   keys and CSRs, a nonce, a first sequence, and an ephemeral response-recipient
   key. Private keys never leave the target.
3. For guided client enrollment, target and offline provisioner retain durable
   sessions for the exact invitation/request/ciphertext transcript. The target
   reads its three comparison words first; only their exact operator-side match
   reveals the reverse group, which the target then verifies.
4. An offline provisioner checks the relay, connector, and client requests,
   issues only their CSR leaves under separate route authorities, signs each
   deployment, and encrypts each response to its intended target.
5. Apply verifies bootstrap pins, signer identity, role, installation ID,
   nonce, request digest and sequence, release/runtime binding, certificate key
   match, chain, EKU, exact SAN, validity, connector pins, and capability root.
6. The lifecycle code creates a complete write-once generation, syncs it, and
   atomically selects its exact digest and release/deployment/credential
   sequence tuple. The request
   digest becomes consumed durable state before leftover request material can
   be considered reusable.
7. The installed lifecycle copy runs the carrier-only proof as the exact bound
   client identity while holding the current package/runtime selector stable.
   A runtime-bound READY receipt is durable before one-time exchange authority
   is destroyed locally. Relay-side consume is best-effort and cannot veto
   cleanup. The operator separately tests SSH using operator-owned identities
   and policy.

The exchange validates canonical signed invitations, creates four independent
mailbox capabilities with operator-capability commitments, encrypts and pads
the request, binds it to the exact invitation, derives a full transcript digest
plus six display words, cross-binds the signed encrypted response and approved
three-target request set, and resumes without regenerating identity material.

Initial enrollment is not rotation. Its approval accepts only first-sequence
requests and a single active identity. The source also implements signed
verifier-first lifecycle policy, post-initial route issuance,
revocation/tombstone overlays, an external exact-state rollback anchor, signed
exact-record rollback, interrupted anchor-first recovery and current/previous
package retention. Production still requires documented expiry operations,
real-host service qualification and a two-location clean-room custody/recovery
rehearsal.

## Native lifecycle requirements

Every installer and lifecycle command acts only on its local role. There is no
universal root orchestrator and no remote host mutation.

An apply transaction must:

- acquire a durable local lock;
- validate strict bounded input before privileged changes;
- compare the observed generation and all monotonic high-water/floor state;
- reject symlinks, hard links, traversal, unexpected owners, and broad modes;
- materialize a complete release/config/credential record on one filesystem;
- sync files and directories before one atomic active-record selection;
- retain an exact authorized rollback tuple; and
- consume one-time request material and preserve tombstones even across
  interruption or ordinary software rollback.

The package transaction supplies role-scoped descriptor locks, staged records,
durable journals, exact receipts, current/previous retention, authenticated
apply/rollback/recovery and atomic selection. Signed release and monotonic
release-policy verification, the external anchor and selector publication are
one manager-held transaction. Client setup holds the same anchor/selector locks
while consuming the authenticated runtime identity, so a concurrent apply,
rollback or recovery fails closed. This package transaction remains distinct
from the target-credential rollback anchor and exact-record rollback.

Ordinary uninstall is non-purging. Destructive purge and trust reset require a
separate explicit recovery ceremony.

The supported macOS client needs a release-signature-verified Homebrew/source
installation plus the qualified privileged handoff that installs its fixed
launcher boundary. A formula that only compiles unprivileged binaries is not a
complete client installation. The optional Developer ID package lane is
disabled until OwnTransit also authenticates its final post-signing bytes; it
is not a v1 requirement. The Linux client needs a signed native package, one
exact authenticated install command and unprivileged per-user enrollment. The
Linux connector needs a dedicated locked, no-login service identity, a
root-owned PID-1 systemd unit, service-nonwritable configuration ancestors,
minimal privileges, bounded resources and logs, restart backoff, and no
listener. The relay image must be digest-addressed, non-root, read-only,
capability-free, resource-bounded, and supplied only immutable credential
mounts.

## Remaining release work

Before production v1, the project must complete:

1. publication from the reviewed sanitized snapshot as a new public root
   commit, followed by an independent secret scan of its complete object graph;
2. actual independent release/policy signing keys, signatures, custody and
   two-location recovery rehearsal using the implemented formats and floors;
3. independent clean-builder reproduction of the nine authenticated artifacts;
4. disposable Linux amd64 install/systemd/reboot, reconnect, interruption,
   upgrade, rollback, uninstall and recovery qualification;
5. disposable Apple-silicon Directory Services, zero-member setgid launcher,
   ACL, upgrade/rollback and reboot qualification;
6. operator expiry/revocation monitoring and clean-room credential recovery
   rehearsal;
7. hostile-relay, disk-full, signal and power-loss qualification beyond the
   in-repository adversarial tests; and
8. independent implementation, penetration, name, license and targeted patent
   review with every release-blocking finding closed or explicitly accepted.

No network auto-updater, mutable `latest` pointer, relay-delivered policy, or
relay-delivered trust bootstrap is permitted.

## Definition of shippable

OwnTransit v1 is shippable only when all of these are true:

- a clean supported client reaches a clean connector without source checkout,
  a client-side container runtime, hand-edited JSON, or copied PEM files;
- every installation has unique OwnTransit keys and an exact
  route/connector/epoch capability binding;
- both transport encryption layers and the pre-local-dial authorization gate
  survive a fully compromised relay;
- the connector can reach only `tcp4 127.0.0.1:22` and has no positive client
  allowlist to synchronize;
- artifacts and deployments are authenticated, sequenced, recoverable, and
  reversibly activated without resurrecting tombstoned state;
- credential removal affects new sessions and existing sessions are bounded;
- connector reboot and relay restart recover without weakening trust;
- normal uninstall preserves OwnTransit recovery state and touches no SSH or
  unrelated host configuration;
- native release signing, clean-host qualification, clean-room OwnTransit
  recovery, and independent security review pass; and
- an operator-owned out-of-band SSH and host-recovery path remains available
  throughout canary and burn-in.

Until every gate passes, this repository remains a release candidate and must
not be described as a production access or recovery system.
