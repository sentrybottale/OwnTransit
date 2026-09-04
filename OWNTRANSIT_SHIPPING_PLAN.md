# OwnTransit v1 shipping plan

Status: **OwnTransit 0.1.0 release-candidate contract; not an official stable
publication**. The tunnel, guided client exchange, target-local credential
lifecycle, signed package transaction and publication boundaries exist in
source, and the tooling can build a signed installable candidate handoff. An
official stable handoff must execute the signing path, carry an independently
verified signed qualification record for the exact bytes, and report PASS for
every hard supported-host gate. Independent reproduction, security/legal
review, custody rehearsal and environment canary work are additional assurance
whose status must be disclosed, not fabricated.

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

The software-release v1 JSON/signature envelope admits only explicitly
enumerated artifact-matrix editions. Public `0.1.0-rc.*` packages bind the
exact-nine edition; stable `0.1.0` binds exact-fourteen. The former is not an
in-place predecessor of the latter. Its non-purging uninstall preserves the
selected lifecycle and trust state, so stable qualification uses a genuinely
fresh host unless a separately reviewed destructive trust-reset ceremony is
implemented in a future change.

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

An official OwnTransit 0.1.0 handoff contains exactly these logical artifacts:

| Artifact | Platform | Responsibility |
|---|---|---|
| `owntransit` | macOS arm64 | On-demand outbound stdio carrier for an operator-owned OpenSSH ProxyCommand |
| `owntransit-launcher` | macOS arm64 | Fixed setgid launcher bound to one local UID, GeneratedUID, release and client digest |
| `owntransit` | Linux amd64/x86_64 and Linux arm64/aarch64 | The same outbound-only client carrier |
| `owntransit-connector` | Linux amd64/x86_64 and Linux arm64/aarch64 | Outbound-only daemon with the fixed loopback SSH target |
| `owntransit-relay` | Separate Linux amd64 and Linux arm64 OCI images | Hostile rendezvous and byte-copy relay; no inner TLS termination |
| `owntransitctl` | macOS arm64, Linux amd64, and Linux arm64 | Target-local enrollment and lifecycle state |
| `owntransit-provision` | macOS arm64, Linux amd64, and Linux arm64 | Offline route authority and response creation |

The release manifest records three clients, the macOS launcher, two Linux
connectors, two architecture-specific Linux relay images, and three platform
builds of each administrative tool as fourteen separate artifact records. Each
record binds its bytes, SHA-256 digest, size, role, platform, format, and named
SBOM evidence. Licenses are independent evidence.

Platform support attaches to exact released bytes only after their native
package, clean-host, rollback and qualification matrices pass, plus upgrade
qualification whenever a supported predecessor exists. Initial stable `0.1.0`
has no supported predecessor, so upgrade is recorded as not applicable; public
`0.1.0-rc.*` state is not an in-place upgrade source. The candidate targets
Apple-silicon macOS (`arm64`), 64-bit x86 Linux (`amd64`,
also called `x86_64`), and 64-bit ARM Linux (`arm64`, also called `aarch64`).
Intel macOS and every other architecture are outside the 0.1.0 scope.
Cross-compilation alone is not support evidence.

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
owntransitctl package-detach
```

Ordinary non-purging uninstall is an explicit local platform package operation,
not a remote lifecycle command. On macOS its public-entry removal is owned by
the authenticated `package-detach` lifecycle operation so an interrupted
detach can resume without guessing at shell-visible residue. `package-detach`
is currently the macOS client/provisioner public-entry operation; Linux
uninstall remains an explicit local platform script. All privileged client
setup steps use the fixed authenticated `owntransitctl` selected by the package
manager and accept their bounded sensitive frames over stdin, never through
caller-selected state paths, argv or environment variables.

## Enrollment and bootstrap

There is no safe zero-touch initial trust. The operator and recipient must
authenticate the software release identity, route issuer pins, deployment
verifier, role and runtime binding through an independently established,
bidirectionally authenticated out-of-band procedure. The bytes may arrive
tentatively in an invitation; the relay, DNS, a download redirect or the
enrollment response itself cannot supply that trust.

The implemented initial path is:

1. Install each authenticated role package, but do not start the relay or
   connector services.
2. The online courier creates one allocation credential and supplies only its
   domain-separated SHA-256 to the relay host. The authenticated relay image
   starts in temporary exchange-only mode behind the exact public reverse-proxy
   location. This process has a mailbox only: no carrier, endpoint state,
   signer, issuer, route, persistence, or target selector.
3. Relay and connector bootstrap only their own local roles and generate their
   first signed requests. Each target creates its unique installation ID,
   OwnTransit private keys and CSRs, nonce, sequence, and one-response recipient
   locally; private keys never leave the target.
4. The provisioner issues one client invitation registered through the
   temporary exchange. The client generates its request and both sides retain
   durable sessions for the exact invitation/request/ciphertext transcript.
5. The client reads its three comparison words first; only their exact
   operator-side match reveals the reverse group, which the client then
   verifies over the independently authenticated human channel.
6. The offline provisioner checks the exact relay, connector, and client
   requests, issues only their CSR leaves under separate route authorities,
   signs each deployment, and encrypts each response to its intended target.
7. The courier uploads the bound client response. The client verifies and
   durably applies it, then reports `SETUP SAVED — NOT READY` because the
   carrier is intentionally not running yet. Keep the exchange process alive
   until this Applied state exists.
8. Apply the relay and connector responses. Every apply checks bootstrap pins,
   signer identity, role, installation ID, nonce, request digest and sequence,
   release/runtime binding, key/certificate match, chain, EKU, exact SAN,
   validity, connector pins, and capability root, then atomically selects a
   complete synced generation and consumes the request digest.
9. Stop temporary exchange-only mode, start the enrolled full relay on the
   same loopback publication port, then start the connector. No mailbox content
   is needed after the client has applied.
10. The installed lifecycle copy resumes and runs the carrier-only proof as the
    exact bound client identity while holding the package/runtime selector
    stable. A runtime-bound READY receipt is durable before one-time exchange
    authority is destroyed locally; relay-side consume is best-effort. The
    operator separately tests SSH using operator-owned identities and policy.

The exchange validates canonical signed invitations, creates four independent
mailbox capabilities with operator-capability commitments, encrypts and pads
the request, binds it to the exact invitation, derives a full transcript digest
plus six display words, cross-binds the signed encrypted response and approved
three-target request set, and resumes without regenerating identity material.

Initial enrollment is not rotation. Its approval accepts only first-sequence
requests and exactly one relay, connector, route, and client. Adding a later
client needs a separately versioned approval-context binding plus a narrowly
authenticated relay-policy append and is not implemented in 0.1.0. The source
also implements signed
verifier-first lifecycle policy, post-initial route issuance,
revocation/tombstone overlays, an external exact-state rollback anchor, signed
exact-record rollback, interrupted anchor-first recovery and current/previous
package retention. OwnTransit 0.1.0 does not make expiry monitoring,
two-location custody or clean-room recovery automatic. Those remain documented
operator procedures, while each official release must qualify its exact
installed service path on the supported hosts.

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

On macOS, one permanent root-only `package-mutation.v1.lock` serializes client
and provisioner apply, rollback, recovery, detach and public-frontend
publication. The provisioner package tree remains `root:wheel` mode `0750`;
its public `owntransit-provision` is a separately created `root:wheel` mode
`0755` copy with the authenticated digest and a different inode. macOS never
widens the protected provisioner tree to make a symlink traversable.

On Linux, the provisioner package tree is root-owned mode `0755` and is
reachable through its ordinary public selector. Both the installer and every
provisioner package lifecycle operation require the kernel policy
`fs.protected_hardlinks=1`. Only Linux performs the authenticated, resumable
legacy provisioner-directory migration from mode `0750` to `0755`.

One permanent empty `root:root` mode-`0600`
`/var/lib/owntransit/package-supervisor/platform.v1.lock`, beneath its
root-only mode-`0700` directory, serializes every complete Linux install and
non-purging uninstall integration window. The lock is never removed. Connector
and relay detach also holds the existing role supervisor lock before stopping
or removing systemd integration, preventing a concurrent package lifecycle
operation from restarting the service into a half-detached state. Partial
detach is an accepted retry state only when every remaining public name is
still the exact expected object.

Connector and relay package operations use two durable supervisor states. The
root-only `<role>.intent` state blocks systemd while mutation is incomplete.
After mutation and activation complete, an atomic rename plus directory sync
publishes `<role>.restart`, which permits systemd startup while retaining the
restart obligation. The record is removed only after the service is verified
active. Recovery moves restart back to intent and replays the authenticated
idempotent operation; conflicting states fail closed.

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

## Release integrity requirements

Every official 0.1.0 handoff must complete these functional release steps for
one exact source revision and artifact set:

1. build the fourteen-artifact matrix from the canonical public history and bind
   its source, inputs, digests, SBOMs and licenses;
2. create and independently verify the actual release-manifest and monotonic
   release-policy signatures used by the installers;
3. independently qualify disposable Linux amd64 and Linux arm64
   install/systemd/reboot, reconnect, interruption, rollback, uninstall and
   recovery behavior through a reviewed composite dossier, treating the
   installer/reboot JSON as sub-evidence only;
4. qualify disposable Apple-silicon Directory Services, zero-member setgid
   launcher, ACL, rollback and reboot behavior;
5. close or explicitly accept every known Critical or High defect affecting
   those exact bytes; and
6. record initial-stable upgrade as **N/A** because `0.1.0` has no supported
   predecessor, then create and independently verify a signed qualification
   record binding the exact source, release identity, outer asset inventory and
   all hard-gate results without representing missing evidence as PASS.

## Additional assurance and operator operations

OwnTransit 0.1.0 does not claim completion or certification of these activities:

- independent clean-builder reproduction and an external public-object secret
  scan;
- independent implementation review and authorized penetration testing;
- professional name, applicable-contract, license and targeted-patent review;
- two-location release/issuer custody and clean-room recovery rehearsal;
- broader hostile-relay, disk-full, signal and power-loss exercises; and
- operator expiry/revocation monitoring, canary and burn-in.

Their status should be attached to the exact release when evidence exists.
They improve assurance and deployment operations but are not substitutes for,
or missing implementations of, the client, connector, relay and installer.

No network auto-updater, mutable `latest` pointer, relay-delivered policy, or
relay-delivered trust bootstrap is permitted.

## Definition of an installable stable release

OwnTransit 0.1.0 is installable and stable within its stated scope only when all
of these are true for the exact released bytes:

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
- native release signing and supported-platform clean-host qualification pass;
- the status of independent review, reproduction, custody and recovery
  assurance is disclosed without implying certification; and
- an operator-owned out-of-band SSH and host-recovery path remains available
  throughout canary and burn-in.

Meeting this definition means the release is distributable and installable
within the documented platform and SSH-only boundary. Suitability for a
particular production environment remains the operator's risk decision;
OwnTransit is not an SSH or host-recovery system.
