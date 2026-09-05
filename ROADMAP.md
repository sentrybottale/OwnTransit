# OwnTransit roadmap

## 0.1.1 receiver-owned integration

The new `pair` commands integrate one-use receiver pairing, receiver-local
issuance, three-role relay bootstrap, automatic certificate refresh, fresh
session authorization and persistent local circuit breakers. The source tests
include real SSH protocol carriage, restart and lock/reconnect. See
[PAIRING_INSTALL.md](PAIRING_INSTALL.md) for development self-test artifacts.
The existing signed release is not replaced by merging this source. Service
installation/upgrade, the signed 0.1.1 handoff and host qualification remain
separate from these development artifacts; no new-machine requirement is added.

The historical 0.1.0 planning contract follows.

Status: **OwnTransit 0.1.0 release candidate; stable publication is not yet
evidenced**. The SSH-only implementation and public-source boundary are present,
and the release tooling can build a signed installable candidate handoff. An
official stable 0.1.0 handoff still requires the exact authenticated artifact
set and an independently verified signed qualification record containing
literal `schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`. That overall status
requires zero unresolved Critical/High findings and four bounded PASS results:
source/security/publication, release signatures, native-artifact smoke, and live
SSH plus SCP through the untrusted relay. Independent review, clean-room
platform labs and environment-specific canary work are disclosed additional
assurance rather than missing executable functionality.

## V1 decision

V1 is a native, SSH-only, always-relayed carrier. Both endpoint roles originate
every connection and expose no OwnTransit listener or public port. The relay is
the only public component and is assumed fully malicious.

The outer TLS 1.3 connection protects admission to the relay. A separate inner
TLS 1.3 connection encrypts and authenticates the client-to-connector byte
stream end to end despite a compromised relay. OpenSSH then independently
encrypts and authenticates SSH inside that carrier under operator-owned policy.

The connector has no positive client allowlist. It accepts a canonical
client/connector/route/epoch capability only under the exact offline
route-capability CA installed for that route, and it can dial only the
build-fixed literal `tcp4 127.0.0.1:22` target.

V1 does not include direct peer-to-peer transport, a controller, SSO, device
posture, DNS, TUN networking, a dashboard, general-purpose proxying, or
automatic updates.

## Phase 0 — public source boundary

State: **public-source boundary complete; governance review remains external**

- Keep OwnTransit as the public name without changing authenticated v1 wire
  bytes.
- Remove deployment-specific operations material, credentials, endpoints, and
  private history from the public surface.
- Preserve the selected Apache-2.0 license and the canonical hosted Go module
  path `github.com/sentrybottale/owntransit`.
- Create the public repository from a reviewed sanitized snapshot as a new
  root commit. Never publish or graft the private development history.
- Run publication checks against the snapshot and its new history. Record an
  independent secret scan when available, or disclose that it was not
  performed.
- Record professional name, applicable-contract, targeted-patent, ownership and
  publishing-entity review as project-governance evidence. Repository tooling
  neither performs nor certifies that work.
- Preserve the complete private development record as a hashed,
  access-controlled evidence archive; never graft it into or destroy it in
  favor of the clean public history.

## Phase 1 — runtime and capability closure

State: **implementation complete; exact release evidence required per handoff**

- Preserve both independent TLS 1.3 boundaries and the pre-local-dial inner
  authentication gate.
- Preserve strict parser and state limits, exact connector SPKI pins, the
  route-capability ALPN, canonical certificate identities, and bounded
  authenticated session lifetimes.
- Preserve the connector's empty positive client list: authorization is the
  exact per-route capability CA plus canonical SAN/epoch validation and bounded
  authenticated tombstones.
- Exercise hostile-relay, cross-wiring, duplicate-join, starvation, exhaustion,
  cancellation and long-lived-session behavior against each exact release.
- Require clean-build evidence that no runtime, environment, DNS or wire input
  can change `tcp4 127.0.0.1:22`.

## Phase 2 — initial enrollment and credential continuity

State: **guided client exchange and signed continuity implemented; operational
assurance is ongoing**

Implemented in source:

- target-generated installation IDs, private keys, CSRs, nonces, and one-time
  response recipients;
- strict first-sequence enrollment requests for relay, connector, and client;
- offline leaf-only route approval using separate route issuers and deployment
  signing;
- signed, target-encrypted responses bound to the retained request and trusted
  out-of-band bootstrap identities;
- target-local write-once record creation, atomic active selection, request
  consumption, high-water marks, rollback floors, and tombstone state;
- signed-invitation, independent mailbox-capability, padded-request,
  exact-transcript and six-word display primitives that grant no activation
  authority on their own;
- durable target/operator sessions, target-first gated comparison, automatic
  hostile-mailbox courier operations, exact response/request-set binding,
  client setup resume/cancel and runtime-bound carrier-only `READY`;
- authenticated temporary relay exchange-only cold start with no carrier,
  endpoint runtime, authority material, persistence, or target selection;
- fail-closed post-cutover resume: expired artifacts remain unusable before
  apply, while an exact already-Applied response may reconcile its anchored
  active record and perform a current live READY probe;
- signed target-bound lifecycle policy, verifier-first overlap validation,
  derived immutable policy generations and post-initial route issuance;
- cumulative client/SPKI revocation and credential tombstone overlays that
  cannot be removed by ordinary transition;
- a separately rooted exact-state rollback anchor, signed exact-record
  rollback which reapplies current denials, and anchor-first interruption
  recovery; and
- local-authoritative retirement of the invitation workspace, mailbox
  capabilities and retained response after READY, independent of relay
  cooperation.

Additional assurance and operator responsibilities:

- invite independent review of the invitation/phrase/exchange construction and
  human-authentication assumptions without claiming that certification for
  0.1.0;
- rehearse the verifier-first leaf/capability-root rotation, signed floor
  advancement, revocation overlay, exact rollback and transaction recovery as
  one documented operator ceremony on real hosts;
- rehearse authenticated revocation distribution and retained current/previous
  generation retirement without resurrecting tombstoned credentials;
- operate expiry monitoring and verify removed identities fail for new
  sessions while existing sessions remain bounded; and
- maintain two-location issuer/signing custody and rehearse clean-room recovery.

## Phase 3 — executable and release contract

State: **signed formats, deterministic staging and activation integration
implemented; release execution is required per artifact set**

- Preserve offline version/config validation and embedded release ID, source
  revision, OS, architecture, role, protocol, and connector target/profile.
- Preserve the separate signed software-release manifest and monotonic release
  policy paths; neither is endpoint deployment signing.
- Preserve binding of artifact bytes, digests, sizes, roles, platforms,
  protocol, source/build inputs, per-artifact SPDX evidence, licenses and
  monotonic release/deployment sequences.
- Preserve the exact fourteen-artifact, twice-built deterministic unsigned staging
  path and digest-addressed relay OCI construction.
- Provide no network updater, mutable `latest` identifier, or relay-delivered
  instruction channel.
- Require the official handoff to execute the signed release/policy path and
  authenticate and execute the no-fee macOS artifact on an existing
  Apple-silicon host. Initial 0.1.0 does not claim candidate macOS client
  installation or launcher activation because its retained RC7 client role is
  intentionally not a stable predecessor. Independent clean-builder
  reproduction, clean-room macOS lifecycle qualification and release/policy
  key-recovery rehearsals are additional assurance. Developer ID/notarization
  remains disabled until OwnTransit also authenticates the final package bytes.

## Phase 4 — native packages and lifecycle

State: **native payload and package lifecycle implemented; exact signed-artifact
smoke required per supported architecture**

- Signature-verified Homebrew/source-installed macOS arm64 client. Developer ID
  packaging remains disabled and outside the v1 requirement.
- Signed Linux amd64/x86_64 and Linux arm64/aarch64 packages with unprivileged
  per-user enrollment.
- Signed Linux amd64/x86_64 and Linux arm64/aarch64 connector packages with a
  dedicated locked service identity and root-owned PID-1 system unit.
- Architecture-specific digest-addressed Linux amd64 and Linux arm64 relay
  images with immutable credential-set mounts.
- Preserve target-local apply, verify, authenticated rollback, interruption
  recovery and non-purging uninstall over durable locks, generation
  compare-and-swap, journals, fsync ordering, and atomic
  release/config/credential activation.
- Preserve routing of every install, upgrade, authenticated rollback and
  ordinary uninstall through one role-scoped package transaction with a
  durable journal and one active-release selector. Interrupted or repeated
  operations must resume or fail closed without mixed binaries, orphaned
  identities or guessed cleanup.
- Preserve binding of release verification, the exact local policy/rollback
  anchor and selector publication into one manager-held transaction. The
  external anchor must compare-and-swap before the selector becomes
  authoritative; a detached or stale verified decision must never authorize
  installation.
- Execute and version-check every ordinary native executable on its matching
  architecture, authenticate and inspect both relay OCI archives and the Darwin
  launcher, record the launcher's expected fail-closed fixed-path rejection,
  and perform no macOS system mutation. On existing Linux amd64 and Linux arm64
  hosts, install and
  activate the exact signed connector, verify its binary identity and systemd
  confinement, prove it owns no OwnTransit listener, restart the enabled
  service, perform an actual host reboot, reacquire the host directly, and
  prove the connector is running or retrying post-boot. This makes no candidate
  macOS client install/launcher, macOS provisioner package-lifecycle, Linux
  client/provisioner/relay package-lifecycle or pristine-host claim; the
  connector reboot result is limited to the two exercised hosts.
- Exercise current/previous retention, authenticated rollback, non-purging
  uninstall, service/user/image integration and process-restart recovery with
  only durable inputs against the exact released packages as continuing
  assurance.
- Fixed root-owned no-shell ProxyCommand launcher and shell-injection tests. The
  installer never writes OpenSSH configuration.
- Preserve the macOS arm64 provisioner's protected `root:wheel` mode-`0750`
  package tree and distinct public mode-`0755` copy; do not replace that
  boundary with a traversable package tree or public hard link.
- Preserve one root-only macOS `package-mutation.v1.lock` across client and
  provisioner apply, rollback, recovery, public-entry publication and durable
  lifecycle-owned detach.
- Require Linux `fs.protected_hardlinks=1` before every provisioner package
  operation; only Linux may migrate its legacy provisioner package directories
  from mode `0750` to `0755`.

## Phase 5 — bounded release acceptance and additional assurance

State: **four exact-byte release results required; external assurance ongoing**

Hard 0.1.0 acceptance results:

- Run the full required source, security, publication and complete public-history
  checks against the frozen commit.
- Independently verify the signed handoff, release manifest, policy, outer and
  native inventories, and every referenced byte from separately authenticated
  trust.
- Execute and version-check every ordinary native executable on its matching
  architecture, authenticate and inspect both relay OCI archives and the Darwin
  launcher, record the launcher's expected fail-closed fixed-path rejection,
  and perform no macOS system mutation. On existing Linux amd64 and Linux arm64
  hosts, install and
  activate the exact signed connector, verify its binary identity and systemd
  confinement, prove it owns no OwnTransit listener, restart the enabled
  service, perform an actual host reboot, reacquire the host directly, and
  prove the connector is running or retrying post-boot. This is not candidate
  macOS client installation or launcher activation, macOS provisioner package
  lifecycle, Linux client, provisioner, or relay package lifecycle,
  pristine-host, or exhaustive lifecycle evidence; the connector reboot claim
  is limited to those hosts.
- Use the exact signed macOS client through the deployed untrusted relay to the
  exact signed connector and prove both an SSH session and an
  integrity-checked SCP transfer. Use the pre-existing operator-supplied client
  configuration and SSH key, perform no macOS system mutation, and require both
  client inputs plus the deployed connector configuration and endpoint
  credentials to remain unchanged. Qualification does not transfer SSH
  identity, authorization or recovery ownership to OwnTransit.
- Require zero unresolved Critical and High defects and bind all four results
  to an independently verified signed qualification record containing literal
  `schema=owntransit.qualification.v1`,
  `gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`.

Additional assurance, not a 0.1.0 publication blocker:

- pristine/factory-clean macOS and per-architecture Linux lifecycle labs;
- repeated or non-connector cold boot/reconnect, upgrade, interrupted apply,
  concurrency, exact rollback, uninstall and clean OwnTransit recovery matrices
  beyond the two required Linux connector reboot runs;
- dual public relay-exchange qualification and exhaustive composite dossiers;
- wrong-role/platform/signature/key/config, replay, downgrade, symlink,
  hardlink, archive, path-race, disk-full, signal and power-loss campaigns;
- independent clean-builder reproduction, implementation review and authorized
  penetration testing; and
- broader relay cross-wiring, duplicate-join, exhaustion and metadata studies.

Record these activities when performed and disclose when they were not. Their
absence is not a claim that they passed.

## Phase 6 — stable release operation

State: **0.1.0 scope defined; stable publication requires exact signed assets
and an independently verified qualification record with
`schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`**

- Publish only the exact authenticated platform artifacts after that overall
  PASS record has been independently verified.
- Run an environment canary while an operator-owned, out-of-band SSH and host
  recovery path remains available.
- Rehearse OwnTransit install, upgrade, rotation, revocation, rollback, and
  clean-room state recovery before treating it as an environment's only
  transport path. This operator decision is deliberately stronger than the
  0.1.0 publication gate.
- Attach external review, legal, custody, independent-reproduction and burn-in
  records to the exact release when available; do not imply that they exist.

## Later — optional direct path

Before any direct-path work, add later-client enrollment if real deployments
need more than the single client supported by the 0.1.0 initial-route profile.
That work needs a new signed approval-context binding for one fresh client
request plus authenticated route state, and an atomic relay-policy transition
which appends exactly that client while preserving every existing route and
pin. It must not reuse the v1 three-live-request digest, route rotation, or an
expired relay/connector request. Older relays must reject the new lifecycle
semantics fail-closed.

Direct client-to-connector transport remains research only. It starts only
after v1 is stable and measured relay bandwidth or availability justifies the
additional NAT traversal, signaling, UDP, and state-machine attack surface. It
requires a separately versioned protocol, strict nominated-tuple confinement,
consent freshness, disabled connection migration, relay fallback, downgrade
analysis, and a new security review. If those gates fail, always-relayed v1
remains authoritative.
