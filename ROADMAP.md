# OwnTransit roadmap

Status: **v1 release candidate**. The source implementation and public-root
tooling are present; no production release is published until the external and
clean-host gates below pass.

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

State: **automation complete; publication actions pending**

- Keep OwnTransit as the public name without changing authenticated v1 wire
  bytes.
- Remove deployment-specific operations material, credentials, endpoints, and
  private history from the public surface.
- Preserve the selected Apache-2.0 license and the canonical hosted Go module
  path `github.com/sentrybottale/owntransit`.
- Create the public repository from a reviewed sanitized snapshot as a new
  root commit. Never publish or graft the private development history.
- Run publication checks and an independent secret scan against both the
  snapshot and its new history.
- Complete professional name clearance, applicable-contract review, targeted
  patent review, and written assignment of the project and release identities
  to the publishing entity before making the repository public.
- Preserve the complete private development record as a hashed,
  access-controlled evidence archive; never graft it into or destroy it in
  favor of the clean public history.

## Phase 1 — runtime and capability closure

State: **implementation complete; release qualification incomplete**

- Preserve both independent TLS 1.3 boundaries and the pre-local-dial inner
  authentication gate.
- Preserve strict parser and state limits, exact connector SPKI pins, the
  route-capability ALPN, canonical certificate identities, and bounded
  authenticated session lifetimes.
- Preserve the connector's empty positive client list: authorization is the
  exact per-route capability CA plus canonical SAN/epoch validation and bounded
  authenticated tombstones.
- Finish hostile-relay, cross-wiring, duplicate-join, starvation, exhaustion,
  cancellation, and long-lived-session qualification.
- Prove in clean builds that no runtime, environment, DNS, or wire input can
  change `tcp4 127.0.0.1:22`.

## Phase 2 — initial enrollment and credential continuity

State: **guided client exchange and signed continuity implemented;
qualification remains stop-ship**

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

Still required before a production v1:

- independently review the invitation/phrase/exchange construction and human
  authentication assumptions;
- qualify the verifier-first leaf/capability-root rotation, signed floor
  advancement, revocation overlay, exact rollback and transaction recovery as
  one documented operator ceremony on real hosts;
- qualify authenticated revocation distribution and retained current/previous
  generation retirement without resurrecting tombstoned credentials;
- add operational expiry monitoring and prove removed identities fail for new
  sessions while existing sessions remain bounded; and
- two-location issuer/signing custody plus clean-room recovery rehearsal.

## Phase 3 — executable and release contract

State: **signed formats, deterministic staging and activation integration
implemented; custody and independent reproduction incomplete**

- Preserve offline version/config validation and embedded release ID, source
  revision, OS, architecture, role, protocol, and connector target/profile.
- Preserve the separate signed software-release manifest and monotonic release
  policy paths; neither is endpoint deployment signing.
- Preserve binding of artifact bytes, digests, sizes, roles, platforms,
  protocol, source/build inputs, per-artifact SPDX evidence, licenses and
  monotonic release/deployment sequences.
- Preserve the exact nine-artifact, twice-built deterministic unsigned staging
  path and digest-addressed relay OCI construction.
- Provide no network updater, mutable `latest` identifier, or relay-delivered
  instruction channel.
- Complete independent clean-builder reproduction, public release execution,
  free macOS distribution qualification and release/policy key-recovery
  ceremonies. Developer ID/notarization is disabled until OwnTransit also
  authenticates the final package bytes.

## Phase 4 — native packages and lifecycle

State: **native payload and package lifecycle implemented; clean-host support
qualification incomplete**

- Signature-verified Homebrew/source-installed macOS arm64 client. Developer ID
  packaging remains disabled and outside the v1 requirement.
- Signed Linux amd64 client package with unprivileged per-user enrollment.
- Signed Linux amd64 connector package with a dedicated locked service identity
  and root-owned PID-1 system unit.
- Digest-addressed relay image with immutable credential-set mounts.
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
- Qualify current/previous retention, authenticated rollback, non-purging
  uninstall, service/user/image integration and process-restart recovery with
  only durable inputs.
- Fixed root-owned no-shell ProxyCommand launcher and shell-injection tests. The
  installer never writes OpenSSH configuration.

## Phase 5 — clean-host qualification

State: **not complete**

- Qualify native macOS and Linux packages with disposable or operator-supplied
  OpenSSH fixtures; qualification does not transfer SSH ownership to
  OwnTransit.
- Exercise cold boot, reconnect, upgrade, interrupted apply, concurrency,
  exact rollback, uninstall, and clean OwnTransit credential/state recovery.
- Test wrong role/platform/signature/key/config, replay, downgrade, symlink,
  hardlink, archive, path-race, disk-full, signal, and power-loss failures.
- Test relay cross-wiring, duplicate join, state exhaustion, metadata exposure,
  and fully compromised relay behavior.
- Complete free macOS install/integrity, Linux
  ownership/systemd/service-identity, reproducibility, and publication checks.
- Prove one authenticated macOS install path performs the required privileged
  launcher handoff, and publish one exact authenticated Linux client install
  command. Homebrew source compilation alone is not that qualification.
- Obtain an independent implementation review and authorized penetration test;
  close or explicitly accept every Critical/High finding.

## Phase 6 — v1 release

State: **pending publication and external qualification gates**

- Publish source from the clean public root history, then publish independently
  signed platform artifacts only after their release gates pass.
- Run a private canary while an operator-owned, out-of-band SSH and host
  recovery path remains available.
- Rehearse OwnTransit install, upgrade, rotation, revocation, rollback, and
  clean-room state recovery before treating it as the only transport path.
- Promote to v1 only after the documented burn-in and review gates pass.

## Later — optional direct path

Direct client-to-connector transport remains research only. It starts only
after v1 is stable and measured relay bandwidth or availability justifies the
additional NAT traversal, signaling, UDP, and state-machine attack surface. It
requires a separately versioned protocol, strict nominated-tuple confinement,
consent freshness, disabled connection migration, relay fallback, downgrade
analysis, and a new security review. If those gates fail, always-relayed v1
remains authoritative.
