# Changelog

OwnTransit records user-visible and security-relevant changes here. An
immutable prerelease candidate is moved out of `Unreleased` when its source is
frozen so its exact version can be bound into build and qualification evidence.
That heading is not a release decision or production claim. A stable-version
heading may freeze the intended release bytes before qualification, but it
becomes a publication record only after its authenticated evidence, signed
qualification record and release decision are complete. Git tags never create
or publish artifacts automatically.

## [0.4.0]

Explicitly named independent relay instances on one VPS.

- Add relay `--instance NAME` setup/registration/removal and local instance listing.
- Preserve the original default relay; give named instances separate keys,
  protected state, containers, reboot services and persistent loopback ports.
- Bind website routing, upgrade recovery, container cleanup and reservations to
  the selected instance; do not adopt another instance or switch endpoint origins.
- Serialize shared host/package operations and distinguish one-instance removal
  from whole-role package removal. Retain all pairing and SSH state.
- Accept known 0.3.0 packages without replacing unrelated commands. Add scoped
  lifecycle, selector, route-conflict, package-lock and port-binding regressions.

## [0.3.0]

Independent named tunnels across shared relays and SSH hosts.

- Add `--tunnel NAME`, local tunnel listing and scoped receiver restart. Preserve
  the original default pairing and advanced explicit state-path commands.
- Let one SSH server host several independently authorized client pairings,
  each with separate receiver keys, state, reboot service and alarm scope.
- Validate named unit ownership and protect setup/package changes with a local
  maintenance lock. Upgrade/remove recognized instances while retaining state.
- Accept 0.2.0 package upgrades on Mac and Linux without replacing unrelated
  commands or changing SSH settings.
- Add shared-relay/shared-SSH-host, crossed-peer, alarm-isolation, selector and
  owned-service regressions. Existing crypto, wire profiles and fixed targets
  remain unchanged.

## [0.2.0]

Receiver-owned stabilization release under the bounded 0.2.0 shipping contract.

- Add a signed one-command Apple-silicon Mac client installer, repeatable
  installation, protected per-user software and offline non-purging uninstall.
- Add Linux non-purging role removal with package/managed-service ownership
  checks, retained pairing state and safe command aliases alongside preview names.
- Keep unrelated legacy commands and every operator SSH setting unchanged.
- Replace generic runtime failures with fixed, non-secret diagnostic categories.
- Serialize simultaneous client startups within the existing opening deadline,
  instead of failing immediately when another SSH startup holds the local lock.
- Add concurrent quiet SSH/restart regressions and native/isolated installer
  tamper, reinstall, removal and state-preservation tests.
- Retain existing cryptographic formats and production security limits. The
  exact 0.2.0 signed inventory adds the Mac installer and rejects older sets.
- Extended soak, clean-host certification and independent security assessment
  are not claimed; no new machines or signing keys are required.

## [0.1.8]

Signed development patch candidate; existing release bytes remain immutable.

- Fix the relay's pending-receiver timer closing an already active carrier.
  Promotion and expiry now resolve ownership atomically; a claimed handler
  stays alive until its exchange ends or the relay shuts down.
- Preserve pending expiry, admission/active quotas, token/session deadlines,
  endpoint authentication, authorization leases and terminal alarm behavior.
  This is an availability fix, not a new wire profile or trust reset.
- Add a real-WebSocket regression that fails on the previous implementation,
  pending/claimed expiry and shutdown tests, a promotion/expiry race test, and
  explicit session-lifetime/token-bound assertions.
- Upgrade the relay to apply the fix; existing compatible clients and receivers
  need no update or re-pairing. The installer accepts 0.1.7 packages as well.

## [0.1.7]

Signed development patch candidate; existing release bytes remain immutable.

- Fix long hidden-code pastes on macOS and Linux by bypassing canonical terminal
  line limits before displaying the prompt. Keep bounded input and strict code
  validation; do not change pairing or wire authentication.
- Support Enter, Backspace/Delete, Ctrl-U, Ctrl-D and cancellation without echo.
  Restore the exact terminal settings on success, failure and handled signals;
  discard queued input on exit. Ctrl-Z cancels instead of suspending hidden input.
- Shorten client setup to source-specific prompts and a three-line success
  message. Print the current executable and selected state in the SSH example,
  with shell/SSH-token quoting, instead of assuming a working PATH.
- Add isolated real-PTY regressions on macOS and Linux for long paste, bounds,
  no echo, editing, cancellation and exact terminal restoration.
- Accept 0.1.6 package upgrades. Existing identities are preserved; no new
  pairing, SSH changes or relay upgrade is required for the client input fix.

## [0.1.6]

Signed development patch candidate; existing release bytes remain immutable.

- Accept Docker's entrypoint arrays and Podman 4.9's entrypoint strings without
  shell interpretation. Normalize bare SHA-256 image IDs before exact image
  comparison, including rollback verification.
- Reject malformed inspection types and prevent multi-command string
  entrypoints from being mistaken for the OwnTransit executable.
- Clean up stopped managed container instances explicitly instead of relying
  only on engine auto-removal. Service pre/post hooks and upgrade rollback
  verify the exact name, image, executable and state bind before removing a
  container; they never force-remove running containers, images or volumes.
- Preserve the exact previous service template in a v2 upgrade journal while
  retaining recovery support for earlier v1 journals.
- Add representation-specific regressions and an explicit operator-authorized
  check for real engine inspection and forced-failure rollback. The latter is
  opt-in only and never runs against an operator host through ordinary CI.
- Accept upgrades from the published 0.1.5 packages. No protocol, endpoint
  credential or SSH authorization changes.

## [0.1.5]

Signed development candidate for the next stable qualification, not a stable
or independently security-assessed release. The planned fixes move directly
to 0.1.5; there is no 0.1.4 artifact release.

- Bound initial unauthenticated admission and public response writes; add
  bounded global/per-TCP-peer admission concurrency and rate accounting.
- Restore WebSocket message limits after adapter construction on both paths,
  preserve bounded stream writes, and test whole/fragmented oversize rejection.
- Add actual managed relay upgrades with exact unit/image validation, retained
  keys/routing, same-version no-op, rollback and interrupted-cutover recovery.
- Add numbered, source-specific prompts with hidden-input explanations,
  actionable retries and preserved existing-client setup state.
- Document exact install versus upgrade/restart steps; no routine software
  upgrade requires regenerating receiver pairing codes.
- Add focused admission, transport, input, install/upgrade and rollback tests.
  Multi-tunnel profiles remain separately queued; SSH policy stays operator-owned.

## [0.1.3]

Signed development preview only; not a stable or production-qualified release.

- Fixed receiver startup under systemd confinement by explicitly retaining the
  broker's UID-drop capability; retained all sandbox restrictions.
- Added worker readiness notification and bounded startup failure instead of
  reporting success merely because systemd accepted a start request.
- Made explicit receiver setup generate fresh IDs, issuer/endpoint keys and
  one-use codes, with terminal retirement and worker shutdown before atomic
  replacement. Normal restart and network recovery preserve identities.
- Added confirmation before replacing a paired client, visible public URL
  input, and exact machine-specific next-step commands.
- Allowed verified managed preview installation to upgrade 0.1.1/0.1.2 units.

## [0.1.2]

Signed development preview only; not a stable or production-qualified release.

- Added one managed VPS setup with a visible public-URL prompt, automatic
  container-engine selection, an unprivileged container and reboot service.
- Added site-specific route adapters for standard Nginx, Apache and Caddy
  configurations, genuine public WebSocket verification and rollback.
- Preserved an existing paired relay's identity during managed adoption.
- Added direct receiver registration without container commands and automatic
  relay setup after interactive installation.

## [0.1.1]

Signed development preview only; not a stable or production-qualified release.

- Added an explicitly versioned receiver-owned pairing profile and local
  `pair` commands for client, connector and relay. Legacy setup is unchanged.
- Added client-local key generation, receiver-local issuance, exact pinned inner
  TLS, automatic operational credential renewal, durable one-use pairing and
  exact retry, and opaque relay registration/bootstrap.
- Added session-bound mutual authorization leases, persistent local lock/unlock,
  active-worker shutdown acknowledgement, and fixed-target SSH integration.
- Isolated receiver authority keys from the Linux network worker using a
  root-owned local pipe broker and a dropped-privilege worker.
- Added integrated SSH exec, restart, renewal, lock/reconnect and protocol
  rejection tests. Published 0.1.0 assets and installers are unchanged.
- Added isolated signed Linux development installation and a prompted
  `pair setup` path that starts the receiver's installed reboot-enabled service.
- Made explicit security alarms terminal: no unlock of the old pairing. Normal
  restart/network failure remains recoverable without an alarm or trust reset.

## [0.1.0]

### Added

- Added Linux arm64/aarch64 client, connector, relay-image, lifecycle, and
  provisioner artifacts alongside the existing Linux amd64/x86_64 artifacts.
  The supported matrix is Apple-silicon macOS, Linux amd64, and Linux arm64;
  Intel macOS remains unsupported.
- Expanded deterministic staging, manifests, SBOMs, native archives,
  installers, and authenticated distribution evidence from nine artifacts to
  the exact fourteen-artifact matrix.

### Security

- Made the nine-to-fourteen artifact transition an explicit prerelease
  boundary. Installed `0.1.0-rc.*` package state is not a supported in-place
  predecessor for stable `0.1.0`; the old exact-nine lifecycle must fail closed
  on the stable manifest. Ordinary uninstall deliberately preserves that state,
  and no destructive RC trust-reset is implemented. The hard macOS release
  lane therefore stays read-only; Linux release qualification reuses retained,
  authenticated hosts without pretending that any retained RC state was
  purged.

- Replaced the macOS client's public release-selector symlink with a distinct
  single-link `root:_owntransit` mode-`2751` regular launcher. Its bytes must
  match the authenticated release-launcher digest, while the protected release
  launcher and mode-`0750` real client remain inside the non-user-traversable
  role tree.
- Published that launcher only through a fixed `root:wheel` mode-`0700` private
  stage using a fresh inode, ownership-before-setgid ordering, fsync, exact
  metadata/ACL/digest checks and atomic rename. Noncanonical residue and unsafe
  public-entry types or metadata fail closed; only the exact historical symlink
  is accepted for symlink migration.
- Made the launcher revalidate the descriptor-relative authenticated `current`
  selector immediately before exec and enumerate `/dev/fd` when closing
  inherited descriptor authority, including descriptors above a subsequently
  lowered resource limit.
- Made the setgid launcher authenticate its exact raw public invocation path
  before every protected read. An ordinary user's retained hard-link alias is
  denied, while canonical execution and replacement remain available when the
  public inode has additional links; uninstall first removes setgid from every
  retained link.
- Serialized macOS client and provisioner package apply, rollback, recovery,
  detach and all deterministic public-entry stages with one persistent,
  root-only advisory lock. Interrupted stages are recoverable only through
  their exact bounded metadata profiles.
- Froze the next `0.1.0` signing ceremony to
  release/policy/floor/lifecycle tuple `13/9/13/1`, preventing rollback to
  RC5-RC7 package boundaries after the launcher and Linux provisioner
  migrations. The earlier private `8/4/8/1`, `9/5/9/1`, `10/6/10/1`, and
  `11/7/11/1` issuances were not publicly distributed. The `9/5/9/1` was used
  only for private qualification; the `10/6/10/1` issuance from public commit
  `5ce5245c` was signed and then abandoned when the v0.1.0 release
  qualification scope was simplified before publication. The `11/7/11/1`
  issuance from public commit `442a5696` was rejected when live qualification
  exposed a post-READY doctor teardown false negative. A fifth private attempt
  from public commit `117e24eb` issued the release-manifest and policy
  signatures for tuple `12/8/12/1`, then failed the protected-ancestor ACL
  preflight before atomic handoff publication. All five abandoned attempts
  permanently consumed their release and policy sequences; none of their
  artifacts, ledgers, signatures, or evidence may be reused.
- Kept the macOS provisioner release tree non-user-traversable as
  `root:wheel` mode `0750` and published a distinct `root:wheel` mode-`0755`
  public provisioner copy with the authenticated digest and a different inode.
  Only the exact historical selector symlink is accepted for migration; macOS
  performs no provisioner-directory chmod migration.
- Moved macOS public-entry removal into the authenticated lifecycle's durable
  `package-detach` operation. Client detach removes setgid from the opened
  launcher inode before unlinking its canonical name, deactivating retained
  hard-link aliases, and resumes only from authenticated partial states.
- Serialized complete Linux install and non-purging uninstall integration
  windows with one persistent root-only platform lock. Connector and relay
  detach additionally retains the role supervisor lock, revalidates the
  selected release, and converges only exact-or-absent partial residue.

### Fixed

- Made the carrier-only doctor treat only wrapped `EOF` and closed-network
  results during post-READY cleanup as successful teardown. The relay is
  deliberately allowed to abort paired carriers after drain; every outer TLS,
  inner mTLS, endpoint authorization, fixed loopback dial, and exact READY
  failure remains fatal.
- Made Linux connector and relay package recovery atomically replace the
  start-blocking mutation intent with a durable restart-pending record before
  invoking systemd. Start failure and reboot preserve a recoverable obligation,
  and clean-host qualification now executes this active recovery path after a
  cold boot.
- Made signed source archives independent of ambient Git `tar.umask`, and
  fail-closed unless archive metadata preserves exact mode-`0644` regular
  files, mode-`0755` executables and mode-`0755` directories.
- Bound Darwin launcher activation to the signed launcher's receipt digest and
  made post-selection client install invoke recovery through the newly selected
  lifecycle binary. Even an idempotent complete recovery now authenticates the
  running lifecycle before accepting installed state.
- Made package-directory ownership and traversal role- and platform-aware.
  Runtime-bearing roles and the macOS provisioner remain mode `0750`; only the
  Linux provisioner's root-owned mode-`0755` package path is reached through
  its ordinary public selector. Linux requires `fs.protected_hardlinks=1`
  before every provisioner package operation and alone repairs the legacy
  provisioner mode-`0750` tree inner-first, resuming only when the exact signed
  candidate release and lifecycle digest are already selected.

### Assurance

- Reduced the 0.1.0 hard release record to four honest exact-byte results:
  source/security/publication, independent signature verification,
  supported-artifact execution on existing hosts, and live SSH plus
  integrity-checked SCP through the untrusted relay using unchanged
  pre-existing operator client configuration and SSH key, with no macOS system
  mutation and no deployed connector configuration or endpoint-credential
  change. The bounded platform result
  runs the exact native binaries, inspects non-ordinary artifacts, performs no
  macOS system mutation, and qualifies exact
  connector install/activation, enabled restart, actual host reboot/direct
  reacquisition, and post-boot running/retrying on both Linux architectures. It
  does not claim stable native macOS client lifecycle activation, macOS
  provisioner package lifecycle, Linux client, provisioner, or relay package
  lifecycle, or pristine-host evidence.
  Clean-room
  platform matrices, dual relay-exchange labs, exhaustive composite dossiers
  and external review remain documented additional assurance rather than
  hidden publication blockers.
- Extended macOS install, uninstall, qualification and static gates for the
  distinct public launcher and provisioner copy, equal signed digest/different
  inode invariants, exact persistent global mutation lock, durable detach,
  private staging cleanup, canonical-path and retained-hard-link-alias
  behavior, direct protected-launcher denial, exact selector check and
  inherited-descriptor cleanup.
- Added Apple Container as a digest-pinned fallback for deterministic native
  archive qualification on macOS hosts without local GNU tar or Docker.
- Made pinned container verification execute on each actual target Linux
  architecture rather than the builder architecture, and made privileged
  helper-process tests portable across native and emulated execution.

## [0.1.0-rc.7]

### Fixed

- Normalized both bare and `sha256:`-prefixed Podman image identities during
  Linux relay installation without weakening the manifest-pinned comparison.
- Removed a BSD `awk` builtin-name collision from macOS client-reader identity
  validation.
- Read the complete Darwin permission mode in macOS install, uninstall,
  qualification, archive, signing, and protected-key checks. The required
  setgid client launcher is now recognized correctly, while unexpected setuid,
  setgid, or sticky bits fail closed throughout the release path.
- Keyed the supplied Nginx per-peer availability limits on the original TCP
  peer address and moved them to fresh shared-memory zone names, preventing an
  ambient Real-IP policy from making request headers select quota identities.

### Assurance

- Added cross-platform negative fixtures for special permission bits and for
  request-rewritten reverse-proxy quota keys. This candidate remains subject to
  the complete signed-artifact and supported-host qualification gates.

## [0.1.0-rc.5]

### Added

- Candidate implementation intended to become the first stable, installable
  OwnTransit release for Apple-silicon macOS and Linux amd64 within the
  SSH-only carrier boundary after all hard gates pass.
- Native client, connector, relay, lifecycle, and offline-provisioning
  executables with the connector destination build-fixed to literal
  `tcp4 127.0.0.1:22`.
- Guided target-generated enrollment, hostile-mailbox exchange, target-first
  two-way word comparison, resumable setup, and authenticated carrier-only
  `READY`.
- Temporary authenticated relay exchange-only cold start for the first route,
  with a packaged non-enableable system service and no carrier, endpoint state,
  authority material, persistence, or target selection.
- Authenticated local-role installation entry point that verifies the outer
  handoff, native checksums, release manifest, and monotonic policy before
  executing the fail-closed platform installer.
- Deterministic nine-artifact staging with signed manifests, SBOMs, licenses,
  source archive, Homebrew formula, and digest-addressed relay image.
- Canonical semantic-version support in the immutable release ledger and signing
  workflow.

### Security

- Preserved independent outer and end-to-end inner TLS 1.3 mTLS boundaries,
  exact endpoint authorization, and the pre-local-dial authentication gate.
- Added checked allocation arithmetic for domain-separated signature inputs.
- Removed the unauthenticated maximum-response parser copy before mailbox
  acceptance and packaged the relay with a 192 MiB Go soft limit beneath its
  fixed 256 MiB hard ceiling.
- Preserved signed monotonic release policy, external rollback anchors,
  tombstones, and exact-record rollback across package transitions.
- Bound crash recovery to the request's authenticated creation time, so an
  unsigned resume clock cannot move historical enrollment validation backward
  or manufacture a new validation point.
- Held the target lifecycle lock across applied-response reconciliation, the
  live carrier proof, the READY receipt, and the target-session transition, so
  a concurrent policy, rollback, recovery, rotation, or response apply cannot
  replace the active record inside that decision.
- Kept expired enrollment artifacts fail-closed before apply while permitting
  an exact already-Applied client to reconcile its anchored response and run a
  current live READY proof after cutover.

### Fixed

- Corrected the bounded enrollment-response envelope for both canonical base64
  layers at the documented maximum size.
- Closed the fresh-route mailbox/carrier bootstrap loop. The initial
  route remains deliberately scoped to one client; later-client enrollment is
  not implemented in 0.1.0.

### Assurance

- The tooling can build an exact signed 0.1.0-rc.5 candidate handoff. The
  project owner may publish those exact bytes only as a prominently marked
  GitHub qualification prerelease with their honest signed qualification
  record, including a `BLOCKED` record while hard platform gates remain open.
  That public lane permits only genuinely `NOT-PERFORMED` gates, never an
  observed failure, with no known Critical or High finding left open or merely
  accepted.
  Official stable 0.1.0 publication still requires an independently verified
  signed `PASS` record for every hard gate.
- Independent external security certification is not claimed for 0.1.0-rc.5.

The 0.1.0-rc.5 candidate supersedes the unpublished 0.1.0 candidate bytes and
the unpublished 0.1.0-rc.3 and 0.1.0-rc.4 snapshots. This entry does not
declare a stable publication or supported deployment.

## [0.1.0-rc.4]

### Security

- Added checked platform-integer arithmetic before allocating the
  domain-separated signature input, so an oversized sign or verify request is
  rejected instead of allowing the allocation-size calculation to wrap. This
  correction addresses the High CodeQL `go/allocation-size-overflow` finding
  and supersedes the unsigned, unpublished `0.1.0-rc.3` candidate.

### Fixed

- Sized the bound enrollment-response envelope for its two canonical base64
  layers, allowing the documented maximum target-encrypted response to pass
  through the mailbox, wire and durable-session limits.

### Not yet qualified

- Every `0.1.0-rc.3` build, scan and qualification result applies only to that
  frozen source. The corrected `0.1.0-rc.4` source requires a new candidate
  ledger, deterministic build, independent scan and complete qualification.
- Production signer custody, clean-host lifecycle matrices, independent
  implementation review and authorized penetration testing remain open.

This historical prerelease snapshot was not signed, tagged, or published as a
release. It is superseded by 0.1.0.

## [0.1.0-rc.3]

### Added

- Native SSH-only client, connector and always-relayed carrier roles.
- Independent outer and end-to-end inner TLS 1.3 mutual-authentication
  boundaries with strict route-capability authorization.
- Target-local enrollment, verifier-first lifecycle policy, route rotation,
  tombstone, external rollback-anchor and exact-record rollback primitives.
- Signed release-manifest and release-policy formats, SPDX and license
  evidence with a production-graph dependency-license gate, deterministic
  nine-artifact staging, native installer payloads and package-transaction
  foundations.
- Guided one-invitation client setup with durable target/operator sessions,
  hostile-mailbox courier exchange, target-first two-way word comparison,
  exact response/request-set binding, resume/cancel, carrier-only READY and
  local-authoritative one-time capability cleanup.
- Manager-held release-policy/rollback-anchor/selector locking across client
  setup, authenticated package apply/rollback/recovery, external rollback
  floors, stable runtime handles and current/previous release retention.
- Linux exact local-account binding and macOS zero-member reader identity,
  fixed setgid launcher, normal non-setgid setup frontend, live GeneratedUID
  validation and descriptor-based ACL checks.
- Clean-public-root exporter and read-only GitHub release-candidate gate.
- Qualification-only candidate identity, deterministic native-archive and
  offline signing orchestration for the private RC workflow.
- Fail-closed verification of the exact monotonic policy anchor produced by
  the signer; the private `rc.1` rehearsal stopped before publication and was
  superseded by this candidate.
- Homebrew-style-clean client formula after the private `rc.2` handoff passed
  signing, independent verification, local installation and
  binary-reproducibility checks but was withheld from publication by the live
  formula style gate.

### Not yet qualified

- Clean-host install, upgrade, interruption, rollback, uninstall and recovery
  matrices on Linux amd64 and Apple-silicon macOS, including systemd,
  Directory Services, setgid/ACL and reboot behavior.
- Independent clean-builder reproduction and public-object secret scan.
- Independent implementation/legal review, authorized penetration test, and
  the actual release/policy signer custody and recovery ceremony.

This historical prerelease snapshot was not installable as a supported
hardened runtime and is superseded by 0.1.0.
