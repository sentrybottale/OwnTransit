# Changelog

OwnTransit records user-visible and security-relevant changes here. An
immutable prerelease candidate is moved out of `Unreleased` when its source is
frozen so its exact version can be bound into build and qualification evidence.
That heading is not a release decision or production claim. A stable-version
heading may freeze the intended release bytes before qualification, but it
becomes a publication record only after its authenticated evidence, signed
qualification record and release decision are complete. Git tags never create
or publish artifacts automatically.

## [Unreleased]

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
