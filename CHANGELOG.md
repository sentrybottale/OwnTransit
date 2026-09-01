# Changelog

OwnTransit records user-visible and security-relevant changes here. An
immutable prerelease candidate is moved out of `Unreleased` when its source is
frozen so its exact version can be bound into build and qualification evidence.
That heading is not a release decision or production claim. A stable version is
recorded only after its authenticated evidence, qualification record and
release decision are complete. Git tags never create or publish artifacts
automatically.

## [Unreleased]

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

This prerelease candidate is not installable as a supported hardened runtime
until the listed qualification gates close. No production version has been
released.
