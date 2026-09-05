# OwnTransit release checklist

This is the immutable-release procedure for stable and prerelease versions. It
does not itself authorize publication, infrastructure changes or credential
rotation. It separates hard artifact-integrity requirements from additional
assurance and owner-governance decisions so their status is recorded against
one exact commit without inventing external certification.

## 1. Freeze the public source candidate

- Start from the sanitized new-root repository produced by
  `scripts/export-public-root.sh`, never from the private development history.
- Confirm the canonical module and repository are
  `github.com/sentrybottale/owntransit`.
- Require the `release-candidate / repository boundary` and
  `release-candidate / Go security profiles` checks on `main`.
- Require review before changing this checklist, `SECURITY.md`, release code,
  workflow files, installer code, authenticated wire values, or signing keys.
- Make the candidate commit immutable for the remainder of qualification. Any
  source change creates a new candidate and invalidates prior build, review and
  qualification evidence.

Run on the exact full-history checkout:

```text
./scripts/publication-check.sh --history
./scripts/security-check.sh --full
./scripts/tests/publication-tools.sh
./scripts/release/static-check.sh
./scripts/qualify/static-check.sh
./scripts/qualify/test-signature-tools.sh
```

After the new public root commit exists, run an independent secret scanner on
only the complete exported/new public object graph when available, and record
or explicitly disclose its status. Do not upload the private development
history to a third-party scanner or treat a scan of it as public-release
evidence. The repository checks are defense in depth and are not that
independent scan.

## Release-readiness matrix

| Item | Class | Required disposition |
|---|---|---|
| Full source, security, publication and complete public-history checks | Hard publish gate | **PASS** for the exact frozen candidate, including both race/vet profiles, pinned vulnerability analysis, release/qualification static checks and signature-helper tests |
| Independent verification of the signed handoff, release policy, manifests and inventories | Hard publish gate | **PASS** under independently obtained verifier trust for every exact artifact byte |
| Supported-artifact execution | Hard publish gate | **PASS** after exact native ordinary binaries are executed/version-checked on existing or operator-provided macOS arm64, Linux amd64 and Linux arm64 hosts; relay OCI archives and the Darwin launcher are authenticated and inspected, including expected direct-launch rejection, with no macOS installation or system mutation; and both exact signed Linux connectors pass install/activation, enabled-service restart, actual host reboot, direct host reacquisition, post-boot running/retrying, binary-identity, systemd-confinement and no-listener checks. This does not claim stable native macOS client lifecycle activation, macOS provisioner package lifecycle, Linux client, provisioner, or relay package lifecycle, or a pristine host |
| Live SSH and SCP through untrusted transit | Hard publish gate | **PASS** using the exact signed macOS client through the deployed untrusted relay to the exact signed connector, including SCP digest integrity, the pre-existing operator-supplied client configuration and SSH key, no macOS system mutation, and unchanged client configuration, SSH key, connector configuration and connector endpoint credentials |
| Signed qualification record binding the candidate commit, release identity, outer asset inventory and four exact results | Hard publish gate | **PASS** only after independent signature verification and confirmation of `schema=owntransit.qualification.v1`, `gate_set=owntransit-0.1.0-minimal.v1`, overall `status=PASS`, four accurate PASS results, and zero unresolved Critical/High counts |
| Every known Critical/High defect | Hard publish gate | Closed; unresolved counts must both be zero |
| Pristine/factory-clean macOS and per-architecture Linux lifecycle/reboot matrices | Additional assurance | Record exact evidence or disclose **NOT PERFORMED** |
| Dual public relay-exchange qualification and exhaustive composite dossiers | Additional assurance | Record exact evidence or disclose **NOT PERFORMED** |
| Independent secret scan of the exported/new public object graph | Additional assurance | Record exact evidence or disclose **NOT PERFORMED** |
| Independent clean-builder reproduction | Additional assurance | Record exact evidence or disclose **NOT PERFORMED** |
| Signer/issuer custody and clean-room recovery rehearsal | Operator assurance | Record exact evidence or disclose **NOT PERFORMED** |
| Independent security review and authorized penetration test | Additional assurance | Record exact evidence/findings or disclose **NOT PERFORMED** |
| Name, contract, patent, assignment and publishing-entity review | Owner governance | Record the owner's disposition; repository tooling cannot certify it |
| Private canary, recovery rehearsal and burn-in | Operator assurance | Attach results when performed; preserve an alternate recovery path |

A hard-gate PASS authenticates and qualifies the frozen installable bytes within
their documented scope. It does not imply that an external/manual assurance
activity happened. An open assurance item does not require another candidate
unless it reveals a source or artifact change; its status must be disclosed.

## 2. Assign the version and release identity

- Select one canonical version: `MAJOR.MINOR.PATCH` for a stable release or
  `MAJOR.MINOR.PATCH-rc.N` for an immutable prerelease candidate, where `N` is
  a positive integer without a leading zero. Also select one fresh nonzero
  canonical release ID and one monotonic release sequence.
- Replace the matching `Unreleased` entries in `CHANGELOG.md` with an exact
  `## [VERSION]` heading, including the full `-rc.N` suffix for a prerelease.
  The heading freezes a qualification candidate; it is not a release decision
  or support statement. Do not date or announce a stable release that has not
  passed the hard publish gates. The narrowly owner-authorized public
  qualification-prerelease exception is defined in section 5.
- Record the exact candidate commit and its commit timestamp as the
  `SOURCE_DATE_EPOCH`. Never use a mutable branch name or `latest` identifier
  as a release input.
- Create the qualification-only candidate ledger with `releasectl
  candidate-init`. The command accepts the canonical stable and `-rc.N` forms
  above and rejects every other prerelease and build-metadata form. Store the
  ledger beneath the ignored operator boundary, review its version, fresh
  release ID, sequences, floors, source commit and source date, and never
  regenerate or overwrite it for the same candidate.
- Treat every release-manifest or release-policy signature operation as
  consuming its release and policy sequence, even when the resulting handoff
  remains private and is never tagged, uploaded or distributed. A correction
  gets a fresh release ID and strictly higher release and policy sequences; do
  not reclaim or reuse a signed tuple.
- For the `0.1.0` stable handoff, require the frozen release/policy tuple
  `13/9/13/1` (release sequence, policy sequence, minimum release sequence,
  minimum lifecycle). The signing conductor rejects every other tuple because
  rollback to RC5-RC7 is incompatible with the hardened macOS launcher and
  Linux provisioner package boundary.
- The private `0.1.0` candidate signed from public commit `9fc7d206` with tuple
  `8/4/8/1` was abandoned before tagging, upload or distribution when its
  source-archive packaging required correction. That signature permanently
  consumed release sequence `8` and policy sequence `4`; it is not a trust
  anchor and its ledger, signatures or qualification evidence must not be
  reused.
- The private `0.1.0` candidate signed from public commit `cfbd584f` with tuple
  `9/5/9/1` was rejected after the Linux arm64 clean-host run exposed a
  package-supervisor restart deadlock. It was never tagged or publicly
  distributed and was used only for private qualification, but its signature
  permanently consumed release sequence `9` and policy sequence `5`; its
  ledger, signatures and failed qualification evidence must not be reused as
  release inputs.
- The private `0.1.0` candidate signed from public commit `5ce5245c` with tuple
  `10/6/10/1` was abandoned when the v0.1.0 release qualification scope was
  simplified before publication. It was never tagged, uploaded, or publicly
  distributed, but its signatures permanently consumed release sequence `10`
  and policy sequence `6`; its artifacts, ledger, signatures, and
  qualification evidence must not be reused as release inputs.
- The private `0.1.0` candidate signed from public commit `442a5696` with tuple
  `11/7/11/1` was rejected after live qualification exposed a post-READY
  doctor teardown false negative. It was never tagged, uploaded, or publicly
  distributed, but its signatures permanently consumed release sequence `11`
  and policy sequence `7`; its artifacts, ledger, signatures, and failed
  qualification evidence must not be reused as release inputs.
- The private `0.1.0` attempt from public commit `117e24eb` issued the
  release-manifest and policy signatures for tuple `12/8/12/1`, then failed the
  protected-ancestor ACL preflight before atomic handoff publication. The
  attempt permanently consumed release sequence `12` and policy sequence `8`;
  its unsigned bundle, ledger, signatures, and partial evidence must not be
  reused as release inputs.
- The next issuance deliberately advances to `13/9/13/1` from the
  still-official RC7 policy anchor `3/5/1`. Skipping consumed policy sequences
  `4`, `5`, `6`, `7`, and `8` is intentional and does not claim that any
  abandoned policy was applied to the official policy/custody anchor.

## 3. Build and authenticate the candidate

- Build the exact fourteen-artifact matrix twice with
  `scripts/release/build-artifacts.sh`; require byte-identical same-builder
  outputs.
- Treat retained exact-nine `0.1.0-rc.*` package state as an unsupported
  in-place predecessor. Verify stable installation refuses it before mutation;
  the non-purging uninstaller is not a clean reset. Use a different unused role
  state for installation smoke on an existing host and never invoke the
  candidate lifecycle around the selected installed manager.
- When available, reproduce the unsigned artifacts on an independent clean
  builder from a fresh clone of the candidate public history and record the
  result as additional assurance. Disclose when it was not performed.
- Review `BUILD-INPUTS`, `SOURCE-MANIFEST.txt`, every artifact digest and size,
  the relay OCI identity, all SPDX records, third-party license evidence,
  provenance and the exact Apache-2.0 license digest.
- Run `scripts/tests/dependency-licenses.sh --full`; require the declared
  inventory to equal the production graph and review every upstream
  `LICENSE`, `COPYING`, `NOTICE` and `PATENTS` file captured in
  `evidence/THIRD_PARTY_LICENSES.txt`.
- Create and independently verify the detached software-release manifest
  signature and the separate monotonic release-policy signature. Keep private
  signing keys and passphrases outside the repository, workflow, agent,
  environment, command line and release bundle.
- For the initial private qualification handoff, use `archive-native.sh` and
  `sign-candidate.sh` with the exact candidate ledger to produce the fixed
  native/source/formula asset set and external trust directory. Require its
  mechanical ledger/`BUILD-INPUTS`/policy match. Verify the outer asset
  `SHA256SUMS` signature from independently obtained trust before extracting
  the native archive; then verify the nested native checksums, release manifest
  and policy signatures. The copied public files beside the candidate are
  comparison material, not trust bootstrap.
- Record any release-key and policy-key recovery rehearsal from independent
  custody locations as operator assurance. The actual signatures and their
  verification remain hard requirements even when that rehearsal is pending.

Checksums delivered beside unauthenticated artifacts are not authentication.
The relay, DNS, a download redirect and GitHub release text are not release
authorities.

## 4. Qualify the frozen bytes

- After completing the tests below, produce one canonical signed qualification
  record that binds the frozen commit, release identity, outer asset inventory,
  four exact results and zero unresolved Critical/High counts. Independently
  verify its `schema=owntransit.qualification.v1`,
  `gate_set=owntransit-0.1.0-minimal.v1`, overall `status=PASS`, and exact
  bindings before promotion. A detached log, unsigned JSON file or statement
  in this repository is not qualification evidence. Use
  `scripts/release/sign-qualification-record.sh` with the fixed result set
  documented in `scripts/release/README.md`. Supply the authenticated extracted
  native inventory, handoff trust root and four closed-schema canonical evidence
  records; arbitrary log hashes are not accepted. Keep its qualification output
  outside `assets/`, independently authenticate its reported SHA-256 handle, verify the
  `owntransit-qualification-v1` SSHSIG, and inspect every evidence digest. The
  helper signs an honest `BLOCKED` record when any fixed result is not `PASS` or
  either unresolved Critical/High count is nonzero; it does not execute tests.
- Pass the complete source/security/publication/history gate for the frozen
  public commit, including both race and vet profiles and all required helper
  and static tests.
- Independently authenticate the exact handoff trust statement, outer and
  native inventories, release manifest, policy and every referenced byte.
- Execute/version-check every exact native ordinary binary on existing or
  operator-provided macOS arm64, Linux amd64 and Linux arm64 hosts. Authenticate
  and inspect the relay OCI archives and Darwin launcher, including the
  launcher's expected direct-path rejection. Perform no macOS installation or
  system mutation. On both Linux architectures,
  install and activate the exact signed connector, restart its enabled service,
  perform an actual host reboot, reacquire the host directly, prove the
  connector is running or retrying post-boot, verify the exact running binary
  and systemd confinement, and prove OwnTransit owns no listener. Record
  pre-existing state honestly. This gate does not claim stable native macOS
  client lifecycle activation, macOS provisioner package lifecycle, Linux
  client, provisioner, or relay package lifecycle, or a pristine host.
- Use the exact signed macOS client through the deployed untrusted relay to the
  exact signed connector. Complete a real SSH session and an SCP transfer, and
  compare the transferred object's digest at both ends. Use the pre-existing
  operator-supplied client configuration and SSH key, perform no macOS system
  mutation, and confirm those client inputs plus the deployed connector
  configuration and endpoint credentials remain unchanged.
- Keep pristine-host lifecycle/reboot matrices, dual relay-exchange labs,
  exhaustive composite dossiers and broader hostile-relay/resource-exhaustion
  campaigns as additional assurance. Record them when performed; they are not
  fixed 0.1.0 qualification-record results.
- Record whether the independent implementation review and authorized
  penetration test defined by `SECURITY_REVIEW.md` were performed. Do not imply
  that they passed when absent. Close every known unresolved Critical or High
  finding without changing the frozen bytes.
- Record the owner disposition for professional name, applicable-contract,
  targeted-patent, contributor-assignment and publishing-entity review.
  Repository tooling cannot perform or certify those reviews.

## 5. Tag and publish without granting CI authority

For the separately owner-authorized development-preview lane, follow
[scripts/development/README.md](scripts/development/README.md). Its versioned
capsules and `owntransit-development-v1` signatures are explicitly not a stable
or qualified handoff. That lane may use a plain numeric immutable version with
GitHub's prerelease flag and a DEVELOPMENT PREVIEW warning; it neither creates
nor substitutes a production qualification record. The stable and qualification
prerelease contracts below remain unchanged.

After every hard publish gate passes and every assurance/governance item has an
honest recorded disposition, a stable release may receive one signed annotated
tag locally. A stable tag uses the exact canonical `MAJOR.MINOR.PATCH` version
already bound into its qualification ledger and artifacts; it is not created
by stripping `-rc.N` from existing candidate bytes.

The project owner may instead authorize a public qualification prerelease so
other machines can exercise one exact candidate before its hard platform gates
are complete. That exception is valid only when all of the following are true:

- the changelog heading, candidate ledger, embedded binary version, archives,
  formula and tag all use the same canonical `MAJOR.MINOR.PATCH-rc.N` version;
- the source/history gates and actual release, policy, native, source and outer
  inventory signatures for those exact bytes have passed and been
  independently verified;
- the exact outer asset set has a signed qualification record whose status is
  honestly derived as either `PASS` or `BLOCKED`; a public `BLOCKED` candidate
  may contain only `NOT-PERFORMED` hard gates, never a `FAIL`, and both
  unresolved Critical and High counts must be zero;
- `NOT-PERFORMED` means no execution produced a result; an observed failed or
  inconclusive execution may not be relabeled and blocks public publication
  until a corrected new candidate exists, and no known Critical or High
  finding may remain open or accepted for this lane;
- the candidate receives one locally verified, signed annotated and immutable
  `vMAJOR.MINOR.PATCH-rc.N` tag selecting its exact source commit;
- the GitHub release is created as a draft, its complete downloaded asset set
  is verified, and it is published only with GitHub's prerelease flag and a
  prominent `QUALIFICATION ONLY — NOT STABLE OR PRODUCTION-QUALIFIED` warning;
  and
- the release text makes no stable, supported, production-ready, promotion,
  certification or `latest` claim and directs testers to retain an independent
  access and recovery path.

This exception publishes testable evidence, not a supported release, and never
satisfies or waives a stable hard gate. The owner authorization and all open
gate dispositions must be recorded in the prerelease notes. A correction gets
a new positive `rc.N` number and new candidate rather than a moved tag. Never
attach a `BLOCKED` record to a stable `vMAJOR.MINOR.PATCH` tag.

```text
git tag -s -a vVERSION COMMIT -m "OwnTransit vVERSION"
git verify-tag vVERSION
git rev-list -n 1 vVERSION
```

The tag must select the frozen commit and match the exact changelog heading.
The read-only GitHub check requires an annotated tag with a recognized
signature envelope, but only `git verify-tag` under the independently obtained
signer trust root authenticates that signature. Push the branch and tag only to
the canonical public repository. The workflow verifies the candidate; it never
signs, uploads, publishes, installs, deploys, rotates credentials or creates a
GitHub release.

Before attaching artifacts, verify the tag and every OwnTransit release/policy
signature from a fresh clone and a separately obtained signer trust root.
Enable GitHub's immutable-release setting when available, disable tag deletion
or force updates through repository rules, and publish only the already
authenticated frozen files. For the qualification-prerelease exception, upload
and verify those files while the release remains a draft, then publish that
same draft as a prerelease; never let GitHub synthesize a lightweight tag.

## 6. Operator canary and continuing assurance

- Keep operator-owned out-of-band SSH and host recovery throughout canary and
  burn-in.
- Rehearse install, upgrade, rotation, revocation, rollback and clean-room
  OwnTransit recovery using the signed release.
- Attach canary and burn-in results to the exact signed release when available;
  do not describe missing evidence as a successful exercise.
- After publication, a source or artifact correction receives a new immutable
  version, normally the next stable patch. Before publication, an explicitly
  reviewed stable-candidate correction may retain its intended semantic version
  only with a fresh release ID, strictly advanced release and policy sequences,
  a newly frozen tuple, and complete requalification. Assurance records that do
  not change bytes do not require a new RC or release version.
