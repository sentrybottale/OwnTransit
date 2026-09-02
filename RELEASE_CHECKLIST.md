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
| Prospective public tree, both race/vet profiles, pinned vulnerability analysis, release/qualification static checks and signature-helper tests | Hard publish gate | **PASS** for the exact frozen candidate in both required read-only CI jobs |
| Complete one-root public history and clean-export boundary | Hard publish gate | **PASS**; the private development history is not a candidate |
| Actual release-manifest and release-policy signatures used by installers | Hard publish gate | **PASS** under independently obtained verifier trust for the exact artifacts |
| macOS arm64, Linux amd64, and Linux arm64 clean-host lifecycle, interruption, rollback, uninstall and recovery matrices | Hard publish gate | **PASS** independently for all three supported targets and the exact released bytes; installer/reboot JSON alone is only sub-evidence |
| Signed qualification record binding the candidate commit, release identity, outer asset inventory and exact platform results | Hard publish gate | **PASS** only after independent signature verification and confirmation that every other hard gate is recorded accurately |
| Every known Critical/High defect | Hard publish gate | Closed or explicitly accepted in the public release risk record |
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
- For the `0.1.0` stable handoff, require the frozen release/policy tuple
  `8/4/8/1` (release sequence, policy sequence, minimum release sequence,
  minimum lifecycle). The signing conductor rejects every other tuple because
  rollback to RC5-RC7 is incompatible with the hardened macOS launcher and
  Linux provisioner package boundary.

## 3. Build and authenticate the candidate

- Build the exact fourteen-artifact matrix twice with
  `scripts/release/build-artifacts.sh`; require byte-identical same-builder
  outputs.
- Treat retained exact-nine `0.1.0-rc.*` package state as an unsupported
  in-place predecessor. Verify stable installation refuses it before mutation;
  the non-purging uninstaller is not a clean reset. Run stable qualification on
  a genuinely fresh host and never invoke the candidate lifecycle around the
  selected installed manager.
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
  exact platform results and Critical/High disposition. Independently verify
  that record before promotion. A detached log, unsigned JSON file or statement
  in this repository is not qualification evidence. Use
  `scripts/release/sign-qualification-record.sh` with the fixed result set
  documented in `scripts/release/README.md`; keep its two-file output outside
  `assets/`, independently authenticate its reported SHA-256 handle, verify the
  `owntransit-qualification-v1` SSHSIG, and inspect every evidence digest. The
  helper signs an honest `BLOCKED` record when any fixed test is not `PASS` or
  either unresolved Critical/High count is nonzero; it does not execute tests.
- Complete the clean macOS arm64, Linux amd64, and Linux arm64 matrices in
  `ROADMAP.md`, including cold boot, reconnect, interrupted apply, concurrency,
  authenticated rollback, non-purging uninstall and clean OwnTransit recovery.
  Each Linux architecture is a separate hard gate, backed by a reviewed
  composite dossier rather than the installer/reboot JSON alone. For initial
  stable `0.1.0`, record upgrade as **N/A**: there is no supported predecessor,
  and public `0.1.0-rc.*` state is not an in-place upgrade source.
- Prove the connector remains outbound-only and can dial only literal
  `tcp4 127.0.0.1:22`; prove the client writes only SSH bytes to stdout.
- Complete hostile-relay and resource-exhaustion qualification against the
  exact candidate.
- Record whether the independent implementation review and authorized
  penetration test defined by `SECURITY_REVIEW.md` were performed. Do not imply
  that they passed when absent. Close or explicitly accept every known Critical
  or High finding without changing the frozen bytes.
- Record the owner disposition for professional name, applicable-contract,
  targeted-patent, contributor-assignment and publishing-entity review.
  Repository tooling cannot perform or certify those reviews.

## 5. Tag and publish without granting CI authority

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
- A source or artifact correction receives a new immutable version, normally
  the next stable patch after 0.1.0. Assurance records that do not change bytes
  do not require a new RC or release version.
