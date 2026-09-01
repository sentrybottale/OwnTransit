# OwnTransit release checklist

This is the immutable-candidate procedure. It does not authorize publication,
infrastructure changes, credential rotation, or a production claim. The v1 tag
is created only after every repository-controlled and manual stop gate below is
recorded against one exact commit.

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

After the new public root commit exists, an independent secret scanner must
inspect only the complete exported/new public object graph. Do not upload the
private development history to a third-party scanner or treat a scan of it as
public-release evidence. The repository checks are defense in depth and are
not that independent scan.

## Release-readiness matrix

| Gate | Evidence class | V1 status |
|---|---|---|
| Prospective public tree, both race/vet profiles, pinned vulnerability analysis, release/qualification static checks and signature-helper tests | Automated | Must report **PASS** for the exact frozen candidate in both required read-only CI jobs |
| Complete one-root public history and clean-export boundary | Automated | Must report **PASS** after the sanitized root commit exists; the private development history is not a candidate |
| Independent secret scan of the exported/new public object graph | External/manual | **OPEN** |
| Independent clean-builder reproduction and authenticated release/policy signatures | External/manual | **OPEN** |
| macOS/Linux clean-host lifecycle, interruption, rollback, uninstall and recovery matrices | External/manual | **OPEN** |
| Signer/issuer custody and clean-room recovery rehearsal | External/manual | **OPEN** |
| Independent security review, authorized penetration test and Critical/High disposition | External/manual | **OPEN** |
| Name, contract, patent, assignment and publishing-entity review | External/manual | **OPEN** |
| Private canary, recovery rehearsal and burn-in decision | External/manual | **OPEN** |

Automated PASS means only that the frozen bytes passed repository-controlled
checks. It cannot substitute for an external/manual gate or make the release
production-ready.

## 2. Assign the version and release identity

- Select one canonical version: `MAJOR.MINOR.PATCH` for a stable release or
  `MAJOR.MINOR.PATCH-rc.N` for an immutable prerelease candidate, where `N` is
  a positive integer without a leading zero. Also select one fresh nonzero
  canonical release ID and one monotonic release sequence.
- Replace the matching `Unreleased` entries in `CHANGELOG.md` with an exact
  `## [VERSION]` heading, including the full `-rc.N` suffix for a prerelease.
  The heading freezes a qualification candidate; it is not a release decision,
  support statement or production claim. Do not date or announce a release
  that has not passed the remaining gates.
- Record the exact candidate commit and its commit timestamp as the
  `SOURCE_DATE_EPOCH`. Never use a mutable branch name or `latest` identifier
  as a release input.
- Create the qualification-only candidate ledger with `releasectl
  candidate-init`. Store it beneath the ignored operator boundary, review its
  version, fresh release ID, sequences, floors, source commit and source date,
  and never regenerate or overwrite it for the same candidate.

## 3. Build and authenticate the candidate

- Build the exact nine-artifact matrix twice with
  `scripts/release/build-artifacts.sh`; require byte-identical same-builder
  outputs.
- Reproduce the unsigned artifacts on an independent clean builder from a
  fresh clone of the candidate public history.
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
- Rehearse release-key and policy-key recovery from the documented independent
  custody locations before accepting their signatures.

Checksums delivered beside unauthenticated artifacts are not authentication.
The relay, DNS, a download redirect and GitHub release text are not release
authorities.

## 4. Qualify the frozen bytes

- Complete the clean macOS arm64 and Linux amd64 matrices in `ROADMAP.md`,
  including cold boot, reconnect, upgrade, interrupted apply, concurrency,
  authenticated rollback, non-purging uninstall and clean OwnTransit recovery.
- Prove the connector remains outbound-only and can dial only literal
  `tcp4 127.0.0.1:22`; prove the client writes only SSH bytes to stdout.
- Complete hostile-relay and resource-exhaustion qualification against the
  exact candidate.
- Obtain the independent implementation review and authorized penetration
  test defined by `SECURITY_REVIEW.md`. Close or explicitly accept every
  Critical or High finding without changing the frozen bytes.
- Record professional name, applicable-contract, targeted patent,
  contributor-assignment and publishing-entity clearance. Repository tooling
  cannot perform or certify those reviews.

## 5. Tag without granting CI publication authority

After every prior item passes, create one signed annotated tag locally. An
`-rc.N` tag names an immutable nonproduction candidate; it does not waive any
manual gate or authorize promotion. A correction gets a new positive `rc.N`
number and new candidate rather than a moved tag.

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
authenticated frozen files.

## 6. Canary and promotion

- Keep operator-owned out-of-band SSH and host recovery throughout canary and
  burn-in.
- Rehearse install, upgrade, rotation, revocation, rollback and clean-room
  OwnTransit recovery using the signed release.
- Promote the release to supported v1 only after the burn-in and every manual
  gate is recorded. Otherwise publish no production claim and cut a new
  candidate for any correction.
