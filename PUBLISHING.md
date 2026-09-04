# Publishing OwnTransit safely

This project originated in a private development and operations workspace. A
clean working tree is not proof that its Git history is safe to publish.

Source publication and an authenticated binary release are separate events. A
public checkout is never an authenticated installation. OwnTransit 0.1.0 is
currently a candidate line: its tooling can produce a signed installable
handoff for qualification, but that handoff is not an official stable release
until the exact artifact set satisfies the four bounded integrity and execution
requirements below and carries an independently verified signed qualification
record with `schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1`, and overall `status=PASS`. Until then,
describe it as a candidate and never as stable or
production-ready. After those gates pass, the bounded claim is
“stable and installable within the documented scope,” not an unqualified
“production-ready” claim.

Within that scope, the only positively qualified package lifecycle is the Linux
connector on both supported architectures, and the exact Mac client transport
is qualified by the live path. Stable native macOS client lifecycle activation
and the other explicitly listed package lifecycles are not claimed by the 0.1.0
qualification record.

The project owner may authorize a public qualification prerelease solely so
other machines can test one exact candidate. That narrow lane requires a
canonical `MAJOR.MINOR.PATCH-rc.N` version everywhere, an independently
verified signed artifact handoff, an honest signed `PASS` or `BLOCKED`
qualification record, a signed annotated immutable tag, and a GitHub release
published with the prerelease flag. Its title and opening text must say
`QUALIFICATION ONLY — NOT STABLE OR PRODUCTION-QUALIFIED`; every open hard gate
must be `NOT-PERFORMED`, no fixed gate may be `FAIL`, both unresolved Critical
and High counts must be zero, and the release must make no support, stable,
promotion, certification or `latest` claim. A public qualification prerelease
does not satisfy or waive any stable-release gate. `NOT-PERFORMED` means no
execution produced a result: never relabel an observed failure or inconclusive
run, and no known Critical or High finding may remain open or accepted for this
lane.

## Required public-history boundary

The public repository must begin with one reviewed sanitized snapshot committed
as a **new root commit with no parent**.

Do not push the private `.git` directory, preserve its commit IDs, graft its
history, add it as an alternate, or merge it into the public repository. A file
deleted from today's tree may still expose endpoints, credentials, operator
identifiers, access procedures, or deployment evidence in an earlier commit.

History rewriting is destructive and is not authorized by this document. Build
the public history from an exported snapshot instead of trying to sanitize the
private history in place.

After the tree passes its publication checks, create that snapshot outside the
working repository with:

```sh
./scripts/export-public-root.sh /absolute/path/to/OwnTransit-public
```

The exporter refuses an existing or nested destination, copies every regular
file tracked by Git or untracked under the repository's `.gitignore` policy,
and excludes every repository-ignored local/runtime file. Global Git excludes
and `.git/info/exclude` cannot silently omit untracked source. It compares the
source file set, bytes, sizes and executable modes before and after the copy,
rejects filesystem metadata sidecars or any other extra entry, initializes a
hook-free new `main` repository, stages raw blobs without Git filters, proves
the staged bytes and modes are the reviewed set, and reruns the checks there.
It deliberately does not commit, tag, add a remote, or publish. The existing
private repository remains untouched.

After the new root commit is created, run the complete-history publication
check and an independent secret scanner **inside that exported repository**.
Do not submit or upload the private development object graph to a third-party
scanner and do not cite a scan of that graph as public-release evidence.

Before the first push, verify that:

- the candidate repository has exactly one root and the first public commit has
  no parent;
- every reachable object belongs to the reviewed public snapshot or later
  public work;
- `.private/`, runtime state, credentials, artifacts, access commands, private
  endpoints, operator identifiers, and deployment evidence are absent;
- the complete exported/new public history passes an independent secret scan;
  and
- a fresh clone contains the same reviewed files and no hidden dependency on
  the private workspace.

The private repository may retain its own history offline. It is not a source
remote for the public repository.

Retain that private history as a hashed, encrypted, access-controlled evidence
archive. A clean public root is a publication boundary, not authorization to
destroy the development record. Record the project owner's disposition for the
applicable-contract, independent-development, name, patent,
ownership-assignment and publishing-entity reviews tracked in `ROADMAP.md`;
repository tooling cannot perform or certify them.

## One-time source publication gates

Before creating that root commit:

1. Verify the canonical Apache-2.0 `LICENSE` file and bind its exact digest into
   release license evidence.
2. Preserve `github.com/sentrybottale/owntransit` as the canonical public
   repository and update the module path and imports atomically.
3. Preserve literal authenticated v1 wire values while adding OwnTransit public
   artifact names and compatibility entrypoints.
4. Review all public documentation and examples for reserved-only endpoints and
   invented identities.
5. Run both build profiles, vet, security checks and publication checks on the
   exact export. Record an independent secret scan when available, or disclose
   that it was not performed.
6. Run `scripts/tests/dependency-licenses.sh --full`, review the exact pinned
   production-module inventory in `THIRD_PARTY_NOTICES.md`, and review the
   upstream license/notice/patent files captured by generated release evidence.
7. Rebuild the candidate from a fresh clone of the new public root history;
   record an independent clean-builder reproduction when available, or disclose
   that it was not performed.

After creating the reviewed root commit, the read-only
`.github/workflows/release-candidate.yml` gate requires the complete public
history, both race/vet build profiles, pinned vulnerability analysis,
release/qualification static checks, detached-signature helper tests and the
clean-root exporter tests. Configure both workflow jobs as required branch
checks. The workflow has no signing, upload, package-publication, deployment or
credential authority.

Run the same repository-controlled gate locally with:

```text
./scripts/publication-check.sh --history
./scripts/security-check.sh --full
./scripts/tests/publication-tools.sh
```

These checks are not an independent secret scan, legal review, clean-builder
reproduction or outside security review. The status of those separate
assurance activities must be recorded without implying that repository tooling
performed them.

The frozen values isolated in `COMPATIBILITY.md` are authenticated protocol and
release inputs, not permission to publish old operational material or product
branding.

## Binary release rule

Do not publish an official stable artifact set until all hard release-integrity
requirements are complete for the exact bytes:

- the full source, security, publication and complete public-history gate;
- independent authentication of the signed handoff, release policy, manifests,
  outer and native inventories, and every referenced byte;
- execution/version checks of every exact native ordinary binary on existing or
  operator-provided macOS arm64, Linux amd64 and Linux arm64 hosts;
- authentication and inspection of relay OCI archives and the Darwin launcher,
  including expected direct-launch rejection, with no macOS system mutation;
- exact signed connector install/activation on existing Linux amd64 and Linux
  arm64 hosts, including enabled-service restart, actual host reboot, direct
  host reacquisition, post-boot running/retrying, running-binary identity,
  systemd confinement and absence of an OwnTransit listener;
- a real SSH session and integrity-checked SCP transfer from the exact signed
  macOS client through the deployed untrusted relay to the exact signed
  connector, using the pre-existing operator-supplied client configuration and
  SSH key without macOS system mutation and leaving those client inputs plus
  the deployed connector configuration and endpoint credentials unchanged;
- zero unresolved Critical and High defects; and
- an independently verified signed qualification record binding the exact
  candidate and outer asset inventory, with
  `schema=owntransit.qualification.v1`,
  `gate_set=owntransit-0.1.0-minimal.v1`, overall `status=PASS`, all four exact
  results at `PASS`, and both unresolved counts at zero.

Routine releases reuse retained, authenticated hosts. These checks require no
new machine and do not claim stable native macOS client lifecycle activation,
macOS provisioner package lifecycle, Linux client, provisioner, or relay
package lifecycle, or a pristine host. Clean-room macOS and broader Linux
lifecycle matrices, dual public relay-exchange labs and exhaustive composite
dossiers remain periodic additional assurance.

Independent implementation review, authorized penetration testing,
clean-builder reproduction, legal/name review, key-custody recovery rehearsal
and operator canary/burn-in are separate assurance or governance activities.
Their status must be disclosed for the exact release, but absence of an
external certification is not represented as missing client, connector, relay
or installer functionality. Actual usable release signatures remain a hard
requirement; a custody rehearsal does not substitute for them.

An owner-authorized public qualification prerelease may carry a signed
`BLOCKED` record solely because one or more of the four bounded gates remain
`NOT-PERFORMED`, but only under the exact prerelease boundary above and the
tag/draft-verification order in `RELEASE_CHECKLIST.md`. It must first pass the
public source/history gates and independently verified signing path for its
exact bytes. Publish the complete assets into a GitHub draft, download and
verify that draft, then expose the unchanged draft with the prerelease flag.
Keep every canonical trust and qualification digest available through a
pre-existing authenticated channel independent of GitHub and the OwnTransit
relay. Never use a blocked candidate as the only access or recovery path.

`RELEASE_MANIFEST.example.json` is an unsigned illustrative record with
reserved example locations and placeholder digests. It is not release evidence.
A detached signature is computed over the exact validated manifest bytes and is
never embedded back into the manifest it authenticates.

The candidate freeze, version/changelog rule, deterministic build, signing,
qualification, signed annotated tag and no-authority publication order are in
`RELEASE_CHECKLIST.md`. Pushing a tag only reruns verification; it does not
create or publish a release.

Signature issuance is irreversible release state even before publication.
Never reuse a release or policy sequence after any signature was created. The
private `0.1.0` candidate signed from public commit `9fc7d206` at tuple
`8/4/8/1` was abandoned before tagging, upload or distribution after a
source-archive packaging correction. A second private candidate from public
commit `cfbd584f` at tuple `9/5/9/1` was rejected after Linux arm64
qualification exposed a package-supervisor restart deadlock. A third private
candidate from public commit `5ce5245c` at tuple `10/6/10/1` was signed and
then abandoned when the v0.1.0 release qualification scope was simplified
before publication. None of those signature sets advances public trust, but
all consume their sequence numbers; their artifacts, ledgers, signatures, and
evidence must not be reused. The next `0.1.0` candidate must use a fresh release
ID and tuple `11/7/11/1`, verified from the still-official RC7 policy anchor
`3/5/1`, and requires a complete new qualification record.
