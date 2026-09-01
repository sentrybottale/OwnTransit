# Publishing OwnTransit safely

This project originated in a private development and operations workspace. A
clean working tree is not proof that its Git history is safe to publish.

Source publication and a production binary release are separate events. The
source may be published as explicitly pre-release software after the public
source gates pass. No binary may be described as production-ready until the
release gates in `ROADMAP.md` pass.

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
destroy the development record. Complete the applicable-contract,
independent-development, name, patent, ownership-assignment, and publishing
entity reviews tracked in `ROADMAP.md` before the first push.

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
5. Run both build profiles, vet, security checks, publication checks, and an
   independent secret scanner on the exact export.
6. Run `scripts/tests/dependency-licenses.sh --full`, review the exact pinned
   production-module inventory in `THIRD_PARTY_NOTICES.md`, and review the
   upstream license/notice/patent files captured by generated release evidence.
7. Reproduce the candidate from a fresh clone of the new public root history.

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

These checks are not the independent secret scan, legal review, clean-builder
reproduction or outside security review required elsewhere in this document.

The frozen values isolated in `COMPATIBILITY.md` are authenticated protocol and
release inputs, not permission to publish old operational material or product
branding.

## Binary release rule

Do not publish a production binary release until all of these are complete:

- executed and independently verified software-release and release-policy
  signatures with recovered, rehearsed key custody;
- end-to-end qualified verifier-first credential/capability-root rotation,
  authenticated revocation distribution, floor advancement, exact rollback
  and record retirement using the implemented source primitives;
- signed native artifacts, free macOS Homebrew/source-install qualification,
  and Linux service ownership and sandbox qualification; Developer ID
  packaging remains disabled and is not a v1 requirement;
- clean-host install, boot, reconnect, upgrade, interrupted-apply, rollback,
  uninstall, and recovery matrices; and
- independent implementation review and authorized penetration testing.

Initial enrollment working in source does not close those gates.

`RELEASE_MANIFEST.example.json` is an unsigned illustrative record with
reserved example locations and placeholder digests. It is not release evidence.
A detached signature is computed over the exact validated manifest bytes and is
never embedded back into the manifest it authenticates.

The candidate freeze, version/changelog rule, deterministic build, signing,
qualification, signed annotated tag and no-authority publication order are in
`RELEASE_CHECKLIST.md`. Pushing a tag only reruns verification; it does not
create or publish a release.
