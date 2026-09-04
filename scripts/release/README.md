# OwnTransit release and installer surface

This directory is intentionally offline and split into three boundaries:

- `build-artifacts.sh` produces the exact fourteen unsigned v1 artifacts twice,
  compares them, builds the relay OCI archive without a mutable base image, and
  emits a path-sorted `SHA256SUMS` staging tree with canonical SPDX, license,
  provenance and unsigned manifest evidence.
- `make-relay-oci.sh` wraps the static Linux relay binary plus the exact project
  license and consolidated dependency/BIP notices in a deterministic OCI
  layout. Its default command supplies `/runtime`, `/anchor`, and reader GID
  `65532` through the explicit runtime-view interface; the image has no shell,
  package manager, CA/issuer material, endpoint secret or update client.
- `install-*.sh` and `uninstall-*.sh` are auditable package payload logic. They
  never download anything. Install requires independently authenticated exact
  artifact and checksum-file digests and rejects existing destinations.
  Uninstall removes only enumerated program paths and preserves all state.
- `releasectl` constructs and verifies canonical SPDX 2.3 SBOMs, third-party
  license texts, the exact Apache-2.0 project LICENSE digest, build provenance,
  signed release manifests and signed monotonic release policy. It has no
  network updater, mutable `latest` input, publication path or deployment-key
  command. The release signer and release-policy signer remain independent of
  the endpoint deployment signer.

The build command requires an explicit monotonic `--sequence` and the exact
52-character lowercase unpadded RFC 4648 base32 release ID used by the Go wire
types. `BUILD-INPUTS`, executable build info, OCI annotations, the manifest and
installer release directory all carry that same canonical ID.

## Qualification-candidate conductor

`releasectl candidate-init` creates the non-secret, qualification-only ledger
for one clean frozen Git commit. It accepts a canonical `MAJOR.MINOR.PATCH`
stable version or `MAJOR.MINOR.PATCH-rc.N` prerelease version and rejects every
other prerelease or build-metadata form. Version components have no leading
zeros, and `N` is positive with no leading zero. The command generates a fresh
nonzero release ID with the protocol random-ID primitive, takes explicit
monotonic sequences and floors, reads the exact Git commit and commit
timestamp, and creates a mode-`0600` JSON file without ever overwriting an
existing path. Keep the ledger under the ignored operator boundary, for
example `.private/releases/vVERSION/candidate.json`. It is a build input
record, not a signing key, tag, release decision or trust anchor.

Run it only after the candidate source commit is clean and frozen:

```text
releasectl candidate-init \
  --version 1.0.0 \
  --release-sequence 5 \
  --policy-sequence 1 \
  --release-floor 5 \
  --lifecycle-floor 1 \
  --out /absolute/ignored/operator/candidate.json
```

Use the identical command surface with a version such as `1.0.0-rc.1` when
qualifying an immutable prerelease. A stable version still produces
qualification-only evidence; it does not bypass signing, review, tagging or
publication gates.

`archive-native.sh` validates the exact unsigned staging inventory,
`BUILD-INPUTS`, file modes and path-sorted checksums, snapshots it into new
inodes, and creates two byte-identical normalized archives before atomically
publishing `owntransit-VERSION-native.tar.gz`. The archive deliberately
contains no signatures, policy or trust files. It uses local GNU tar when
available, otherwise the digest-pinned build image through Apple Container or
Docker; every fallback mounts the immutable snapshot read-only and exposes
only a separate output directory.

`sign-candidate.sh` is the offline candidate-signing conductor. It accepts the exact
candidate ledger, explicit and separate release and policy PKCS#8 Ed25519
keypairs, one explicit OpenSSH Ed25519 distribution/source keypair, an
independently prepared `allowed_signers` trust file, a clean source checkout
and an explicit native bundle. It never generates keys. Before atomic output
publication it:

- verifies the candidate ledger against `BUILD-INPUTS`, policy floors, and the
  exact clean Git HEAD commit and commit timestamp in the source root;
- rejects reuse of one release/policy key ID;
- signs and verifies the software manifest and initial monotonic policy;
- signs and verifies the native staging checksums;
- builds the deterministic native archive and signed source archive;
- renders the pinned Homebrew formula; and
- signs a fixed, path-sorted outer asset checksum inventory; and
- creates and separately SSHSIG-signs one canonical trust statement which
  binds the release/source identity, all three public-authority files, the
  exact `allowed_signers` bytes, and the outer asset inventory digest.

The result has this fixed handoff shape:

```text
assets/
  NATIVE-SHA256SUMS.sig
  RELEASE-CANDIDATE.json
  RELEASE-MANIFEST.json
  RELEASE-MANIFEST.sig
  RELEASE-POLICY.json
  RELEASE-POLICY.sig
  SHA256SUMS
  owntransit-VERSION-native.tar.gz
  owntransit-VERSION-source.tar.gz
  owntransit.rb
trust/
  SHA256SUMS.sig
  TRUST-STATEMENT.txt
  TRUST-STATEMENT.txt.sig
  allowed_signers
  distribution-public.key
  policy-public.pem
  release-public.pem
```

`RELEASE-CANDIDATE.json` is copied qualification evidence covered by the outer
checksum signature; it is not a release decision or trust anchor.
`TRUST-STATEMENT.txt` is the compact review handle for the handoff. Its
`owntransit-trust-v1` signature detects substitution after the distribution
identity is trusted, while the statement's exact SHA-256 is the value a
recipient authenticates independently. The statement and signature are
deliberately outside the asset inventory whose digest the statement binds, so
there is no self-referential checksum.

The trust directory is not self-authenticating. For every handoff, the release
operator must send the exact 64-character SHA-256 of `TRUST-STATEMENT.txt`
through a pre-existing authenticated administrator channel which is
independent of the release download, GitHub account and OwnTransit relay—for
example an organization password-manager record established with the operator
before this release, or an in-person hardware-token-authenticated handoff.
The recipient must compare it locally before any extraction or root execution:

```sh
shasum -a 256 /ABSOLUTE/trust/TRUST-STATEMENT.txt
```

Do not accept a digest, key, contact address or verification instruction found
only beside the release assets. After that comparison, `install.sh`
independently verifies the statement signature, requires the exact two v1
`allowed_signers` principals to use `distribution-public.key`, and recomputes
every statement binding. By default this conductor verifies an initial policy
against an empty anchor and therefore requires policy sequence `1`. For a
later policy whose persisted tombstone list is empty, supply the three exact
numeric `--anchor-*` values, the exact `--anchor-policy-key-id`, and
`--anchor-tombstones none` from the independently persisted previous anchor.
The conductor then verifies the signed candidate policy as a strict advance,
requires the same pinned policy key, and rejects sequence replay or weaker
release or lifecycle floors. A nonempty tombstone list requires a future
canonical anchor-file ceremony and is deliberately rejected by this scalar
helper. Anchor claims must come from the separate custody record, not from the
new candidate, download site, or relay. The three counters and empty-tombstone
claim come from the prior policy anchor; the policy-key ID comes from the prior
independently persisted policy public key/package anchor because the scalar
policy-anchor JSON does not contain that key identity. Derive that identity
from the already trusted prior key with `releasectl public-key-id`, never from
the candidate's copy. This helper does not support policy-key rotation.

The `0.1.0` stable handoff is deliberately frozen to release sequence `10`,
policy sequence `6`, minimum release sequence `10`, and minimum lifecycle `1`.
The signing conductor rejects every other candidate tuple and requires the
still-official RC7 policy anchor `3/5/1` before any signature operation. This
floor is mandatory: RC5-RC7 predate the hardened macOS launcher/package
mutation boundary, and the Linux provisioner migration cannot safely hand
control back to their mode-`0750` lifecycle implementation.

An earlier private `0.1.0` candidate from public commit `9fc7d206` was signed
with tuple `8/4/8/1` and then abandoned before tagging, upload or distribution
when its source-archive packaging required correction. Creating a signature
consumes its release and policy sequence even if the handoff remains private;
neither sequence may be reclaimed. The corrected ceremony therefore skips the
consumed policy sequence `4`. A later private `0.1.0` candidate from public
commit `cfbd584f` was signed with tuple `9/5/9/1`, then rejected after Linux
arm64 clean-host qualification exposed a package-supervisor restart deadlock.
It was never tagged or publicly distributed and was used only for private
qualification, but that signature consumed release sequence `9` and policy
sequence `5`. The corrected ceremony therefore uses `10/6/10/1` and verifies
policy sequence `6` as a strict advance from the still-official RC7 anchor
rather than treating either abandoned policy as official persisted trust.
Neither abandoned ledger, signature set nor qualification evidence is an input
to the corrected handoff.

Fresh endpoints can bootstrap the currently trusted policy against their empty
local anchor. An upgraded endpoint independently requires the new policy
sequence to advance, both floors not to weaken, cumulative tombstones not to
disappear, and the pinned policy signer not to change. During a canary, retaining
the previous release floor preserves authenticated rollback only when the two
package layouts are explicitly qualified as rollback-compatible. Raising the
floor to the candidate sequence deliberately burns that rollback. For `0.1.0`,
floor `10` is a fixed safety requirement rather than an optional canary choice.

The independently authenticated OpenSSH key authorized as
`owntransit-release` in `allowed_signers` is the privileged package-bootstrap
authority. Its SSHSIG authenticates the outer asset inventory and the native
checksum inventory containing `packaging/scripts/install.sh`. The release and
policy signatures are separate lifecycle authorities, but they cannot make an
entry point safe after an attacker has already forged the distribution SSHSIG
and caused that entry point to run as root. Compromise of this distribution
key is therefore a software-release compromise, not merely a download-integrity
failure or one share of a threshold-signing construction.

Authenticate the signed outer asset inventory before extracting its native
archive or executing anything from the handoff. Root must then create fresh
staging directories on a local filesystem and copy or extract the bundle,
assets and independently authenticated trust into newly created root-owned
inodes. Do not turn a user-created extraction tree into staging with `chown`:
an earlier writer may retain an open writable descriptor. Do not stage from
FUSE, a network filesystem, a reused writable tree or a path with symlinked or
writable ancestors. The three protected trees remain separate and must not be
group- or world-writable.

With `--engine container`, the script runs the digest-pinned Go toolchain
directly with a read-only source mount, an isolated temporary cache, no added
capabilities and a write-only artifact destination. This avoids depending on
Apple Container versions that mishandle deny-by-default `.dockerignore`
negations. The Docker Buildx lane continues to use the pinned `Containerfile`;
both lanes are subject to the same twice-built byte comparison and evidence
checks.

Run the release helper from the pinned build environment, or build it on the
offline signing host:

```text
go run -mod=readonly ./scripts/release/releasectl evidence ...
go run -mod=readonly ./scripts/release/releasectl manifest ...
go run -mod=readonly ./scripts/release/releasectl sign-manifest \
  --manifest RELEASE-MANIFEST.json \
  --release-private-key /offline/release-signing-key.pem \
  --out RELEASE-MANIFEST.sig
go run -mod=readonly ./scripts/release/releasectl verify-bundle \
  --bundle /absolute/protected/bundle \
  --manifest RELEASE-MANIFEST.json \
  --signature RELEASE-MANIFEST.sig \
  --release-public-key /trusted/release-signing-key.pem
```

`policy`, `sign-policy`, and `verify-policy` form the separate release-policy
path. Verification accepts an independently stored anchor high-water mark,
release/lifecycle floors and cumulative tombstones, rejects replay or any
weakening, and emits the complete next anchor document. Platform lifecycle code
must commit that document to its external rollback anchor before activation.
The helper deliberately has no key-generation command: custody, encrypted or
hardware-backed signing, two-location recovery, and release/policy key-rotation
ceremonies are operator security procedures, not defaults hidden in a script.

The staging tree is not a release merely because it has checksums. Before public
use it needs all fourteen separately named SBOM records, generated third-party
license evidence, the exact Apache-2.0 project LICENSE digest, provenance, an
exact signed software-release manifest, and clean-host qualification. The
implemented free Homebrew/source lane is the macOS v1 distribution direction;
every exact handoff must carry the hardened-activation qualification described
below. Developer ID package output is disabled until OwnTransit also
authenticates the final post-signing bytes and version. A checksum supplied by
the same unauthenticated download is not authentication.

The exact-nine public `0.1.0-rc.*` qualification packages and exact-fourteen
stable line are separate authenticated matrix editions inside the v1 release
envelope. An installed RC lifecycle accepts only its exact-nine edition and
must fail closed on the fourteen-artifact manifest. There is no supported
RC-to-stable in-place upgrade. Ordinary uninstall is deliberately non-purging
and therefore does not prepare that host for stable installation; use a
genuinely fresh host. A destructive RC trust-reset and complete re-enrollment
ceremony is not implemented, and invoking the candidate lifecycle around the
selected installed manager is forbidden.

Every native installer copies the checksummed Apache license and generated full
third-party license evidence into the selected immutable release directory next
to its executable payload. Homebrew installs the Apache license and consolidated
dependency/BIP notices under the formula's `pkgshare`. Ordinary native uninstall
detaches only the role's enumerated public or service integration and preserves
the authenticated release directory, its license notices, selectors and
recovery state. A preserved relay OCI image carries the same obligations under
`/licenses`.

The root installer must run from the exact absolute path inside a protected
package staging tree. The staging directory, every ancestor back to `/`, every
directory below it, and every file must be root-owned and must not be writable
by group or world. Symlinks, non-regular entries, multiply linked files, extra
files, and (on macOS) extended ACLs are rejected. Linux access-ACL write grants
are reflected in the group-class mode mask and are therefore rejected by the
same write-bit check; a default ACL alone cannot grant the directory mutation
permission needed to race the protected tree. Platform packaging must copy the
payload into new inodes created beneath a protected root-owned directory; merely
chowning user-originated files does not revoke an already-open write descriptor.
Do not run the installer with `sudo` directly from a user-owned checkout or
download.

## Linux installation boundary (amd64/x86_64 and arm64/aarch64)

The client and provisioner are on-demand executables. Both use their own
manager-bound signed release/policy transaction, external rollback anchor,
immutable release directory and authenticated `current` selector. Provisioner
package lifecycle installs an authenticated role-local `owntransitctl`, but
creates no runtime reader, service, target state or credential. Its root-owned
mode-`0755` package namespace remains reachable through the ordinary public
selector only on hosts where `fs.protected_hardlinks=1`; the installer checks
that policy before any provisioner package mutation, and the lifecycle binary
checks it again for every provisioner package operation. Only the Linux
installer contains the authenticated, resumable legacy provisioner-directory
migration from mode `0750` to `0755`.

Client installation requires one exact existing non-root `--client-user`, creates a
fresh dedicated `owntransit-client` group containing only that user, and
installs the client `root:owntransit-client` mode `2750`. The setgid executable
gives the client the exact effective primary reader GID required by
runtime-view validation; a new login session is required before the selected
user can execute it. The lifecycle executable is `root:root 0700` and is never
setgid. A filesystem or mount that suppresses setgid execution is a
qualification stop gate, not permission to weaken the exact-GID check.

Connector installation adds a locked service identity and a hardened but
disabled systemd unit. Relay installation imports the exact OCI archive into
local Podman storage, records its immutable image ID, and adds a disabled
loopback-published unit. No service is enabled or started by an installer.

Every installer-time Podman invocation runs locally under a minimal empty
environment with fixed root `HOME` and `PATH`; caller-controlled connection,
storage, XDG, and container configuration variables are not inherited.

Linux install and non-purging uninstall hold the permanent empty root-only
`/var/lib/owntransit/package-supervisor/platform.v1.lock` for their complete
integration mutation window. The opened descriptor and canonical name must
remain the same exact inode. Connector and relay uninstall then holds the
existing service-role supervisor lock through stop, disable, removal and
postcondition checks. An interrupted detach may be rerun: exact remaining
entries are removed and already absent entries stay absent; any foreign residue
fails closed. Neither lock is removed by uninstall.

For client, connector, and relay, installation creates only the protected
root-owned role parent. All four child roots must be absent. Root-only
`owntransitctl bootstrap` then creates this boundary exclusively:

```text
/var/lib/owntransit/<role>/                 root:root              0755
  private/                                  root:root              0700
  authority/                                root:root              0700
  runtime/                                  root:<dedicated-group> 0750
  anchor-view/                              root:<dedicated-group> 0750
```

Only root may run `owntransitctl`. Runtime publication keeps all child
directories `root:<dedicated-group>` mode `0750` and all child files mode
`0640`; the runtime principal can read the selected view but cannot create,
replace, rename, unlink, chmod, or chown it. Bootstrap records the private
state, authority root, publication roots, runtime-visible configuration root,
and exact positive reader GID. Later lifecycle commands derive those values
from authenticated private bootstrap state.

For a native client or connector, `--runtime-config-root` is the same absolute
host path supplied as `--runtime-root`. Relay bootstrap instead records
`--runtime-config-root=/runtime`, because rendered configuration is consumed in
the container namespace. This path is an authenticated local packaging input;
it is never selected by the relay, network, environment, or deployment wire.

Connector and relay units remain stopped throughout every lifecycle mutation.
The connector reads only `runtime/` and `anchor-view/` and receives the numeric
GID through a root-only environment file. The relay receives those two trees
as distinct `ro,nosuid,nodev,noexec` mounts at `/runtime` and `/anchor`; its
private and authority roots never enter the container. Both units use explicit
`--runtime-root`, `--anchor-view-root`, and `--reader-gid` arguments and remain
disabled until enrollment is applied and verified.

## macOS installation boundary

The authenticated Apple-silicon (`arm64`) client and lifecycle binaries are
copied into new root-owned inodes beneath `/Library/OwnTransit`; Intel macOS is
outside the 0.1.0 matrix. Never run a user-writable Homebrew Cellar or source
build directly with `sudo`; privileged lifecycle
execution is allowed only from the authenticated `/Library/OwnTransit` copy. It
has no launchd job, and package code never descends into a home directory.

Lifecycle activation also publishes `/Library/OwnTransit/bin/owntransit-cli`
as a root:wheel mode-`0755`, non-setgid copy of the exact authenticated client
artifact. It exposes setup, version, SSH-stanza generation and courier
administration, but rejects proxy/doctor/runtime-view commands. The protected
ProxyCommand launcher in the selected release is `root:_owntransit` mode
`2751`, while `owntransit-real` is `root:_owntransit` mode `0750`; their
containing release namespace is `root:_owntransit` mode `0750` and is not
traversable by the selected user.

`/Library/OwnTransit/bin/owntransit` is the only macOS ProxyCommand entry point.
It is a distinct single-link `root:_owntransit` mode-`2751` regular inode with
the exact signed release-launcher digest. It is neither a selector symlink nor a
hard link into the protected release tree. The package finalizer creates it in
the fixed `root:wheel` mode-`0700` `/Library/OwnTransit/launcher-stage`
directory, using a fresh root-only inode, ownership-before-setgid ordering,
fsync and atomic rename. A permanent empty single-link `root:wheel` mode-`0600`
`package-mutation.v1.lock` serializes client and provisioner package apply,
rollback, recovery, detach and public-frontend publication; it is the only
steady-state entry in that directory. Only the exact historical client symlink
is accepted as a migration input; unsafe public metadata/types or noncanonical
transaction stages fail closed.

The macOS client uses a different exact-user boundary. Its `_owntransit` reader
group has zero members. A root-owned mode-`2751` fixed launcher authenticates
the selected real UID and live GeneratedUID against a root-owned binding before
it gives only the checksummed `owntransit-real` process the reader EGID. The
ordinary selected user therefore cannot read runtime or anchor bytes directly.
Before exec it also validates the real client as an exact single-link
root:reader mode-`0750` file with the bound digest, and descriptor-relatively
confirms that the root-owned `current` selector still names the bound release.
Before any protected read it requires the raw executable path to be exactly the
fixed public launcher and authenticates that entry by descriptor. An ordinary
user's retained hard-link alias therefore cannot acquire the reader GID;
canonical execution and upgrade remain available while an alias exists.
It enumerates `/dev/fd` rather than trusting the current resource limit, so a
high inherited descriptor cannot survive merely because the limit was lowered.
See `packaging/macos/CLIENT_READER_BOUNDARY.md`. The descriptor-based Darwin ACL
verifier and launcher are implemented; every exact handoff must carry its
clean-Mac setgid and Directory Services qualification result.

After package selection, the installer invokes `package-recover` through the
newly selected authenticated lifecycle executable. Recovery re-authenticates
that running lifecycle even when the transaction journal is already complete,
closing the upgrade window between selector publication and public-entry
finalization.

The macOS provisioner package tree stays protected as `root:wheel` mode `0750`.
Finalization publishes `/Library/OwnTransit/bin/owntransit-provision` as a
distinct `root:wheel` mode-`0755` regular file with the authenticated source
digest but a different inode. Its deterministic root-only stage shares the
same mutation lock. The exact historical provisioner selector symlink is the
only accepted migration input. The macOS installer never changes provisioner
package directories to mode `0755`; the legacy `0750` to `0755` directory
migration belongs only to Linux, where protected-hardlink enforcement is
mandatory.

Ordinary macOS uninstall invokes the authenticated selected lifecycle's
`package-detach` operation under that same lock. For the client it verifies and
opens the exact public launcher, removes setgid from that inode so every
retained hard-link alias is deactivated, syncs it, and durably detaches the
canonical launcher and non-setgid frontend. A retry accepts the authenticated
mode-`0751` interruption residue and already-absent exact names. Provisioner
detach similarly removes only its authenticated public copy. Package releases,
selectors, receipts, floors, identities, credentials and recovery state remain
installed.

The provisioner is a separate offline-host role and is never included in a
client, connector or relay runtime package. Its macOS package transaction lives
under `roles/provisioner`, separately from both the client selector and all
operator-selected provisioner data. A payload-only `.pkg` cannot perform that
manager-held transaction and is therefore disabled; use the authenticated
native installer entry point.

## Per-handoff qualification and assurance

`sign-qualification-record.sh` creates the post-test record; it does not run a
test or turn an absent result into a pass. Prepare one canonical results file
with these exact sorted lines:

```text
connector-client-ssh-boundary|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
hostile-relay-resource-exhaustion|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
linux-amd64-clean-host-lifecycle|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
linux-amd64-relay-exchange|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
linux-arm64-clean-host-lifecycle|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
linux-arm64-relay-exchange|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
macos-arm64-clean-host-lifecycle|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
public-history-clean-export|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
public-tree-source-gates|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
release-signatures|PASS|64_LOWERCASE_HEX_EVIDENCE_SHA256
```

Each status is exactly `PASS`, `FAIL`, or `NOT-PERFORMED`. `PASS` and `FAIL`
require the SHA-256 of the exact retained evidence; `NOT-PERFORMED` requires
`-`. Review those evidence objects, compare the explicit release ID and source
commit to the authenticated candidate, then run the signer offline:

```sh
scripts/release/sign-qualification-record.sh \
  --release-id RELEASE_ID \
  --source-commit SOURCE_COMMIT \
  --outer-checksums /ABSOLUTE/assets/SHA256SUMS \
  --outer-signature /ABSOLUTE/trust/SHA256SUMS.sig \
  --allowed-signers /ABSOLUTE/trust/allowed_signers \
  --distribution-key /ABSOLUTE/private/distribution \
  --results /ABSOLUTE/private/qualification-results \
  --unresolved-critical 0 \
  --unresolved-high 0 \
  --output /ABSOLUTE/qualification
```

The output is exactly `QUALIFICATION.txt` and `QUALIFICATION.txt.sig`, signed
in namespace `owntransit-qualification-v1`. It remains a sibling of `assets/`,
never a member of the outer inventory whose digest it binds. The script derives
`status=PASS` only when every fixed v1 test is `PASS` and both unresolved counts
are zero; every other honest input produces a signed `BLOCKED` record. It emits
the record SHA-256 as its stable review handle. Before stable promotion, obtain
that handle through the same pre-existing independent administrator channel,
verify the SSHSIG against authenticated `allowed_signers`, and independently
confirm every referenced evidence digest. The signature authenticates what the
release operator recorded; it cannot prove that a test was performed honestly.

- Each exact Linux architecture handoff must independently qualify setgid
  client execution, exact primary-GID selection, directory/file modes,
  lifecycle/runtime lock exclusion, required `fs.protected_hardlinks=1`
  enforcement for the traversable provisioner namespace, and service inability
  to mutate the views on a clean host.
  `nosuid` or policy suppression of setgid execution is a stop for that host.
- Each exact macOS handoff must qualify the zero-member setgid launcher, exact
  GeneratedUID binding, descriptor-based ACL verifier, equal signed launcher
  digests on distinct protected/public inodes, the role-appropriate distinct
  public-copy boundaries, the exact persistent root-only global mutation lock with no
  transaction-stage residue, canonical invocation and
  retained-hard-link-alias denial, direct protected-launcher/runtime/anchor
  denial, exact current-selector validation, high inherited-descriptor closure,
  group-drift rejection,
  debugger/task-port isolation, interruption-safe authenticated detach, and
  reboot behavior on a clean Apple-silicon Mac.
- The two local builds are a deterministic same-builder regression check, not
  independent reproducible-build attestation. Record an independent clean
  builder result when available, or disclose that it was not performed; it is
  additional assurance rather than a substitute for the exact signed build.
- macOS Developer ID `.pkg` output remains disabled, and the payload-only
  provisioner `.pkg` lane is fail-closed at the manager boundary. Free
  Homebrew/source distribution instead relies on the independently verified
  OwnTransit release manifest and provenance.
- Relay Podman confinement and read-only mounts need host-specific SELinux or
  AppArmor qualification. The installer never disables or rewrites host policy.
- Runtime invocations must pass absolute `--runtime-root` and
  `--anchor-view-root` paths plus the installed numeric `--reader-gid`. The
  installer prints these paths but never edits operator SSH configuration.
