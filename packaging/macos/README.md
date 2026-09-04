# macOS arm64 release lanes

OwnTransit has two deliberately separate Apple-silicon (`arm64`) macOS
distribution lanes. Intel macOS is outside the 0.1.0 support matrix.

## No-fee source/Homebrew lane

The source lane does not require an Apple Developer Program membership. A
release source archive contains `SOURCE-MANIFEST.txt` plus an OpenSSH detached
signature. The manifest covers the complete Go build input set. The Homebrew
formula pins the archive SHA-256, pins the source-signing Ed25519 public key,
verifies the detached signature, verifies every manifest entry, rejects
unlisted build inputs, requires exact `go1.26.7` from Homebrew's keg-only
`go@1.26` formula, and builds only the unprivileged client from source. The
formula deliberately does not build or install `owntransitctl`.

Create the signed source archive with `packaging/homebrew/build-source-archive.sh`
and render a tap formula with `packaging/homebrew/render-formula.sh`. The
release-signing SSH key is free and independent of Apple. Keep it offline and
publish its public half through an authenticated channel.

Both free-lane signing helpers require the named key to be an absolute,
canonical, current-effective-UID-owned regular file with exactly one hard link,
mode `0400` or `0600`, and an actual Ed25519 private key. On Darwin, the key and
every ancestor back to `/` must have no extended ACL; every ancestor directory
must be owned by root or the current effective UID and must not be group- or
world-writable. The key must also be outside the source/checksum staging tree
and outside the output parent. This intentionally rejects ordinary locations
whose inherited macOS ACL cannot be proved absent.

The helpers clear SSH agent, graphical askpass, and display environment before
calling `ssh-keygen`, so a public key backed only by an ambient agent cannot be
substituted for the named private-key file. A passphrase-protected key is
supported only with an attached controlling terminal and may prompt once for
private-key validation and again for signing. A headless invocation of an
encrypted key fails closed; automation must not put the passphrase in argv or
environment variables.

For the canonical `sentrybottale/homebrew-owntransit` tap, installation is:

```text
brew tap sentrybottale/owntransit https://github.com/sentrybottale/homebrew-owntransit
brew install sentrybottale/owntransit/owntransit
```

The owner, source repository and release URL remain explicit renderer inputs;
the release invocation supplies `sentrybottale` and `owntransit`. The template
never invents a GitHub identity. The current project license input is
`Apache-2.0`.

This lane is authenticated, but the locally built binaries are not Apple
notarized. Homebrew/source installation is therefore the honest free lane, not
a substitute claim that Apple notarized the software.

Authentication of the free build does not activate a client or authorize a
user-writable Cellar or source-tree executable to run with privilege. The
separate signed system handoff copies independently authenticated artifacts
into fresh root-owned, role-specific inodes beneath `/Library/OwnTransit`;
`scripts/release/install-macos.sh` installs the protected lifecycle executable
at `/Library/OwnTransit/roles/client/current/owntransitctl` mode `0700`. Guided
setup may invoke only that fixed system copy through its reviewed privileged
dispatch. Never run the Homebrew client or a source-tree build with `sudo`.

## Developer ID package lane

Developer ID output is currently disabled. Codesigning, product signing and
stapling change the final package after the source artifacts were authenticated,
so Apple validation alone would make Apple and the packaging machine a trust
root for the installed bytes. Re-enabling this optional lane requires an
OwnTransit signature over the final package digest and authenticated
`BUILD-INPUTS` version, plus a recipient-side verifier. The retained unsigned
packaging machinery is non-release scaffolding; client generation fails at the
reader-identity boundary and provisioner generation fails because a
payload-only package cannot enter the manager-bound signed release/policy
transaction.

Apple's paid program is therefore not a v1 dependency. The implemented direction
remains the no-fee source/Homebrew lane plus a separately authenticated
privileged handoff. The bounded 0.1.0 record qualifies the client transport,
not that package lifecycle.

The supported source lane authenticates bytes before building. The disabled
package tooling and the unsigned qualification aid do not create OwnTransit
state, edit SSH configuration, install a client daemon, contact a relay, or
handle operator SSH material.

## Hardened activation qualification

The CGO-free Darwin descriptor path now rejects every extended ACL and fails
closed when the filesystem or syscall ABI cannot prove that result. The client
installer also uses a zero-member reader group plus a fixed, authenticated
setgid launcher; it never gives the selected user's ordinary processes reader
membership. The signed release launcher remains inside a
`root:_owntransit` mode-`0750` release directory. The public ProxyCommand path
is a distinct single-link `root:_owntransit` mode-`2751` regular inode with the
same authenticated digest—not the historical selector symlink and not a hard
link into the protected tree. Publication uses a fixed `root:wheel` mode-`0700`
private staging directory, ownership-before-setgid ordering, fsync and atomic
rename. A permanent empty `root:wheel` mode-`0600`
`package-mutation.v1.lock` serializes client and provisioner package selection,
rollback, recovery, detach and public-frontend publication; it is the only
permitted steady-state staging entry. Before protected reads the launcher
authenticates its exact raw public invocation path, so a hard-link alias
retained by an ordinary user cannot gain the reader GID. See
`CLIENT_READER_BOUNDARY.md` for the exact UID/GeneratedUID, current-selector
and immutable-client binding.

After package selection the installer runs `package-recover` through the newly
selected authenticated lifecycle copy. Recovery authenticates the running
lifecycle even for an already-complete journal, so an interrupted finalizer or
upgrade from an exact historical symlink cannot silently leave a mixed
selector/public-entry state.

The macOS provisioner package tree remains non-user-traversable:
`root:wheel` mode `0750`. Finalization copies its authenticated executable to
the distinct public `/Library/OwnTransit/bin/owntransit-provision` inode as
`root:wheel` mode `0755`; the public and protected files must have the same
digest and different inode identities. The copy uses its own deterministic
root-only stage beneath the same mutation lock. Only the exact historical
provisioner selector symlink is accepted as a migration input. macOS performs
no provisioner-directory chmod migration.

Ordinary macOS uninstall asks the selected authenticated lifecycle binary to
run `package-detach` while holding that same lock. Client detach first removes
setgid from the authenticated launcher inode, which deactivates retained hard
links, then durably unlinks the canonical launcher and public client frontend.
It resumes safely from the authenticated mode-`0751` launcher residue or from
already-absent names. Provisioner detach similarly removes only its exact
public copy. Both roles preserve protected releases, selectors, rollback
floors, identities, credentials and recovery state.

The 0.1.0 hard artifact smoke authenticates and inspects the Darwin launcher and
records its expected fail-closed rejection when invoked outside the fixed
installed path. It is strictly read-only and performs no macOS system mutation
because retained RC7 client state is intentionally not a stable predecessor. It
therefore makes no candidate macOS client-install,
launcher-activation, ACL-trampoline or setgid-runtime claim. The clean
Apple-silicon matrix below is additional assurance. When it is run, its evidence
should prove
ordinary-process denial for actual runtime and anchor bytes, correct setgid
propagation through the distinct public inode, equal launcher digests and
different inode identities, denial of direct traversal to the protected
release launcher, the exact persistent root-only mutation lock with no staging
residue, canonical-path execution and retained-hard-link rejection, wrong-UID
rejection, Directory Services group/GeneratedUID drift rejection,
debugger/task-port and core-dump isolation, authenticated current-selector validation, inherited
descriptor closure and restart survival. Unsupported filesystems or execution
policies remain fail-closed stops, not reasons to weaken ownership, ACL, or
identity checks.

The native staging `SHA256SUMS` signature uses the separate
`owntransit-release-v1` SSHSIG namespace. Keep its detached signature outside
the staging tree; the installer intentionally rejects extra files. The helper
does this safely and verifies the result before publishing it:

```text
packaging/macos/sign-checksums.sh \
  --subject /protected/staging/SHA256SUMS \
  --signing-key /offline/release-signing-key \
  --allowed-signers /authenticated/allowed_signers \
  --signer owntransit-release \
  --output /separate/release-evidence/SHA256SUMS.sig
```
