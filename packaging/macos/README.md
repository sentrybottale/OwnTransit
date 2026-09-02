# macOS release lanes

OwnTransit has two deliberately separate macOS distribution lanes.

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
into new root:wheel inodes beneath `/Library/OwnTransit`;
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

Apple's paid program is therefore not a v1 dependency. The supported direction
remains the no-fee source/Homebrew lane plus a separately authenticated,
qualified privileged handoff.

The supported source lane authenticates bytes before building. The disabled
package tooling and the unsigned qualification aid do not create OwnTransit
state, edit SSH configuration, install a client daemon, contact a relay, or
handle operator SSH material.

## Hardened activation qualification

The CGO-free Darwin descriptor path now rejects every extended ACL and fails
closed when the filesystem or syscall ABI cannot prove that result. The client
installer also uses a zero-member reader group plus a fixed, authenticated
setgid launcher; it never gives the selected user's ordinary processes reader
membership. See `CLIENT_READER_BOUNDARY.md` for the exact UID/GeneratedUID and
immutable-client binding.

Every official 0.1.0 handoff must exercise the ACL trampoline and setgid
launcher after lifecycle activation on a clean Apple-silicon Mac and carry the
result in its exact qualification record. That evidence must prove
ordinary-process denial for actual runtime and anchor bytes, correct setgid
propagation, wrong-UID rejection, Directory Services group/GeneratedUID drift
rejection, debugger/task-port and core-dump isolation, and restart survival.
Unsupported filesystems or execution policies remain fail-closed stops, not
reasons to weaken ownership, ACL, or identity checks.

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
