# macOS exact-user reader boundary

The hardened client never makes the selected local user a member of the
`_owntransit` reader group. That group has no named, UUID, nested, or primary
members. Consequently an ordinary process under the selected UID cannot read
the `root:_owntransit` mode `0640` runtime, rollback-anchor, or launcher-binding
bytes.

The authenticated installer places two different binaries in the immutable
release directory:

- `owntransit` is the authenticated release copy of the deliberately small
  fixed launcher, `root:_owntransit` mode `2751`. The containing release
  directory is `root:_owntransit` mode `0750`, so the selected user cannot
  traverse to or execute this protected copy directly.
- `owntransit-real` is the network client, `root:_owntransit` mode `0750`, with
  no setid bit. An ordinary user cannot read or execute it directly; only the
  authenticated launcher transition supplies the reader EGID.
- `owntransitctl` remains `root:wheel` mode `0700`. No Homebrew Cellar,
  source-tree, or user-writable binary is ever setgid or run as root.

The public ProxyCommand entry point is a separate single-link regular inode at
`/Library/OwnTransit/bin/owntransit`, also `root:_owntransit` mode `2751`.
It has exactly the signed release launcher's SHA-256 but is neither a symlink
nor a hard link to the protected copy. `/Library/OwnTransit/bin` remains
`root:wheel` mode `0755`, so an ordinary user can execute—but cannot read or
replace—the public launcher without gaining traversal into the release tree.

The launcher accepts no ordinary arguments. It authenticates the caller against
the protected `/Library/OwnTransit/launcher-auth/client.v1` binding: exact
non-root real UID, live Directory Services GeneratedUID, reader GID, compiled
release ID, and SHA-256 of `owntransit-real` must all match. UID reuse therefore
fails closed. It rejects a changed effective UID, a missing setgid transition,
or reader authority already present in the caller's primary/supplementary group
vector. It then hashes and metadata-checks the fixed root-owned real client,
requires that the descriptor-relative root-owned `current` selector still
identifies the binding's exact release, enumerates `/dev/fd` to mark every
inherited descriptor above stderr close-on-exec even after a lowered resource
limit, selects `/` as its working directory, replaces the environment with
fixed locale/path values, and execs only:

```text
/Library/OwnTransit/roles/client/releases/RELEASE_ID/owntransit-real proxy
```

The privileged client resolves the fixed Darwin runtime and anchor-view paths
from its authenticated EGID; the launcher never forwards caller- or
script-selected paths. The public launcher authorizes one release from its
protected binding and confirms that the authenticated manager selector still
names `releases/RELEASE_ID` immediately before the final process transition.
The protected lifecycle executable has no public symlink and remains under the
same signed current selector.

The package finalizer publishes the public launcher through the fixed
`/Library/OwnTransit/launcher-stage` directory, which is `root:wheel` mode
`0700`. A permanent single-link, empty `root:wheel` mode-`0600`
`package-mutation.v1.lock` holds a nonblocking exclusive advisory lock across
client and provisioner apply, rollback, recovery, detach and public-frontend
publication. After completion it is the only entry in that directory; the
deterministic launcher, client-frontend and provisioner-frontend transaction
stages must be absent. Publication creates a fresh root-only mode-`0600` inode,
writes and syncs the signed launcher bytes, changes ownership before applying
mode `2751` (because macOS clears setgid on ownership change), verifies the
final metadata, ACL and digest, and atomically renames the inode into the public
directory. A noncanonical staging entry, unsafe existing public type or
metadata, final digest mismatch or ACL fails closed. Upgrade accepts only the
exact historical selector symlink as a one-time symlink migration input;
steady state is always the distinct regular inode.

Before any protected read, the launcher requires Darwin's raw executable path
to be exactly `/Library/OwnTransit/bin/owntransit` and descriptor-authenticates
that canonical root-owned public entry. macOS permits an ordinary user to make
a hard link to some execute-only root-owned files. Such an alias is therefore
not treated as an identity: canonical invocation remains usable while the
alias fails before it can acquire the reader GID. Upgrade tolerates and replaces
a multiply linked old public entry; uninstall removes setgid from all links to
that inode before detaching the canonical name. Protected release and freshly
staged inodes remain single-link requirements.

The installer requires `--client-user` naming one existing canonical non-root
local account. It creates `_owntransit` only when that name is absent locally
and through the search policy. Its GID comes from `5000..59999` only after both
views prove that no group owns it and no user uses it as a primary GID. The
group must remain completely empty and unnested. The target user must resolve
identically through the local node, search policy, numeric UID, canonical name,
and GeneratedUID.

The durable identity receipt survives ordinary uninstall:

```text
/Library/OwnTransit/identity/client-reader.v1
```

Its directory is `root:wheel` mode `0700`; the single-link receipt is
`root:wheel` mode `0600`; neither may have an extended ACL. It binds the
canonical username, numeric UID, user GeneratedUID, group name, numeric GID,
and group GeneratedUID. Reinstall adopts the preserved empty group only when
the receipt and every live local/search-policy fact still match exactly.
Missing halves, reuse, collision, ambiguity, ACLs, membership, nesting, or UUID
changes fail closed. Ordinary uninstall invokes the selected authenticated
lifecycle binary's `package-detach` operation under the package-mutation lock.
It authenticates the current runtime, changes the opened public launcher from
mode `2751` to `0751` to deactivate every retained hard-link alias, syncs it,
then durably unlinks the canonical launcher and public non-setgid frontend.
A retry accepts only that authenticated mode-`0751` interruption state or an
already-absent exact name. It preserves the manager selector, releases,
installed notices, rollback anchor, release-specific launcher binding, group,
and identity receipt. Destructive identity or package-state purge is
deliberately not implemented.

After a client package selects a release, installation invokes
`package-recover` through that newly selected authenticated lifecycle binary.
This completes an interrupted finalizer or revalidates the running lifecycle
even when the journal already says complete, so migration cannot leave a new
selector paired with the old public-launcher boundary.

A failed Directory Services or signed package mutation is not hidden or guessed
away. Exact reinstall/recovery adopts only authenticated manager state and the
same protected reader identity; unexplained partial state fails closed.

This boundary limits the authenticated on-demand client to read-only access to
published views. It does not defend against root, an administrator granting
root, kernel compromise, denial of service, or malicious root-level replacement
followed by deliberate metadata and receipt repair.

## Qualification invariant

Every official 0.1.0 handoff must exercise this boundary after lifecycle
activation on a clean Apple-silicon Mac and attach the exact result to its
qualification record:

```text
sudo scripts/qualify/macos-client-boundary.sh \
  --client-user operator \
  --release-id 52_CHARACTER_CANONICAL_RELEASE_ID \
  --reader-gid NUMERIC_GID_FROM_INSTALLER
```

The gate verifies zero membership/nesting, identity receipt and live
GeneratedUID agreement, exact file modes and ACL absence, denial of direct
runtime/anchor reads by an ordinary target process, equal signed digests but
distinct inodes for the protected and public launchers, the exact persistent
root-only mutation lock with no transaction-stage residue, denial of direct
protected-launcher traversal, successful canonical execution while an ordinary
user retains a hard link, rejection of that alias before reader authority,
exact public-launcher EGID for the bound user, wrong-UID denial, rejection of
caller-selected arguments, and the root-owned release directory that prevents
client replacement. It performs no successful identity or installation
mutation.

The direct `.pkg` lane cannot securely select and revalidate the target local
identity, so `package-pkg.sh` fails closed for the client role. It also fails
closed for the provisioner because a payload-only package cannot perform the
manager-bound signed release/policy transaction. The authenticated native
installer keeps the two role selectors separate. Homebrew is a signed
source/build delivery lane only.
