# macOS exact-user reader boundary

The hardened client never makes the selected local user a member of the
`_owntransit` reader group. That group has no named, UUID, nested, or primary
members. Consequently an ordinary process under the selected UID cannot read
the `root:_owntransit` mode `0640` runtime, rollback-anchor, or launcher-binding
bytes.

The authenticated installer places two different binaries in the immutable
release directory:

- `owntransit` is a deliberately small fixed launcher, `root:_owntransit` mode
  `2751`. Other users can enter it through the execute bit but cannot read or
  change it.
- `owntransit-real` is the network client, `root:_owntransit` mode `0750`, with
  no setid bit. An ordinary user cannot read or execute it directly; only the
  authenticated launcher transition supplies the reader EGID.
- `owntransitctl` remains `root:wheel` mode `0700`. No Homebrew Cellar,
  source-tree, or user-writable binary is ever setgid or run as root.

The launcher accepts no ordinary arguments. It authenticates the caller against
the protected `/Library/OwnTransit/launcher-auth/client.v1` binding: exact
non-root real UID, live Directory Services GeneratedUID, reader GID, compiled
release ID, and SHA-256 of `owntransit-real` must all match. UID reuse therefore
fails closed. It rejects a changed effective UID, a missing setgid transition,
or reader authority already present in the caller's primary/supplementary group
vector. It then hashes and metadata-checks the fixed root-owned real client,
closes every inherited file descriptor above stderr, selects `/` as its working
directory, replaces the environment with fixed locale/path values, and execs
only:

```text
/Library/OwnTransit/roles/client/releases/RELEASE_ID/owntransit-real proxy
```

The privileged client resolves the fixed Darwin runtime and anchor-view paths
from its authenticated EGID; the launcher never forwards caller- or
script-selected paths. `/Library/OwnTransit/bin/owntransit` selects only
`../roles/client/current/owntransit`. The protected lifecycle executable has
no public symlink and remains under the same signed current selector.

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
changes fail closed. Ordinary uninstall detaches only the fixed public launcher
and preserves the manager selector, releases, installed notices, rollback
anchor, release-specific launcher binding, group, and identity receipt.
Destructive identity or package-state purge is deliberately not implemented.

A failed Directory Services or signed package mutation is not hidden or guessed
away. Exact reinstall/recovery adopts only authenticated manager state and the
same protected reader identity; unexplained partial state fails closed.

This boundary limits the authenticated on-demand client to read-only access to
published views. It does not defend against root, an administrator granting
root, kernel compromise, denial of service, or malicious root-level replacement
followed by deliberate metadata and receipt repair.

## Qualification gate

This remains a macOS ship gate until exercised after lifecycle activation on a
clean disposable Apple-silicon Mac:

```text
sudo scripts/qualify/macos-client-boundary.sh \
  --client-user operator \
  --release-id 52_CHARACTER_CANONICAL_RELEASE_ID \
  --reader-gid NUMERIC_GID_FROM_INSTALLER
```

The gate verifies zero membership/nesting, identity receipt and live
GeneratedUID agreement, exact file modes and ACL absence, denial of direct
runtime/anchor reads by an ordinary target process, exact launcher EGID for the
bound user, wrong-UID denial, rejection of caller-selected arguments, and the
root-owned release directory that prevents client replacement. It performs no
successful identity or installation mutation.

The direct `.pkg` lane cannot securely select and revalidate the target local
identity, so `package-pkg.sh` fails closed for the client role. Provisioner
packages remain separate. Homebrew is a signed source/build delivery lane only.
