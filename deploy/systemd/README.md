# OwnTransit systemd units

These units are package payloads, not bootstrap scripts. An authenticated local
installer places them under `/etc/systemd/system`, but deliberately does not
enable or start them.

`owntransit-connector.service` runs as the dedicated, locked
`owntransit-connector` account. That account owns no workspace, state, key, or
anchor. Root performs lifecycle operations under the private role layout:

```text
/var/lib/owntransit/connector/              root:root                  0755
  private/                                  root:root                  0700
  authority/                                root:root                  0700
  runtime/                                  root:owntransit-connector  0750
  anchor-view/                              root:owntransit-connector  0750
```

Every published child directory is `0750` and every published file is `0640`
with the same root and dedicated-group ownership. The service receives only
the two read-only views. Both its offline check and runtime invocation pass
explicit `--runtime-root`, `--anchor-view-root`, and the exact positive numeric
`--reader-gid` recorded in the root-only
`/etc/owntransit/connector-runtime.env`. The runtime verifies that this value
matches its effective primary GID. The unit also makes `private/` and
`authority/` inaccessible inside its mount namespace and has no writable
filesystem, capabilities, listener, home directory, or SSH authority.

`owntransit-relay.service` runs a locally imported, digest-verified OCI artifact
with Podman. The process inside the container uses the locked relay account's
numeric UID and the dedicated relay reader group's numeric GID as its primary
GID, a read-only root filesystem, and no capabilities. Host `runtime/` is
mounted at `/runtime` and
`anchor-view/` at `/anchor`, each `ro,nosuid,nodev,noexec`. Relay `private/` and
`authority/` are never mounted. The unit supplies all three runtime-view
arguments explicitly instead of relying on the image default. Only container
port 9087 is published, and only on host IPv4 loopback. The signed relay
deployment must therefore use the isolated container listen address
`0.0.0.0:9087`; the host reverse proxy still reaches only
`127.0.0.1:9087`.

The relay package also installs
`owntransit-relay-exchange@.service` for the temporary, credential-free first
route exchange. The native archive authenticates it under the portable member
name `packaging/systemd/owntransit-relay-exchange-template.service`; the Linux
installer maps that exact signed payload to the template name. The unit has no
`[Install]` section, conflicts with the enrolled relay unit, mounts no role
state or authority material, and accepts only one canonical allocation digest
as its systemd instance. It is never enabled or started by the installer.

Podman port publication translates the host reverse-proxy connection before it
reaches the container. Consequently, the packaged relay's exchange handler
accepts cleartext only from loopback or a canonical RFC1918/ULA bridge source;
the ordinary non-container handler remains TLS-or-loopback only. Public,
link-local, unspecified and malformed source addresses remain rejected. This
private-source exception is container admission plumbing, not enrollment or
human-identity authority. It is safe only together with the exact official
`--network=bridge --publish=127.0.0.1:9087:9087/tcp` boundary, and must never
justify publishing the container port on a non-loopback host address. Both the
temporary exchange and enrolled relay units select that bridge explicitly;
host networking and implicit operator-selected networks are not supported.

The container has a fixed 256 MiB hard memory ceiling and a build-packaged
192 MiB Go soft memory limit. The soft limit leaves explicit headroom for
non-Go mappings and container accounting; it is not operator-selected relay
configuration. The exchange parser borrows its bounded WebSocket input only
during synchronous capability checking, so an unauthenticated maximum response
does not create a second 4 MiB parser copy before the mailbox rejects it.

Relay bootstrap uses the host publication path for `--runtime-root` but records
`--runtime-config-root=/runtime`; connector bootstrap uses
`/var/lib/owntransit/connector/runtime` for both values. These fixed local
namespace bindings keep rendered file paths valid without making them a wire-
or environment-selected runtime target.

The installer creates only the protected root-owned role parent and requires
all four children to be absent. Root-only bootstrap creates the four roots
exclusively with the ownership above, preventing reuse of attacker-prepopulated
paths. The installer never imports trust, generates keys, edits OpenSSH,
changes a reverse proxy, or starts a service. Bootstrap and every later
lifecycle mutation are explicit root-only `owntransitctl` operations with
independently verified CA certificates and deployment-signer public key. Stop
the unit before bootstrap, apply, policy apply, rollback, recovery,
cancellation, or any future mutation; the cross-principal activation lock fails
closed if a runtime still holds the view. Restart only after both
`owntransitctl status` and `owntransitctl verify`, plus the role's offline
`check-config`, all succeed. Never run lifecycle commands as the service
account.

The relay unit assumes `/usr/bin/podman` and a host whose confinement policy
permits a read-only bind mount without relabeling it. SELinux/AppArmor policy,
reverse-proxy integration and resource sizing require separate platform
qualification; the package must not weaken host policy automatically.
