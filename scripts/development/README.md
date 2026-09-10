# OwnTransit distribution

0.7.0 ships three public roles: Client, Relay and Target. Commands are
`owntransit-client`, `owntransit-relay` and `owntransit-target`; run the local
role's `setup` command for its menu. The SSH server runs on the Target.
Public commands have no `pair` prefix or preview aliases.

The supported matrix remains Linux amd64, Linux arm64 and the Apple-silicon
macOS client. The nine public assets are:

- `install-linux.sh`
- `install-macos.sh`
- `owntransit-0.7.0-linux-amd64.tar.gz`
- `owntransit-0.7.0-linux-arm64.tar.gz`
- `owntransit-0.7.0-darwin-arm64.tar.gz`
- `DEVELOPMENT.txt`
- `DEVELOPMENT-SHA256SUMS`
- `DEVELOPMENT-SHA256SUMS.sig`
- `distribution-public.key`

The existing distribution key, principal `owntransit-development`, SSHSIG
namespace `owntransit-development-v1` and capsule schema remain unchanged.
These signatures do not grant authority in the historical 0.1.0 manifest or
release-policy namespaces. No additional signer, key generation or rotation is
part of this lane. Signing keys never enter CI, capsules, relay state or Git.

The initial installer download trusts GitHub HTTPS. Each bootstrap then checks
the pinned public-key digest, detached signature, exact versioned six-member
inventory and selected archive digest before extraction or execution. The
bundle installer checks the exact flat member set and platform again.

Linux installs software at `/opt/owntransit/0.7.0/{client,relay,target}`.
macOS retains the per-user `Library/Application Support/OwnTransitSoftware`
directory and installs `~/.local/bin/owntransit-client` without sudo.
The target uses `owntransit-target.service` and named units
`owntransit-target@NAME.service`. The fixed destination remains
`tcp4 127.0.0.1:22` after end-to-end authorization.

Software installation and removal preserve all endpoint identities, pending
pairings, terminal alarms and operator-owned SSH settings. Only explicitly
owned earlier aliases and exact recognized service units can be retired.
Unrelated commands, services and previous release directories are retained.
Default and named pairing directories keep their existing locations.
An explicit pairing replacement is a separate target setup operation.

Build and verify one immutable release:

1. Complete both race/vet profiles, security/publication checks and the bounded
   installer, service and end-to-end fixtures for the current source.
2. Freeze the source commit and run
   `sh scripts/development/build.sh ABSOLUTE_GO1267 ABSOLUTE_NEW_OUTPUT`.
   Build intermediates remain under that output for inspection.
3. Inspect the exact native and OCI inventories. Sign the inventory using
   `sh scripts/development/sign.sh PRIVATE_KEY PUBLIC_KEY DEVELOPMENT-SHA256SUMS`.
   All paths must be absolute and the private key stays outside staging.
4. Independently verify signatures and all referenced bytes, then execute the
   matching native artifacts and bounded final carrier/SSH check.
5. With publication explicitly authorized, create the immutable version tag and
   draft release, upload the exact nine assets, and download and verify them
   before publication. Published tags and assets are never overwritten.

The normal release lane uses the bounded shipping contract in
`OWNTRANSIT_SHIPPING_PLAN.md`. It does not claim an extended soak, pristine-host
qualification, independent security assessment or unperformed platform test.
The historical 0.1.0 source/bootstrap lane remains under `scripts/release/`.

`test-install-linux.sh` runs only in its instrumented disposable Linux
container. It covers inventory tampering, exact reinstall, managed service
renaming, unrelated command preservation, locks and non-purging removal.
`TestMacInstallerIsolatedLifecycle` uses a caller-supplied private fixture root,
a disposable signing key and a fake home path; it never changes the real HOME.
