# Platform qualification harnesses

`test-native-archive.sh` exercises the deterministic native handoff before any
privileged host qualification. It checks repeated byte equality, normalized
gzip/tar metadata and exact content/modes, then proves that extra files,
symlinks, hard links, checksum tampering, an output inside the bundle and a
noncanonical archive name all fail without publishing output. It is a tooling
test, not clean-host lifecycle evidence.

## Linux amd64 clean-host and reboot gate

`linux-amd64-vm.sh` is intended only for a fresh, disposable, reboot-capable
amd64 VM with systemd as PID 1. It refuses containers, non-amd64 systems,
non-root execution, an existing OwnTransit installation, reused service
accounts, an occupied qualification port, and hosts without this protected
marker:

```text
/etc/owntransit-qualification-disposable
OWNTRANSIT_DISPOSABLE_VM=1
```

Create that marker only after verifying the VM is disposable:

```text
install -o root -g root -m 0644 /dev/null /etc/owntransit-qualification-disposable
printf 'OWNTRANSIT_DISPOSABLE_VM=1\n' >/etc/owntransit-qualification-disposable
```

Copy the exact release staging tree under a new root-owned, non-writable path
such as `/opt/owntransit-release`. Keep the handoff's
`assets/NATIVE-SHA256SUMS.sig`, release-manifest signature, signed policy and
policy signature under a separate protected assets root. Keep the independently
trusted allowed-signers and release/policy public keys under a protected trust
root; none may come from the candidate staging tree. First run the read-only
gate:

```text
scripts/qualify/linux-amd64-vm.sh preflight \
  --bundle /opt/owntransit-release \
  --checksums-sha256 AUTHENTICATED_64_HEX \
  --checksums-signature /opt/release-assets/NATIVE-SHA256SUMS.sig \
  --allowed-signers /opt/release-trust/allowed_signers \
  --signer owntransit-release \
  --manifest-signature /opt/release-assets/RELEASE-MANIFEST.sig \
  --release-public-key /opt/release-trust/release-public.pem \
  --policy /opt/release-assets/RELEASE-POLICY.json \
  --policy-signature /opt/release-assets/RELEASE-POLICY.sig \
  --policy-public-key /opt/release-trust/policy-public.pem
```

Repeat with `prepare` and the same arguments. It authenticates the staging
checksum record, signed manifest, distinct-signer monotonic policy and fixed
per-role package transaction, then generates one throwaway route authority and three local
enrollment requests, applies only the connector response, destroys the
throwaway issuer/client/relay material, validates the root-owned runtime-view
boundary and systemd hardening, and starts the connector. It first proves that
the installer left `private`, `authority`, `runtime`, and `anchor-view` absent,
then runs bootstrap as root while the service is stopped. After activation it
requires `private` and `authority` to be `root:root 0700`, both view roots and
their directories to be `root:<dedicated-group> 0750`, and every view file to
be a root-owned, single-link `0640` regular file. It also runs probes as the
connector identity to prove the service owns nothing, cannot read either
private root, cannot create, replace, rename, unlink, chmod, or chown view
material, and can read the published runtime and anchor views. The generated connector is configured to
retry only `wss://127.0.0.1:65535/connects`, so qualification performs no relay
or Internet connection and requires no live credential.

The harness enables the connector but deliberately never invokes `reboot`.
Reboot through the VM console, then run:

```text
scripts/qualify/linux-amd64-vm.sh verify-after-reboot
```

The resume phase requires a changed kernel boot ID. It revalidates artifact and
unit digests, service identity, systemd confinement, enabled/active state,
current-boot activation, zero unexpected restarts, and that the connector owns
no TCP listener. JSON evidence is written beneath
`/var/lib/owntransit-qualification/` and also emitted on stdout. Hostnames,
machine IDs, generated identities, certificate material and logs are excluded.

This qualifies native installer/systemd/reboot mechanics with throwaway local
state. It does not prove a real relay path, SSH login, recovery, upgrade,
rollback, power-loss behavior or external security review.

## Linux relay exchange gate

Static unit inspection and native-archive tests do not qualify the temporary
relay exchange. Release evidence is incomplete until a disposable Linux amd64
host with systemd and rootful Podman has exercised the signed relay OCI image
through the installed `owntransit-relay-exchange@.service` template. That gate
must authenticate the portable archive member, prove the installer reproduced
it exactly as `/etc/systemd/system/owntransit-relay-exchange@.service`, and run
`systemd-analyze verify` on the installed template before activation.

The runtime portion must use a throwaway allocation capability and the real
packaged network path: public WebPKI reverse proxy to host loopback publication,
then Podman DNAT to the container. It must complete a WebSocket upgrade with the
exact enrollment subprotocol and at least one create/read-or-write mailbox
round trip. Merely calling the Go handler directly or reaching an unpackaged
binary on host loopback is not sufficient, because it does not exercise the
private bridge-source admission path. Evidence must also show that port 9087 is
bound only on host IPv4 loopback. Record the exact live output of
`podman port owntransit-relay-exchange 9087/tcp` and require it to be exactly
`127.0.0.1:9087`; unit text or a socket observed only inside the container is
not evidence of the host exposure boundary. Probe the host's non-loopback
interface address and require connection refusal while the loopback/reverse-
proxy mailbox round trip succeeds. Evidence must also show that the exchange
unit has no role-state or authority mounts and the enrolled relay cannot run
concurrently. The packaged live gate proves the host non-loopback refusal;
repository handler tests separately prove that public, link-local, unspecified
and malformed cleartext peer addresses are rejected before mailbox handling.

Finally, stop every exchange instance and run the authenticated relay
uninstaller. Qualification must prove that the template is removed, no
exchange instance remains active, and no endpoint state or authority material
was created by the temporary unit. Until this packaged round trip is recorded,
the relay bootstrap path remains unqualified even when all local tests pass.

`linux-relay-exchange.sh` is the destructive disposable-host harness for this
gate. Run it only after the exact relay role from the signed bundle has been
installed but not enabled, started or enrolled. The relay state root must still
be empty. Create its dedicated one-use marker only after re-confirming that the
host is disposable; the harness consumes it before the first package mutation:

```text
install -o root -g root -m 0644 /dev/null /etc/owntransit-relay-exchange-qualification-disposable
printf 'OWNTRANSIT_RELAY_EXCHANGE_DISPOSABLE=1\n' >/etc/owntransit-relay-exchange-qualification-disposable
```

```text
scripts/qualify/linux-relay-exchange.sh \
  --bundle /opt/owntransit-release \
  --checksums-sha256 AUTHENTICATED_64_HEX \
  --native-checksums-signature /opt/release-assets/NATIVE-SHA256SUMS.sig \
  --allowed-signers /opt/release-trust/allowed_signers \
  --manifest-signature /opt/release-assets/RELEASE-MANIFEST.sig \
  --release-public-key /opt/release-trust/release-public.pem \
  --policy /opt/release-assets/RELEASE-POLICY.json \
  --policy-signature /opt/release-assets/RELEASE-POLICY.sig \
  --policy-public-key /opt/release-trust/policy-public.pem \
  --exchange-endpoint wss://PUBLIC_RELAY_DNS/connects/enrollment \
  --non-loopback-ip HOST_PUBLIC_IPV4
```

`NATIVE-SHA256SUMS.sig` is the signature over the extracted native bundle's
inner `SHA256SUMS`; the handoff's `trust/SHA256SUMS.sig` instead signs the outer
asset inventory and is not interchangeable. The native bundle, release assets
and independently authenticated trust inputs must remain in separate
root-owned trees whose complete ancestor chains are not group- or
world-writable.

The DNS name must resolve to exactly that public IPv4 address on the
qualification host. The harness authenticates and snapshots the executable
bundle members into fresh root-only inodes, then requires the installed
`owntransitctl` to replay the exact signed manifest and policy idempotently
against its package receipt, selector and external anchor. Only after that
manager-bound proof and marker consumption does it start its generated hash
instance and allocate a mailbox through the real public WSS reverse-proxy path.
It stores one opaque response, proves an identical retry is idempotent and a
conflicting response is rejected, then stops the exact instance and runs the
authenticated staged relay uninstaller. The endpoint, address and throwaway
capabilities are not recorded; bounded JSON evidence is written to
`/var/lib/owntransit-qualification/relay-exchange-evidence.json`.

There is intentionally no public courier command that reads a target response.
The harness therefore records `target_response_read_qualified:false` rather
than inventing a private test interface. Target-side response read, verification
and apply remain part of the full recipient enrollment qualification; this
harness qualifies every public courier action needed to allocate the mailbox
and immutably place the opaque response.

## Local checks

`static-check.sh` validates shell syntax and required fail-closed invariants.
`test-signature-tools.sh` uses ephemeral Ed25519 and RSA SSH keys to exercise
both signing helpers, positive and negative checksum/signature verification,
private-key type, mode, link-count and staging/output separation, Darwin
writable/ACL ancestor rejection, signed source-archive creation, and formula
rendering. Neither test touches a system installation.
