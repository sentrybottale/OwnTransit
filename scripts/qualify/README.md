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
such as `/opt/owntransit-release`. Keep `SHA256SUMS.sig`, both independently
trusted release/policy public keys, the release-manifest signature, and the
signed policy plus its signature under a separate protected trust root; none
may come from the candidate staging tree. First run the read-only gate:

```text
scripts/qualify/linux-amd64-vm.sh preflight \
  --bundle /opt/owntransit-release \
  --checksums-sha256 AUTHENTICATED_64_HEX \
  --checksums-signature /opt/release-trust/SHA256SUMS.sig \
  --allowed-signers /opt/release-trust/allowed_signers \
  --signer owntransit-release \
  --manifest-signature /opt/release-trust/RELEASE-MANIFEST.sig \
  --release-public-key /opt/release-trust/release-public.pem \
  --policy /opt/release-trust/RELEASE-POLICY.json \
  --policy-signature /opt/release-trust/RELEASE-POLICY.sig \
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

## Local checks

`static-check.sh` validates shell syntax and required fail-closed invariants.
`test-signature-tools.sh` uses ephemeral Ed25519 and RSA SSH keys to exercise
both signing helpers, positive and negative checksum/signature verification,
private-key type, mode, link-count and staging/output separation, Darwin
writable/ACL ancestor rejection, signed source-archive creation, and formula
rendering. Neither test touches a system installation.
