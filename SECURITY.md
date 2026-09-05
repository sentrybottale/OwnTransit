# OwnTransit security policy

## Receiver-owned pairing development profile

The `pair` commands implement a separately selected 0.1.1 development profile;
they do not change the published 0.1.0 enrollment rules below. See
[RECEIVER_PAIRING.md](RECEIVER_PAIRING.md) and
[PAIRING_INSTALL.md](PAIRING_INSTALL.md) for its authority and testing boundaries.
An independently transferred 256-bit one-use receiver code binds the exact
advertisement and intended receiver. Public IDs and relay codes cannot issue
inner credentials. Code possession authorizes a device, not a human identity.

Receiver issuance happens in a root-owned local process with a bounded pipe
interface. Its separate Linux network worker drops to UID/GID 65534, clears
supplementary groups, disables dumps and gaining privileges, and cannot read the
root-private issuer/signing/age store. Client operational keys are generated on
the client. Both TLS 1.3 mTLS boundaries remain independent; inner exact names,
SPKIs, ALPN and fresh exporter-bound leases gate the fixed SSH dial. Relay keys
cannot forge those checks. Root/endpoint compromise and whole-state rollback or
cloning remain outside this profile's guarantee.

Local policy locks survive restart. A successful lock acknowledges persistence
and closure of the local active-worker gate. Peer shutdown can be delayed by a
malicious relay until the remaining authorization lease expires. It is not a
guarantee of simultaneous shutdown, termination of SSH-started jobs or erasure
of bytes already delivered. Source integration tests are not an independent
security assessment or signed release qualification. CI self-test artifacts are
explicitly unsigned development outputs and do not replace stable assets.

## Release and assurance status

OwnTransit 0.1.0 is the candidate release line for Apple-silicon macOS
(`arm64`), 64-bit x86 Linux (`amd64`/`x86_64`), and 64-bit ARM Linux
(`arm64`/`aarch64`) within the documented SSH-only boundary. Intel macOS is
not a supported 0.1.0 target. The tunnel, route-capability
profile, guided target-generated enrollment, signed verifier-first lifecycle
policy, route-rotation issuance, revocation overlays, external rollback anchor,
exact-record rollback, signed release/policy verification and manager-bound
package activation exist in source. The release tooling can turn one clean
candidate commit into a signed, installable handoff for qualification.

That statement neither authenticates this checkout nor claims that the required
release checks passed. An official stable handoff must bind the exact source,
signed artifacts and release policy to an independently verified signed
qualification record containing literal
`schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`. That overall status
requires all four bounded 0.1.0 results to pass and both unresolved finding
counts to be zero. The results cover the complete source/security/publication
gate, independent signature and inventory verification, the bounded native
artifact smoke described below, and real SSH plus SCP through the untrusted
relay using the exact signed client and connector. No such record,
independent external security assessment, penetration-test certification or
universal suitability is claimed here. SSH and host recovery remain operator
responsibilities; keep them independently available throughout qualification
and deployment canarying.

Retained `0.1.0-rc.*` package state is not a supported stable-install source.
Those lifecycle binaries recognize the older exact-nine artifact profile and
must fail closed on the exact-fourteen stable manifest. Ordinary uninstall is
intentionally non-purging, and a destructive RC trust-reset is not implemented.
Release qualification uses existing or operator-provided hosts and does not
represent them as pristine; retained RC state still cannot be treated as a
supported in-place stable installation. The bounded macOS gate therefore stays
read-only and makes no stable macOS client-install or lifecycle claim.

## Reporting a vulnerability

Use the canonical GitHub repository's private security-advisory feature. Do not
open a public issue for a suspected vulnerability, secret or deployment
exposure. Include:

- affected revision and component;
- minimal reproduction or malformed input;
- expected and observed security boundary;
- whether endpoint, relay or local privileges are required; and
- any evidence that a credential or real deployment may be affected.

If that private channel is unavailable, keep the report private and use only a
maintainer contact independently verified from the canonical repository. Do not
send secrets through ordinary issue trackers.

## Security boundary

OwnTransit assumes the public reverse proxy, relay host, process, configuration
and relay keys are fully compromised. They may observe metadata, ignore
admission rules, cross-wire attempts and deny service. They must remain unable
to decrypt or forge the independently keyed inner client-to-connector TLS
stream.

Each endpoint-to-relay leg uses an outer TLS carrier, and the endpoints create
a separate inner TLS 1.3 mTLS stream through it. SSH is independently encrypted
inside that stream. Compromise of the relay can therefore expose metadata and
availability, but it must not collapse either the inner OwnTransit boundary or
the separate SSH boundary.

Both endpoint roles originate every OwnTransit connection. Neither exposes an
OwnTransit listener or requires a public address; only the relay is publicly
reachable.

Reverse-proxy connection and request limits are availability hygiene, never an
authentication boundary. The supplied Nginx policy keys its per-peer buckets
on the original TCP peer address retained before RealIP header processing and
keeps independent virtual-server-wide ceilings. This prevents a request header
from selecting a quota identity even under unsafe ambient RealIP trust, while
deliberately grouping clients behind the same immediate CDN or proxy. A fully
compromised reverse proxy may still ignore every limit or deny service without
weakening the inner endpoint-authentication and confidentiality boundary.

The client, connector, offline issuers and software/deployment signers are
explicit OwnTransit trust anchors. OpenSSH host/user keys and policy form a
separate, operator-owned security boundary inside the carried stream; they are
not OwnTransit credentials. A compromise of either endpoint is not hidden by the
relay threat model.

OwnTransit owns only the encrypted byte carrier and its endpoint credentials.
It never creates, selects, stores or edits SSH identities, accounts,
authorization, client/server configuration, forwarding or recovery.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component and key boundaries.

## Security invariants

- TLS 1.3 only; mutual authentication on both outer and inner boundaries. Outer
  mTLS is admission defense in depth, not trusted authorization once the relay
  is malicious.
- Exact OwnTransit role, EKU and SAN authorization everywhere. Outer profiles
  and the client's connector check retain exact SPKI pins. A capability-profile
  connector instead requires the exact route-specific client CA plus strict
  connector/route/epoch SAN binding and local revocation state; it has no
  positive client list.
- Newly enrolled runtimes validate each local key/leaf against its explicit
  issuer, exact configured role name and validity window before opening a
  network connection.
- Session resumption disabled for the authenticated profiles. The capability
  profile uses a distinct ALPN, so it cannot fall back to legacy exact-pin TLS.
- Connector local dial occurs only after successful inner authentication.
- Production target is build-fixed to literal `tcp4 127.0.0.1:22`.
- Strict fixed-size rendezvous frames and bounded state/time/resource use,
  including fixed-cardinality DNS-keyed client admission state, a one-per-second
  OPEN rate with burst four, relay per-client pending/active quotas, and a
  post-handshake connector per-client active quota whose zero-count entries are
  deleted.
- No endpoint, issuer, release or deployment secrets on the relay.
- No relay-controlled enrollment, target, software update or rollback channel.
- Proxy stdout contains only SSH bytes.
- Unique endpoint keys per physical installation.
- A distinct offline client-capability root per connector/route; never a global
  capability issuer. One root is normal and a second is accepted only during an
  explicit signed-state rotation overlap.
- Signed, sequenced and reversible release/config/credential tuples for 0.1.0.

Initial public trust may be transported tentatively through the invitation,
but the exact transcript becomes trusted only through an independently
established, bidirectionally authenticated out-of-band procedure. The relay and
enrollment response may carry no authority to replace issuer roots, the
deployment verifier, release trust or rollback floors. There is no TOFU mode
for those anchors.

The route-capability profile intentionally accepts any unrevoked client leaf
issued by that route root. This removes connector-side per-client configuration
and leaves OpenSSH to decide login authorization, but it makes theft of that
route issuer sufficient to mint new capabilities for the route. The legacy
exact-pin migration profile has stronger issuer-compromise resistance because a
new leaf also needs a preinstalled SPKI pin. This tradeoff is explicit, scoped
to one connector/route, and not hidden behind an empty allowlist.

## Installation trust

There are two installation paths with different bootstrap trust assumptions:

- The Linux quick install trusts the canonical GitHub repository and HTTPS
  delivery of a commit-pinned bootstrap script. That script runs as root, pins
  the exact v0.1.0 downloads by size and SHA-256, and invokes the signed native
  installer. A fixed commit avoids following later changes to `main`, but it
  does not protect against a compromised GitHub delivery channel replacing
  the initial script. Such a replacement can run arbitrary root code before
  any embedded check. Those checks authenticate the downloaded payload only
  after the bootstrap itself is trusted.
- The independent/offline handoff authenticates its distribution signer and
  trust statement through a separately established channel before privileged
  execution. It remains available for operators who do not accept GitHub as
  their bootstrap authority. Its instructions are in [INSTALL.md](INSTALL.md).

The quick bootstrap was added after the immutable v0.1.0 release; it is not
part of that release's signed inventories or qualification record. The
release binaries, signatures and runtime authorization are unchanged.
Neither installation path uses an OwnTransit relay as a software authority.
A compromised installer compromises its endpoint; the malicious-relay
construction does not protect a compromised endpoint.

## Release integrity and additional assurance

Every official 0.1.0 artifact handoff must provide authenticated native
distribution and an exact release and policy binding. A separately executed
verifier must authenticate every handoff, policy, manifest and inventory byte.
On matching macOS arm64, Linux amd64 and Linux arm64 hosts, the bounded artifact
result must execute and version-check every ordinary native executable,
authenticate and inspect both relay OCI archives and the Darwin launcher,
record the launcher's expected fail-closed fixed-path rejection, and perform no
macOS system mutation. On both
Linux architectures it must install and activate the exact signed connector,
verify its binary identity and systemd confinement, prove it owns no OwnTransit
listener, restart the enabled service, perform an actual host reboot, reacquire
the host directly, and prove the enabled connector is running or retrying
post-boot. The separate live result must carry a real SSH
session and integrity-checked SCP transfer through the deployed untrusted relay
with the exact signed macOS client and connector, using the pre-existing
operator-supplied client configuration and SSH key. It must perform no macOS
system mutation and leave those client inputs plus the deployed connector
configuration and endpoint credentials unchanged. A known unresolved Critical
or High security defect is a release block.

This is deliberately a bounded first-release claim. It does not prove candidate
macOS client installation or launcher activation, macOS provisioner package
lifecycle, Linux client, provisioner, or relay package lifecycle, pristine
installation, every lifecycle transition, every host policy, or
portability to an untested environment. The Linux connector reboot result is
specific to the two exercised existing hosts, not a clean-host or universal
recovery claim. Those stronger claims require the additional assurance below.

For the independently authenticated handoff, the OpenSSH distribution signer
authorized as `owntransit-release` is the privileged package-bootstrap
authority: it authenticates the outer asset
inventory and the native checksum inventory containing the installer entry
point. Because the first privileged program cannot retroactively authenticate
itself, compromise of that distribution key can authenticate malicious root
installer code even without the distinct release-manifest or release-policy
keys. Those keys preserve separate lifecycle and rollback authorities; they do
not form a threshold signature for package bootstrap. Protected staging must
use fresh root-created inodes on a local filesystem, never a `chown` of an
untrusted extraction tree or a FUSE/network/reused writable tree.

Client, connector, relay and offline provisioner software use the same
manager-bound signed release/policy transaction, external rollback anchor,
immutable release directories and authenticated current selector. The
provisioner handoff invokes its authenticated role-local `owntransitctl` only
for package apply, rollback, recovery and (on macOS) detach. Installing or
updating that role creates no runtime reader, service, target state, endpoint
credential or SSH material.

On macOS, a single persistent root-only `package-mutation.v1.lock` covers both
client and provisioner transitions, public-entry publication and lifecycle-owned
detach. The provisioner release tree remains non-user-traversable at
`root:wheel` mode `0750`; only a distinct digest-matched mode-`0755` copy is
publicly executable. On Linux, one persistent empty root-only
`/var/lib/owntransit/package-supervisor/platform.v1.lock` serializes complete
installer and non-purging uninstaller integration windows. Connector and relay
detach additionally holds the existing role supervisor lock so a concurrent
lifecycle action cannot restart a service while its unit is removed. The
provisioner tree is mode `0755` and package operations fail closed unless
`fs.protected_hardlinks=1`; the legacy directory mode migration is Linux-only.

For connector and relay mutations, a root-only `<role>.intent` record blocks
systemd activation until authenticated package mutation and role activation
finish. The supervisor then atomically renames and directory-syncs the record
to `<role>.restart` before asking systemd to start the role. That second state
allows activation but preserves a durable restart obligation until the service
is verified active. Recovery returns a surviving restart record to the blocked
intent state and replays the exact idempotent operation. Simultaneous intent
and restart records are treated as conflicting residue and fail closed.

The packaged relay mailbox accepts only the Podman private-bridge peer as
deployment plumbing. The exact signed units' `--network=bridge` and
`--publish=127.0.0.1:9087:9087/tcp` settings are the exposure boundary;
mailbox reachability grants no release trust, enrollment authority, endpoint
identity or plaintext access. The repository supplies a packaged mailbox
qualification harness; per-architecture public-relay exchange labs are
additional assurance rather than a 0.1.0 publication gate.

The following work improves assurance and operations but is not represented as
missing tunnel, client, connector or relay functionality:

- independent implementation review and authorized penetration testing;
- pristine or factory-clean macOS and per-architecture Linux lifecycle labs;
- dual public relay-exchange qualification and exhaustive composite dossiers;
- broader hostile-filesystem, disk-full, power-loss and recovery exercises;
- independent clean-builder reproduction and external public-history scans;
- expiry monitoring, authenticated revocation operations and
  third-generation retirement procedures;
- two-location issuer/signing custody and clean-room recovery rehearsals; and
- operator canary, burn-in and environment-specific recovery exercises.

No completion or certification of those external activities is claimed for
0.1.0. The connector's lack of a positive client list makes offline
route-issuer custody, bounded revocation state and a rehearsed issuer-rotation
procedure particularly important operator responsibilities.

## Known limitations in the 0.1.0 candidate scope

The candidate scope retains these fail-closed limitations; release wording must
not turn bounded existing-host smoke into a clean-room or exhaustive platform
qualification claim:

- Endpoint lifecycle activation relies on descriptor-held runtime generations,
  a final pre-network check, root-published read-only views and a separately
  rooted exact-state rollback anchor. It does not defend against a compromised
  platform package manager or host root. Clean-host package, privilege, reboot
  and interruption matrices are additional assurance beyond the 0.1.0 smoke.
- Release bundle and policy verification, external release-policy anchor
  compare-and-swap and selector publication are bound by one manager-held
  transaction. A detached verified decision remains intentionally unusable as
  install authorization. Both Linux connector install/activation/reboot runs
  exercise the manager boundary; the read-only macOS checks do not. These checks
  do not claim candidate macOS client installation or launcher activation,
  macOS provisioner package lifecycle, Linux client, provisioner, or relay
  package lifecycle, an exhaustive lifecycle, or hostile-filesystem qualification.
- Bootstrap release ID, artifact digest, platform and architecture are
  authenticated operator inputs; `owntransitctl` does not yet measure the
  installed executable and derive those values itself.
- Initial route enrollment supports exactly one client. Later-client
  enrollment is not implemented, and route rotation changes authenticated
  route state for the existing deployment; it is not a substitute for adding
  another client.
- Anchor-first endpoint recovery can finish an exact interrupted transition,
  but authenticated garbage collection, third-record retirement and complete
  clean-room recovery policy are not integrated or qualified.
- The initial provisioner creates distinct keys but stores the three issuer
  keys and deployment signer unencrypted beneath one private `0700` directory.
  This proves logical key separation, not two-location custodial separation.
- Consumed-request history is bounded at 4096 entries and then fails closed;
  authenticated compaction has not been designed.

These are local endpoint, lifecycle and custody concerns. They do not give a
malicious relay inner-stream plaintext, accepted endpoint-forgery authority or
connector target-selection authority.

## Secrets and examples

Never commit real keys, tokens, passwords, passphrases, endpoint bundles,
fingerprints, hostnames, public IPs or deployment logs. Public examples use
only reserved names and documentation address ranges.

If a real secret ever enters a commit, deleting the working-tree file is not
remediation. Revoke/rotate it first, then clean the publication history through
a separately reviewed process.

## Cryptography policy

Use the standard-library TLS 1.3 implementation and reviewed standard envelope
and signing constructions. Do not introduce custom encryption, home-grown key
derivation, ambiguous signed serialization or a new handshake pattern without a
written threat analysis, test vectors, negative tests and independent review.
