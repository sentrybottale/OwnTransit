# OwnTransit security policy

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
platform matrices passed. An official stable handoff must bind the exact source,
signed artifacts and release policy to an independently verified signed
qualification record in which every hard release gate passes. No such result,
independent external security assessment, penetration-test certification or
universal suitability is claimed here. SSH and host recovery remain operator
responsibilities; keep them independently available throughout qualification
and deployment canarying.

Retained `0.1.0-rc.*` package state is not a supported stable-install source.
Those lifecycle binaries recognize the older exact-nine artifact profile and
must fail closed on the exact-fourteen stable manifest. Ordinary uninstall is
intentionally non-purging, and a destructive RC trust-reset is not implemented;
use a genuinely fresh host for stable qualification.

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

## Release integrity and additional assurance

Every official 0.1.0 artifact handoff must provide authenticated native
distribution, an exact release and policy binding, and clean-host evidence for
the supported platform privilege and exposure boundaries. It must exercise
the installed path, service integration, reboot/reconnect and fail-closed
package transaction behavior using the exact released bytes. A known
unaccepted Critical or High security defect is a release block.

The OpenSSH distribution signer authorized as `owntransit-release` is the
privileged package-bootstrap authority: it authenticates the outer asset
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

The packaged relay mailbox accepts only the Podman private-bridge peer as
deployment plumbing. The exact signed units' `--network=bridge` and
`--publish=127.0.0.1:9087:9087/tcp` settings are the exposure boundary;
mailbox reachability grants no release trust, enrollment authority, endpoint
identity or plaintext access. Every exact artifact handoff must qualify an
actual packaged mailbox round trip through that boundary.

The following work improves assurance and operations but is not represented as
missing tunnel, client, connector or relay functionality:

- independent implementation review and authorized penetration testing;
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
not hide them or imply that the platform qualification gates passed:

- Endpoint lifecycle activation relies on descriptor-held runtime generations,
  a final pre-network check, root-published read-only views and a separately
  rooted exact-state rollback anchor. It does not defend against a compromised
  platform package manager or host root; each artifact handoff must cover the
  native package, privilege, reboot and interruption boundary in its evidence.
- Release bundle and policy verification, external release-policy anchor
  compare-and-swap and selector publication are bound by one manager-held
  transaction. A detached verified decision remains intentionally unusable as
  install authorization, so each artifact handoff must qualify the installed
  manager boundary rather than treating detached verification as sufficient.
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
