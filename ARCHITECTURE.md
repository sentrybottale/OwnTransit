# OwnTransit architecture

The receiver-owned 0.1.1 development profile is explicitly selected by the
`pair` commands and specified in [RECEIVER_PAIRING.md](RECEIVER_PAIRING.md).
Its command flow is in [PAIRING_INSTALL.md](PAIRING_INSTALL.md). The legacy
administrator-led profile below remains unchanged for the 0.1.0 release.

## Scope

OwnTransit carries one thing: a byte stream between a native OpenSSH client and
a connector-local OpenSSH server. It does not create a network interface, route
subnets, resolve private DNS, expose a public SSH port or select arbitrary
connector destinations.

Both endpoint roles originate every OwnTransit connection. Neither the client
nor connector exposes an OwnTransit listener or requires a public address; the
relay is the only publicly reachable component.

V1 always uses a public rendezvous relay. A possible direct path is a separate
future protocol, not a hidden optimization in v1.

## Components

### Client

The client is an on-demand OpenSSH `ProxyCommand`. It opens an outbound carrier
to the relay, completes outer TLS 1.3 mutual authentication, requests one exact
route, then completes a separate inner TLS 1.3 mutual-authentication handshake
with the connector. Only after the connector's authenticated READY marker does
the client copy stdin/stdout as opaque SSH bytes. It has no inbound listener.

### Connector

The connector maintains an outbound authenticated control connection to the
relay. For an admitted session it opens a second outbound data connection,
completes inner TLS with a client holding a route-scoped capability, acquires a
bounded active-session slot and dials the build-fixed literal
`tcp4 127.0.0.1:22`. It has no inbound listener.

### Relay

The relay terminates only the two independent outer admission-TLS connections.
It parses a small fixed-size rendezvous protocol, pairs one client leg with one
connector leg and copies the still-encrypted inner stream. It has no inner TLS
key, endpoint issuer, SSH credential, software-signing key or target-selection
input.

While the relay is honest, every authenticated client DNS identity owns one
preallocated admission account: a one-per-second OPEN bucket with burst four,
plus bounded pending and active quotas. Allowed SPKI rotation pins for that DNS
name share the account, and network-provided names cannot create new entries.
Global and per-route caps remain independent backstops.

That description is expected behavior, not a trust assumption. The security
model treats the reverse proxy, relay host, relay implementation, configuration
and keys as fully malicious. They may ignore admission rules, cross-wire
sessions, replay attempts and deny service; the independent inner boundary must
still reject forgery and preserve plaintext confidentiality.

Before a fresh relay has endpoint credentials, the same authenticated relay
artifact may run in a separate temporary `exchange` mode. It binds only the
packaged container address, serves the exact `/connects/enrollment` path, and
reuses the bounded in-memory opaque mailbox. It cannot serve `/connects` or
load a target runtime, endpoint key, issuer, signer, route, or connector
selection. The operator keeps it running only until the first client has
fetched and durably applied its bound response, then replaces it with the
enrolled full relay on the same host-loopback publication port. This is a cold
start mechanism, not an alternate carrier or online controller.

### Offline provisioner

The provisioner is not an online controller. It approves target-generated CSRs,
issues role-specific leaves, renders route-capability roots, revocations and the
remaining exact peer pins, and signs target-bound deployment responses. Its
issuer and deployment-signing authority never belongs on a client, connector or
relay.

## Layering

```text
Public WebPKI TLS / WebSocket carrier
  outer TLS 1.3 mTLS: client <-> relay
  outer TLS 1.3 mTLS: connector <-> relay
    inner TLS 1.3 mTLS: client <-> connector
      SSH transport: OpenSSH client <-> OpenSSH server
```

Each layer has a different job:

- WebPKI makes the public carrier deployable behind an ordinary reverse proxy.
- Outer mTLS performs admission and protects rendezvous frames against ordinary
  network interference while the relay key and implementation are honest. The
  malicious-relay claim does not rely on it.
- Inner mTLS keeps even a fully compromised relay outside OwnTransit endpoint
  authentication and plaintext.
- Operator-owned SSH independently authenticates the server host and user key.

The outer carrier and inner endpoint stream are separate encryption layers.
SSH is a third, independent protocol inside them; its encryption is not used as
an excuse to omit OwnTransit's end-to-end inner layer. OwnTransit does not
create, select, store or edit SSH host/user keys, accounts, authorization,
client/server configuration, forwarding or recovery.

## OwnTransit endpoint authorization

- Every physical client has unique outer and inner keys.
- Every connector has unique outer and inner keys.
- Before networking, each runtime validates its local key/leaf against the
  explicitly installed local issuer, exact role name, EKU and validity window.
- Clients validate the connector chain, validity, exact role/EKU/SAN and
  explicit connector SPKI pins.
- A connector does not carry a positive client list. It accepts only a strict
  Ed25519 client capability chaining to the exact locally installed
  connector-and-route-specific client root. The one DNS SAN binds client
  installation, connector installation, route and credential epoch.
- The canonical capability SAN is
  `i-<client-id>.r-<route-id>.c-<connector-id>.e-<16-hex-epoch>.client-cap.v1.owntransit.invalid`.
  The connector leaf uses
  `i-<connector-id>.r-<route-id>.connector.v1.owntransit.invalid`. These are
  certificate identities under the reserved `.invalid` namespace, not DNS
  discovery inputs.
- The capability profile has its own ALPN. The legacy per-client exact-pin
  profile remains available only when explicitly selected for migration; an
  empty client list never selects capability behavior.
- Connector state may contain bounded client-installation and client-SPKI
  revocations rendered by signed local deployment state. One route root is
  normal; exactly two are accepted only during explicit rotation overlap.
- Post-handshake active-session accounts are keyed by the authenticated client
  installation ID, capped below total connector capacity and deleted at zero;
  unauthenticated input can never create that map state.
- Route IDs are opaque fixed-size identifiers.
- The connector target is selected by the production build, not configuration,
  DNS, environment or protocol input.
- Removing an identity affects new handshakes; every connector session ends no
  later than the earlier of its configured lifetime and the client leaf's
  `NotAfter`.

Route capability authorization deliberately trades connector configuration
cardinality for issuer blast radius. A stolen route-client issuer can mint a
new capability for that one connector and route, whereas the legacy exact-pin
profile also required a preinstalled leaf pin. OwnTransit therefore never uses
a global client-capability issuer: every connector/route receives a separate
offline root, distinct from relay, connector, deployment and release
authorities. OpenSSH still makes the independent login decision.

The relay may decide whether it can pair an admitted route, but it is not an
authorization oracle for endpoint trust.

These rules authorize OwnTransit endpoint identities and one build-fixed byte
destination only. OpenSSH remains solely responsible for every SSH identity,
account, authorization, configuration, forwarding and recovery decision.

## Trust bootstrap and local state

There is no online controller and no trusted instruction channel through the
relay. A target may receive the expected public issuer certificates,
deployment-verification key and release identity tentatively through an
untrusted invitation carrier, but their exact transcript must be authenticated
through an independently established, bidirectionally authenticated human
channel before activation. That ceremony is unavoidable: accepting those
values merely because the relay, enrollment response or download delivered them
would move the trust boundary back to the public transit system.

Enrollment private keys and CSRs are generated on the target. The offline
provisioner receives public requests, issues leaves and returns a signed payload
encrypted to a one-request recipient. The lifecycle code writes a complete
write-once generation, fsyncs its contents, then atomically selects that record
in durable state. Monotonic high-water marks prevent protocol replay;
separately authenticated rollback floors and tombstones are intended to
constrain which older complete record may be selected.

"Write-once" describes the lifecycle transaction, not an operating-system
immutability bit. The package manager owns lifecycle mutation, holds the
external anchor and role-selector locks across authenticated transitions, and
publishes a read-only runtime view to the exact installed runtime identity.
Guided setup is bound to that identity and cannot activate a detached package
decision. Compromise of the privileged package manager or host root remains
outside the endpoint-isolation claim. The 0.1.0 artifact smoke executes and
version-checks every ordinary native executable on its matching architecture,
authenticates and inspects both relay OCI archives and the Darwin launcher,
records the launcher's expected fail-closed fixed-path rejection, and performs
no macOS system mutation.
On existing Linux amd64 and Linux arm64 hosts it installs and activates the
exact signed connector, verifies its binary identity and systemd confinement,
proves it owns no OwnTransit listener, restarts the enabled service, performs an
actual host reboot, reacquires the host directly, and proves the connector is
running or retrying post-boot. It does not claim candidate macOS client
installation or launcher activation, macOS provisioner package lifecycle,
Linux client, provisioner, or relay package lifecycle, clean-host state,
interruption or hostile-filesystem coverage.

The native filesystem boundary is platform-specific. On macOS arm64, one
persistent root-only `package-mutation.v1.lock` serializes client and
provisioner apply, rollback, recovery, detach and public-entry publication. The
provisioner release tree remains `root:wheel` mode `0750`; a distinct digest-matched
`root:wheel` mode-`0755` copy is the only public provisioner executable. On
Linux amd64/x86_64 and Linux arm64/aarch64, the provisioner package tree is
mode `0755` behind an ordinary selector, so installation and every provisioner
package operation require `fs.protected_hardlinks=1`. Only Linux has the
authenticated legacy directory migration from mode `0750` to `0755`. A
permanent root-only `package-supervisor/platform.v1.lock` covers each complete
Linux installer or non-purging uninstaller integration window; service-role
detach also retains the connector or relay supervisor lock through stop,
disable and unlink.

Each Linux service-role package mutation is crash-consistent across the
systemd restart boundary. A root-only `<role>.intent` record blocks service
activation while package state is changing. Once mutation and role activation
are complete, the supervisor atomically renames and directory-syncs that record
to `<role>.restart`; this allows systemd activation while preserving a durable
restart obligation. Only a verified active service permits removal of the
restart record. Recovery moves a surviving restart record back to intent,
replays the authenticated idempotent operation, and completes the same
transition. Conflicting records fail closed.

Initial request, guided approval, apply, signed floor/upgrade policy, exact
rollback, interruption recovery and native package integration are part of the
0.1.0 candidate implementation. An official stable handoff must independently
verify its signed bytes, complete the bounded artifact smoke above, and prove
real SSH and SCP through the deployed untrusted relay with the exact signed
client and connector. That live proof uses the pre-existing operator-supplied
client configuration and SSH key, performs no macOS system mutation, and must
leave those client inputs plus the deployed connector configuration and
endpoint credentials unchanged. Its independently verified signed qualification
record must contain literal `schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`; that overall status
also requires all four fixed results to pass and both unresolved finding counts
to be zero. The initial workflow authorizes exactly one relay, one connector,
one route and one client. Adding a later client requires a
separately versioned approval-context and signed relay-policy transition and is
not implemented in 0.1.0. Expiry monitoring, rotation, revocation, retirement,
issuer custody and clean-room recovery remain operator-run procedures and
additional assurance work; the architecture does not claim that they are
automatic or externally certified.

## Failure and compromise properties

| Compromised component | Expected impact | Must remain impossible |
|---|---|---|
| Public reverse proxy or relay host | Metadata observation, delay, denial, resource pressure | SSH plaintext, accepted endpoint forgery, local target selection, credential or update issuance |
| Client host | That OwnTransit client identity is lost; operator-managed SSH material on the same host may also be exposed outside OwnTransit's custody | Connector/issuer/release-key compromise by design |
| Connector | Connector impersonation and access to its fixed local SSH socket | Client/issuer/release-key compromise by design |
| Offline issuer | New endpoint identities can be minted | Software-release signing unless separately compromised |
| Release signer | Malicious software can be authenticated | Endpoint certificate issuance unless separately compromised |

No architecture makes a compromised endpoint harmless. OwnTransit instead
minimizes what a transit-host compromise can do and separates credentials so one
key is not universal authority.

## Session transcript decision

V1 does not add a bespoke three-party signature exchange. TLS 1.3 already uses
`CertificateVerify` and `Finished` to authenticate its handshake transcripts.
A relay signature would not survive relay-key compromise and would add another
canonicalization and key-lifecycle surface.

If a later protocol needs explicit route/session channel binding, it may bind a
fixed transcript (`version`, route, epoch, session and endpoint SPKIs) to the
inner TLS connection with a dedicated TLS exporter, then fail before the local
SSH dial. That requires a versioned design and review.

## Compatibility

The rendezvous framing, READY marker and outer authenticated identifiers retain
the frozen profile in `COMPATIBILITY.md`. Route capabilities are a deliberately
separate inner authorization profile, `owntransit-route-capability/1`, with a
distinct ALPN and certificate-name format. The earlier exact-pin identity is
not reinterpreted. Any further profile change still requires explicit
negotiation, downgrade protection and mixed-version rollback tests.

The release-manifest v1 envelope separately authenticates an exact artifact
matrix. Public `0.1.0-rc.*` lifecycle binaries accept exact-nine; stable
`0.1.0` accepts exact-fourteen. RC state is not a supported in-place stable
predecessor, and ordinary non-purging uninstall does not erase that retained
state. This compatibility rule is separate from the release's bounded native
artifact, read-only macOS, and Linux connector/reboot checks.
