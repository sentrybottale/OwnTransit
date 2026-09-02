# OwnTransit

**Your SSH. Your keys. Untrusted transit.**

> [!IMPORTANT]
> OwnTransit 0.1.0 is the candidate release line for Apple-silicon macOS
> (`arm64`), 64-bit x86 Linux (`amd64`, also called `x86_64`), and 64-bit ARM
> Linux (`arm64`, also called `aarch64`) within the SSH-only boundary described
> here. Intel macOS is outside the 0.1.0 support matrix. The repository can
> build a signed, installable candidate handoff, but that handoff is not an
> official stable release until its exact assets and policy are authenticated,
> its signed qualification record reports every hard release gate as passed,
> and that record is independently verified. This checkout does not claim that
> those platform gates passed or that an independent external security
> certification exists. Keep an operator-owned alternative access and recovery
> path throughout qualification and deployment canarying.

The public `0.1.0-rc.*` packages were qualification artifacts, not supported
in-place predecessors of stable `0.1.0`. Their non-purging uninstall preserves
the old lifecycle and trust state; stable qualification therefore requires a
genuinely fresh host. No destructive RC trust-reset is currently implemented.

## Installed operator experience

OwnTransit is for the practical IT person who can install a package and use
SSH. They should not have to understand certificates, JSON, system groups or
the relay protocol. After an authenticated installation, the intended normal
path is:

1. run `owntransit setup office.otinvite`;
2. make one short verified call and compare three words in each direction; and
3. run the exact OpenSSH command supplied separately, or an SSH alias that IT
   already installed.

OwnTransit never edits SSH configuration or handles SSH keys. The detailed
recipient walkthrough is in [INSTALL.md](INSTALL.md); the machinery below is
for deployers and reviewers.

OwnTransit lets an SSH client and a hidden SSH server talk through a public
relay without trusting that relay with the conversation. The relay may carry
the sealed traffic, observe its shape, or refuse to carry it; it must not be
able to read it, forge either endpoint, or choose where the connector sends
it.

## The problem

An SSH server is often safest when it has no public listener. The client may
also be on an outbound-only network. OwnTransit gives those two buried
endpoints a narrow meeting path without making the public meeting point a
trusted man in the middle.

Both endpoint roles dial outward:

1. the SSH client starts an OwnTransit client as a `ProxyCommand`;
2. a connector beside the SSH server maintains an outbound relay connection;
3. the public relay pairs the two outbound legs and copies opaque bytes; and
4. the connector can deliver an authenticated stream only to the build-fixed
   literal `tcp4 127.0.0.1:22` target.

Neither endpoint exposes an OwnTransit listener or needs a public address. The
relay is the only publicly reachable OwnTransit component.

## The security construction

```text
operator-owned OpenSSH client
  -> OwnTransit client
  -> outer TLS 1.3 carrier
  -> fully untrusted relay
  -> outer TLS 1.3 carrier
  -> end-to-end inner TLS 1.3 mTLS
  -> connector
  -> build-fixed tcp4 127.0.0.1:22
  -> operator-owned OpenSSH server
```

The transport is encrypted twice from the network's perspective: each relay
leg has an outer TLS carrier, and the endpoints create a separate inner TLS 1.3
stream that passes through the relay without terminating there. SSH then runs
inside that carrier with its own independent encryption and host/user
authentication.

Assume the relay host, reverse proxy, process, configuration and keys are fully
compromised. A malicious relay can observe endpoint addresses, timing, sizes
and route correlation. It can cross-wire attempts, delay traffic, exhaust its
own service or deny access. It must not decrypt the inner stream, forge an
endpoint accepted by the other endpoint, select a different connector target,
issue credentials or authorize software and policy changes.

## Connector authorization without a client list

The v1 capability profile does not install a positive client allowlist on the
connector. Instead, an offline issuer exists for one connector and one route.
The connector accepts an unrevoked client leaf only when it:

- chains to that exact locally installed route-capability CA;
- has the strict Ed25519 client-auth certificate profile;
- uses the capability profile's distinct ALPN; and
- has one exact DNS SAN binding the client installation, connector
  installation, route and credential epoch.

The connector still has locally activated state derived from a signed
deployment: its own credentials, route, capability root, revocation
tombstones, limits and relay information. The user does not maintain a
per-client connector configuration.

This deliberately moves trust from a list of client leaves to a narrowly
scoped offline CA. Theft of that CA can mint capabilities for its one
connector/route, so OwnTransit must never use a global client-capability issuer.
OpenSSH remains the independent authority that decides whether a capability
holder may log in.

## Initial trust and enrollment

OwnTransit has no online controller. Initial issuer certificates, the
deployment-verification key and the expected release identity may arrive
tentatively in the invitation, but they become trusted only after the exact
invitation/request transcript is confirmed with the real administrator through
an independently established, bidirectionally authenticated contact procedure.
The relay is never a trust-bootstrap channel, and OwnTransit does not use TOFU
for these authorities.

The source implements the target-local cryptographic enrollment and guided
client exchange:

- target-local unique outer and inner key generation;
- signed CSRs and a target-bound request;
- offline leaf-only issuance;
- a signed response encrypted to a one-request target recipient;
- strict role, installation, route, SAN, key, issuer, runtime and sequence
  verification; and
- durable record creation followed by atomic activation;
- strict signed invitations, independent mailbox capabilities, padded request
  encryption and exact response/request-set cross-binding;
- durable target and operator sessions with target-first, gated two-way word
  comparison and crash-safe resume; and
- a carrier-only `READY` proof followed by local-authoritative retirement of
  one-time mailbox and response authority.

For a brand-new deployment, the authenticated relay artifact first runs in a
temporary **exchange-only** mode. That mode exposes only the fixed bounded
opaque enrollment mailbox on `/connects/enrollment`; it has no carrier,
endpoint credentials, runtime state, issuer, signer, persistence, or target
selection. After the client has durably applied its bound response, the
operator replaces that process with the enrolled relay on the same loopback
port, starts the connector, and the client resumes to authenticated `READY`.
The relay remains untrusted throughout both phases.

The 0.1.0 initial-route workflow installs exactly one relay, one connector,
one route, and one client. Adding another client to an existing route is not
implemented in 0.1.0; route rotation is not a substitute for client
enrollment. This limit is fail-closed and documented in the roadmap.

The machines move only opaque encrypted requests and responses. The invitation
is the only setup file the client recipient handles. They never manually move
generated keys, certificates, enrollment requests, enrollment responses or
runtime configuration, and OwnTransit never edits their SSH configuration.
The words are only a human view of a full transcript digest; they never
authorize enrollment. The relay remains an opaque hostile mailbox. The exact
protocol and disclosed external-review status are documented in
[ENROLLMENT_EXCHANGE.md](ENROLLMENT_EXCHANGE.md).

## What OwnTransit does not own

OwnTransit transports SSH bytes. It never creates, selects, stores or edits SSH
host keys, user keys, accounts, `authorized_keys`, client or server
configuration, forwarding rules, login policy or host recovery.

Bring your own working OpenSSH setup and your own out-of-band host recovery.
An OwnTransit carrier proof is not an SSH login proof, and an SSH login is not
OwnTransit enrollment authority.

OwnTransit is not a VPN, TUN interface, subnet router, DNS layer, service mesh,
identity provider, dashboard, general reverse proxy or remotely managed policy
plane.

## OwnTransit 0.1.0 artifact contract

- `owntransit` for macOS arm64, Linux amd64/x86_64, and Linux arm64/aarch64;
- `owntransit-launcher` for the authenticated macOS arm64 client boundary;
- `owntransit-connector` for Linux amd64/x86_64 and Linux arm64/aarch64,
  compiled only for the fixed SSH target;
- `owntransit-relay` as separate digest-addressed Linux amd64 and arm64 images;
- `owntransitctl` for target-local lifecycle transactions on all three
  supported platform/architecture targets; and
- `owntransit-provision` for offline approval and signing on all three
  supported platform/architecture targets.

Those builds form fourteen separately authenticated artifact records: four for
macOS arm64 and five for each supported Linux architecture.

The installed client flow is: authenticate the release and native handoff, run
`owntransit setup INVITATION.otinvite`, compare the two three-word groups with
the known administrator, let the offline provisioner approve the request,
prove the OwnTransit carrier, and then invoke it from operator-owned SSH
configuration. Interrupted setup resumes with `owntransit setup --resume`; an
unapplied setup can be abandoned with `owntransit setup --cancel`. It requires
no TUN device, DNS takeover or background client daemon.

User-facing `READY` requires a live carrier-only probe through the relay, inner
mTLS and authenticated connector, including the build-fixed loopback SSH-port
dial. It does not prove an OpenSSH host key, user key, account or login.

The rendezvous protocol retains a frozen authenticated legacy wire profile; it
is not a public product name. The route-capability inner profile is separately
versioned and cannot silently downgrade to the older exact-pin profile. The
byte-exact boundary is documented in [COMPATIBILITY.md](COMPATIBILITY.md).

Read [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md),
[COMPATIBILITY.md](COMPATIBILITY.md), [CREDENTIALS.md](CREDENTIALS.md) and
[ENROLLMENT_EXCHANGE.md](ENROLLMENT_EXCHANGE.md)
before evaluating the design. Release integrity requirements and additional
assurance work are tracked in [ROADMAP.md](ROADMAP.md) and
[OWNTRANSIT_SHIPPING_PLAN.md](OWNTRANSIT_SHIPPING_PLAN.md). The immutable
handoff and exit criteria for the required outside assessment are in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md). Candidate freeze, versioning,
signing, tagging and publication order are in
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md).

## Contributing and disclosure

Development and review requirements are in [CONTRIBUTING.md](CONTRIBUTING.md).
Independent-development and contributor rules are in
[PROVENANCE.md](PROVENANCE.md).
Report suspected vulnerabilities through the private process in
[SECURITY.md](SECURITY.md), not a public issue.

OwnTransit is licensed under the [Apache License 2.0](LICENSE). The canonical
public source location is `github.com/sentrybottale/owntransit`.
