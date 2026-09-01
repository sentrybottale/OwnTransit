# OwnTransit independent security review brief

## Purpose

This brief defines the minimum independent implementation review and authorized
penetration-test scope required before an OwnTransit v1 release. It is not a
self-attestation. A reviewer is independent only when they did not design or
implement the reviewed revision and have no release-approval conflict.

The review target must be one immutable, clean public-root Git revision and the
exact release manifest and artifact digests produced from it. Findings against
another revision do not qualify the release candidate.

## Security claim under review

OwnTransit carries only an SSH byte stream. The client and connector both dial
outward, and only the rendezvous relay is public. Treat the reverse proxy,
relay host, relay process, configuration, storage and every relay key as fully
compromised.

Even under that compromise, the relay must remain unable to:

- decrypt the inner client-to-connector stream;
- forge an endpoint accepted by the other endpoint;
- select or influence the connector destination;
- enroll an endpoint, mint a route capability, distribute trusted policy, or
  authorize a release, upgrade, rollback or recovery; or
- cause proxy diagnostics or control bytes to enter the SSH stream.

The only production connector destination is the build-fixed literal
`tcp4 127.0.0.1:22`. OpenSSH identities, accounts, authorization, forwarding,
configuration and host recovery are outside OwnTransit.

The normative design and invariants are in `ARCHITECTURE.md`, `SECURITY.md`,
`CREDENTIALS.md`, `AGENTS.md` and `OWNTRANSIT_SHIPPING_PLAN.md`.

## Required reviewer work

The reviewer must independently inspect, reproduce and attack at least these
boundaries:

1. Outer and inner TLS 1.3 profiles, certificate roles, EKUs, SANs, SPKI pins,
   capability-root scope, ALPN separation, session resumption and expiry.
2. Hostile-relay cross-wiring, duplicate joins, replays, truncation, ordering,
   backpressure, cancellation, starvation and resource exhaustion.
3. The pre-local-dial authentication gate and the impossibility of changing
   `tcp4 127.0.0.1:22` through configuration, environment, DNS or wire input.
4. Strict bounded parsing of configuration, frames, enrollment, deployment,
   release, policy, anchor and local-state records, including duplicate and
   unknown fields and non-canonical encodings.
5. Target-generated enrollment, offline approval, response encryption,
   rotation overlap, revocation, expiry, monotonic floors, exact rollback,
   tombstone preservation and clean recovery.
6. Release/deployment signer separation, artifact measurement, manifest and
   evidence binding, replay/downgrade resistance and rollback anchors outside
   service-writable state.
7. Filesystem attacks: symlink, hardlink, traversal, ownership/mode confusion,
   pathname replacement, concurrent apply, interruption, disk-full behavior,
   stale generation handles and snapshot rollback.
8. Native packaging: Linux service identity and PID-1 unit, macOS/Homebrew
   install path, uninstall non-purge behavior, startup/reboot behavior and the
   absence of SSH configuration mutation.
9. Secret exposure through Git, build context, artifacts, images, argv,
   environment, logs, crash output and temporary files.
10. Dependency and build risks, reproducibility claims, SBOM/license evidence,
    vulnerability reports and release-key recovery/revocation procedures.

Reviewers should add their own attack hypotheses. Passing only the repository's
existing tests is not an independent assessment.

## Authorization boundary

The default authorization covers local disposable fixtures and targets created
for the review. It does not authorize testing a real website, VPS, SSH host,
third-party service, public IP range or credential. Denial-of-service tests must
remain inside an isolated fixture with explicit resource limits.

No real key, hostname, address, fingerprint, endpoint bundle or operator log
belongs in the report or reproduction files. Use reserved example names and
documentation address ranges.

## Reproduction baseline

From the exact review revision, run:

```sh
go test -race ./...
go test -race -tags=owntransit_poc_ssh ./...
go vet ./...
go vet -tags=owntransit_poc_ssh ./...
./scripts/security-check.sh
./scripts/publication-check.sh --history
./scripts/release/static-check.sh
```

Where the host lacks Go, use the digest-pinned build stages in `Containerfile`.
Record tool versions, host architecture and every deviation. Independently
verify release signatures, artifact hashes, SBOM/license hashes, reproducible
outputs and native install results; do not accept a CI badge as evidence.

## Deliverables

The final report must contain:

- reviewer identity, independence statement and review dates;
- exact Git revision, release ID, manifest hash and artifact hashes;
- methods, tools, versions, environments and scope exclusions;
- one reproducible record per finding with affected invariant and component;
- severity, exploit prerequisites, impact and confidence;
- proposed remediation and retest result; and
- a signed final disposition for every finding.

Use these release severities:

- **Critical:** breaks inner confidentiality/authentication, permits arbitrary
  connector targeting, credential/release authority forgery, or unauthenticated
  remote code execution.
- **High:** practical endpoint compromise, persistent downgrade/revocation
  bypass, secret extraction, privileged package escape or unbounded remotely
  triggerable resource exhaustion.
- **Medium:** meaningful defense-in-depth failure or constrained availability,
  integrity or metadata exposure outside the documented model.
- **Low:** hardening, diagnosability or misuse resistance with limited direct
  security impact.

## Release exit rule

Every Critical and High finding must be fixed and independently retested, or
explicitly accepted in a public release risk record by the project owner. An
unreviewed change to cryptography, identity, parsing, lifecycle, packaging or
release verification after the review invalidates the affected portion and
requires focused re-review.
