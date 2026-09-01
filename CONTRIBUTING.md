# Contributing to OwnTransit

OwnTransit is security-sensitive infrastructure. Prefer small, reviewable
changes with explicit negative tests over broad refactors.

## Before changing behavior

Read:

1. `README.md`
2. `ARCHITECTURE.md`
3. `SECURITY.md`
4. `CREDENTIALS.md`
5. `ROADMAP.md`
6. `OWNTRANSIT_SHIPPING_PLAN.md`
7. `AGENTS.md`

Open a design discussion before changing a wire value, trust bootstrap,
certificate profile, capability scope, connector target, public API, package
layout, durable state invariant, release policy, or credential lifecycle.

## Boundaries that changes must preserve

- Treat the relay host, proxy, process, configuration, and keys as compromised.
  It may expose metadata or deny service but must not terminate or forge the
  inner client-to-connector TLS stream.
- Preserve the independent outer and inner TLS 1.3 boundaries. OpenSSH remains
  a third, operator-owned encrypted and authenticated protocol inside the
  carrier.
- Keep the connector destination build-fixed to literal
  `tcp4 127.0.0.1:22`. Reject runtime, environment, DNS, relay, and wire-selected
  targets.
- Keep the connector's positive client list empty. The public capability
  profile authorizes through an exact per-route offline client-capability CA,
  capability ALPN, strict certificate profile, canonical
  client/connector/route/epoch SAN, and bounded authenticated tombstones.
- Bootstrap issuer pins, deployment verification, release identity, role, and
  runtime binding through an independently authenticated out-of-band channel.
  Never use relay-delivered trust or TOFU.
- Keep target private keys on the target and all issuer/deployment/release
  private keys offline and out of runtime packages.
- Do not make OwnTransit create or edit OpenSSH identities, accounts,
  authorization, configuration, forwarding, or recovery state.
- Read `PROVENANCE.md`. Every commit must include a `Signed-off-by` trailer
  certifying Developer Certificate of Origin 1.1, and every third-party input
  must be identified with its compatible license and attribution.

The byte strings isolated in `COMPATIBILITY.md` are authenticated compatibility
inputs. Branding work must not rename them. A protocol change requires a new
version, downgrade analysis, mixed-version tests, migration, and rollback
design.

## Development checks

Use the exact Go version declared in `go.mod`. The full security gate runs both
race and vet profiles, pinned vulnerability analysis, repository/publication
checks, release and platform static checks, and signature-helper tests:

```sh
./scripts/security-check.sh --full
./scripts/publication-check.sh
./scripts/tests/publication-tools.sh
```

The read-only GitHub workflow additionally runs `publication-check.sh
--history` against the complete public object graph. That history mode is
expected to reject the private development repository; public work begins from
the sanitized one-root export described in `PUBLISHING.md`.

New parsers and state transitions need malformed, truncated, duplicate-field,
unknown-field, replay, downgrade, bound, and cancellation tests. Filesystem and
lifecycle changes need symlink, hardlink, traversal, ownership, permissions,
interruption, concurrency, and durability tests. Peer authorization and fixed
local-dial changes need negative tests proving failure before any connector
local dial.

## Pull requests

- Explain every trust boundary and durable invariant affected.
- List the positive and negative checks run, including any checks that could not
  run.
- State whether authenticated wire inputs, capabilities, bootstrap trust,
  credentials, release metadata, state floors, or package layout changed.
- Do not include real endpoints, domains, addresses, usernames, credential
  values, fingerprints, access commands, deployment output, operator notes, or
  screenshots containing identifiers.
- Use reserved example domains and documentation address ranges only when an
  example is essential.
- Keep generated artifacts, runtime state, and credentials out of every commit.
- Do not publish or graft private development history. Public work starts from
  the reviewed new root commit described in `PUBLISHING.md`.

## Security reports

Follow `SECURITY.md`. Do not disclose a suspected vulnerability, secret, or
private deployment detail in a public issue or pull request.
