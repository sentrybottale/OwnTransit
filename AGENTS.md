# OwnTransit contributor contract

Read `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `ROADMAP.md`,
`OWNTRANSIT_SHIPPING_PLAN.md` and `ENROLLMENT_EXCHANGE.md` before changing
security-sensitive behavior.

## Product boundary

- OwnTransit carries SSH byte streams only.
- It is not a VPN, TUN interface, service mesh, DNS layer, controller, UI,
  identity provider or general-purpose proxy.
- Both client and connector originate every OwnTransit connection. Neither
  endpoint exposes an OwnTransit listener or requires a public address; only the
  relay is publicly reachable.
- Assume the public reverse proxy, relay host, relay process, configuration and
  relay keys are fully compromised. They must never terminate or forge the inner
  client-to-connector TLS stream.
- The production connector target is build-fixed to literal
  `tcp4 127.0.0.1:22`; never add a runtime-, environment-, DNS- or wire-selected
  target.
- SSH remains an independent, operator-owned authenticated and encrypted
  protocol inside the OwnTransit carrier. OwnTransit provides transport only;
  OpenSSH owns every SSH identity, account, authorization, configuration,
  forwarding and recovery decision.

## V1 compatibility boundary

The source currently implements the authenticated legacy v1 profile documented
in `COMPATIBILITY.md`. Frame magic, READY marker, ALPN values, WebSocket
subprotocol, certificate identity format, route/session encoding and protocol
version are authenticated compatibility inputs. Do not rename or weaken them
as product branding work.

Any protocol change requires an explicit version, mixed-version tests, a
downgrade analysis and a migration/rollback design. Add OwnTransit artifact
aliases before removing legacy source entrypoints.

## Security invariants

1. Preserve both independent TLS 1.3 mTLS boundaries and exact OwnTransit
   endpoint certificate/SPKI authorization.
2. Complete the inner handshake and peer authorization before any connector
   local dial.
3. Keep parsers strict, bounded and closed to unknown fields/types.
4. Add negative tests before relaxing identity, target, path, limit or state
   validation.
5. Client proxy stdout is exclusively the raw SSH stream; diagnostics use
   stderr.
6. Secrets never appear in Git, images, argv, environment, logs, crash output,
   broad temporary trees or test fixtures.
7. Treat the entire relay domain as malicious. It may expose metadata or deny
   service only; it must gain no plaintext, endpoint-forgery, enrollment,
   signing, update, rollback or target-selection authority. Outer mTLS is
   admission defense in depth, not the malicious-relay trust boundary.
8. Installers operate only on the local role. Do not build a universal root
   orchestrator or infer permission to operate a real host.
9. OwnTransit and its installers never create, select, store or edit SSH
   host/user keys, accounts, `authorized_keys`, client/server configuration,
   forwarding rules or SSH/host recovery. Qualification uses disposable or
   operator-supplied SSH fixtures.
10. The explicitly selected receiver-owned pairing profile is specified in
    `RECEIVER_PAIRING.md` and `PAIRING_INSTALL.md`. Its independently transferred
    private one-use code authorizes one exact client; public receiver IDs and
    relay routing codes grant no endpoint authority. Receiver issuer/signing/age
    keys stay in the local authority process, inaccessible to its unprivileged
    network worker. Legacy v1 enrollment convenience may move only bounded opaque blobs through the
    relay. Comparison words are only a human view of the full transcript digest;
    they grant no authority and authenticate neither human. Before issuance or
    activation, the recipient must authenticate the administrator through an
    independently established contact procedure, and the administrator must
    authenticate the intended recipient from pre-existing operator records.
    Invitation possession, request contents, safety words, mailbox capabilities,
    caller ID and contact information supplied during enrollment are never
    human identity evidence. Both sides must complete and locally record the
    fixed target-first, gated-reveal comparison against the same full digest.

## Repository hygiene

- Never commit private keys, passwords, passphrases, endpoint bundles, issuer
  material, access commands, real hostnames/domains/IPs, fingerprints or dated
  deployment evidence.
- Use reserved example domains and documentation address ranges in public
  examples.
- Keep private operator notes outside the repository or under the ignored
  `.private/` root.
- Preserve unrelated user changes in a dirty worktree.
- Do not rewrite Git history, publish a repository, operate infrastructure or
  rotate credentials without an explicit request.
- Historical private deployment material is not a source of public examples.

## Required checks

Run both build profiles. The untagged/default connector is the production
port-22 profile; port 2222 exists only behind the explicit development POC tag:

```sh
go test -race ./...
go test -race -tags=owntransit_poc_ssh ./...
go vet ./...
go vet -tags=owntransit_poc_ssh ./...
./scripts/security-check.sh
./scripts/publication-check.sh
```

If the local host lacks the required toolchain, use the pinned repository build
environment and report exactly which checks were and were not executed.
