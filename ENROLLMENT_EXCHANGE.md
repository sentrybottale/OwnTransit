# Hostile enrollment exchange

This document specifies the unchanged legacy administrator-led profile. The
separately selected 0.1.1 receiver-owned `pair` commands use
[RECEIVER_PAIRING.md](RECEIVER_PAIRING.md), not this human comparison procedure.

Status: implemented v1 protocol for the OwnTransit 0.1.0 release-candidate line.
Canonical signed
invitations, independent mailbox capabilities and commitments, padded request
encryption, exact invitation/request binding, full-transcript hashing,
target-first word comparison, durable target/operator sessions, response
cross-binding, the hostile courier/mailbox, resumable client setup and the
carrier-only `READY` gate are present in source. A signed installable candidate
handoff can be built, but an official stable handoff must still carry an
independently verified signed qualification record containing literal
`schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1` and `status=PASS`. That overall status
requires all four bounded 0.1.0 results to pass and both unresolved finding
counts to be zero. Independent cryptographic, application and human-factors
certification is not claimed.

## Outcome

A recipient should handle one target-specific invitation, complete a guided
target-first, two-way six-word comparison with a known administrator, and wait
for `READY`.
OwnTransit should exchange the enrollment request and response automatically
without giving the public relay any enrollment authority.

The 0.1.0 initial-route profile covers exactly one relay request, one connector
request and one client request. It does not add a later client to an existing
route; the signed three-target request-set meaning must not be silently reused
for that different operation.

This is a convenience layer over the existing target-local enrollment
construction. It must not change these invariants:

- operational private keys are generated on and never leave their target;
- issuer, deployment-signing and release-signing private keys remain offline;
- initial trust never comes from the relay, DNS, a download redirect, TOFU, or
  a response authenticating its own verifier;
- every response remains signed, encrypted to one retained request recipient,
  and bound to the exact role, installation, route, release, nonce and
  sequence; and
- a malicious relay gains only metadata and denial-of-service power.

Bidirectional human authentication plus the transcript comparison is the
initial trust ceremony. It is not optional and must gate issuance and
activation.

## Roles

- **Target**: the client, connector, or relay installation generating local
  keys and a signed request.
- **Relay exchange**: a bounded opaque request/response rendezvous with no
  plaintext parser, signer, issuer, directory, policy, or target credentials.
- **Courier**: an online, untrusted administrator-side program that downloads
  and uploads opaque blobs. It holds no signing or issuer private key.
- **Provisioner**: the offline authority that validates requests, displays the
  comparison phrase, issues leaves, signs deployments and encrypts responses.
- **Human verifiers**: the recipient authenticates the administrator through an
  independently established contact procedure, and the administrator
  authenticates the intended recipient from pre-existing operator records.
  They then confirm the phrase. The phrase authenticates only the transcript,
  not either human.

The courier and relay may both be fully compromised. Neither can approve a
request.

## Invitation split

The offline provisioner creates a brand-new, expiring invitation and an
operator receipt. Both are strict, canonically encoded, versioned objects.

The recipient invitation contains only bounded public or limited one-time
material:

- invitation ID and expiration;
- target role and intended route/connector binding;
- exact release ID, release sequence, artifact digest, platform and lifecycle
  floor;
- issuer pins and deployment-verifier identity;
- relay exchange endpoint;
- a one-invitation age X25519 request recipient;
- a random request-write capability and a distinct response-read capability;
- domain-separated commitments to the operator-only request-read and
  response-write capabilities; and
- the offline deployment signature over the complete invitation.

The operator receipt retains the exact invitation digest, intended recipient
description and pre-existing identity/contact reference, request-read
capability, response-write capability and the one-invitation request-decryption
identity. Administrator capabilities and recipient-authentication records are
not placed in the recipient invitation.

Mailbox IDs and all four capabilities are independently generated with at
least 256 bits of operating-system randomness. Capabilities are abuse controls,
not trust anchors: the relay sees them and is already assumed malicious.

## Protocol

```text
offline provisioner       hostile relay/courier       target       human
        |                           |                    |             |
        |---- invitation ----------+------------------->|             |
        |                           |                    | generate    |
        |                           |<-- encrypted req --| local keys  |
        |<--- encrypted request ----|                    |             |
        | validate and compute transcript                words ------>|
        |<===== known channel: target reads its three words first =====|
        | match, then reveal reverse words ===========================>|
        |<===== known channel: administrator reads reverse words =====>|
        | confirm transcript       |                    | confirm     |
        | sign + encrypt response   |                    |             |
        |---- encrypted response -->|------------------->|             |
        |                           |                    | verify/apply|
        |                           |                    |---- READY -->|
```

1. The target strictly parses the invitation and verifies that its installed
   release and platform match. Invitation trust remains tentative.
2. A root-protected lifecycle operation creates one installation identity,
   fresh operational keys and CSRs, request nonce, and response-recipient key.
   It signs the existing enrollment request exactly once.
3. The request is encrypted to the invitation's one-time age recipient,
   padded to a versioned bounded class, retained locally, and uploaded. A
   retry uploads byte-for-byte identical ciphertext.
4. Target and offline provisioner independently compute the same full 256-bit
   digest from the exact signed invitation bytes, exact signed request
   plaintext bytes, and exact encrypted request ciphertext bytes. Two distinct
   domain-separated hashes derive the target-to-provisioner and
   provisioner-to-target three-word groups. The provisioner refuses any
   request without an exact locally retained operator receipt and matching
   invitation digest, even if the request carries a self-declared verifier or
   otherwise parses correctly. It prepares the words only after decrypting and
   fully validating the request and its invitation binding.
5. Recipient and administrator use a bidirectional identity-check procedure
   established before the invitation. For example, the recipient calls a
   previously known help-desk number and both complete the organization's
   ordinary identity checks. Contact details in the invitation, relay, error
   page or invitation-delivery message are never acceptable, and an
   unsolicited inbound caller is not an authenticated administrator. The
   administrator identifies the recipient from pre-existing records.
   Invitation possession, words, request fields and caller ID are not identity.
6. The target displays only its target-to-provisioner three-word group first.
   The recipient reads those words and the administrator types the complete
   group locally. Only an exact match records the provisioner-side confirmation
   and reveals its reverse-direction group. The administrator then reads that
   group and the recipient types it locally; only an exact match records the
   target-side confirmation. There is no `YES`/`NO` shortcut and neither UI
   displays the words it expects the human to enter. A submitted mismatch is
   terminal, produces no per-position hint, and cancels the invitation. Empty
   input creates no confirmation and leaves the exact request pending. Each
   speaker says the word and spells its first four letters, or the whole word
   when shorter. A homophone or uncertain word is a mismatch.
7. Each local confirmation records the exact full transcript digest in
   protected tentative state. It never approves a different invitation,
   request or regenerated identity. Administrator approval, a downloaded
   response and a relay claim cannot substitute for target-local confirmation.
8. After the normal multi-target approval checks and provisioner-side phrase
   confirmation, the offline provisioner creates the existing signed
   deployment response encrypted to the target's retained one-request
   recipient. The signed response must additionally bind the exact invitation
   digest, encrypted-request digest, full transcript digest, and the digest of
   the complete approved relay/connector/client request set. The courier
   uploads it.
9. The target may download the response before confirmation, but must not
   decrypt into active state or activate it until confirmation exists. It then
   performs every ordinary apply, monotonic-floor, anchor and publication
   check. After activation, it performs a live carrier-only probe through the
   public relay, completes inner mTLS and exact connector authorization, causes
   the connector's build-fixed `tcp4 127.0.0.1:22` dial, and receives the
   authenticated protocol READY marker. Only then may the user interface report
   `READY`. This probe performs no SSH host-key or user authentication.
10. Successful activation consumes the request in target-local monotonic state
    and removes its one-time response identity. After the authenticated carrier
    probe, the client durably records a receipt bound to the exact installed
    runtime and active response, asks the relay to consume its slot as
    best-effort hygiene, then locally destroys the exchange session, retained
    response, invitation workspace and mailbox capabilities. A malicious relay
    cannot veto that local cleanup. A redacted root-only `READY` receipt remains
    so restart can report the result without retaining mailbox authority.

Closing, choosing `later`, and resuming setup must reuse the same tentative
state, exact request ciphertext and phrase. Regeneration requires an explicit
cancel operation and a new invitation.

## Six-word comparison

The phrase is a short authentication string, not a secret, credential, seed,
or proof of a human's identity or physical presence. The malicious relay sees
the public invitation and encrypted request but normally lacks the exact signed
request plaintext needed to calculate the words. A compromised endpoint or an
attacker who controls an invitation may know them anyway. The independently
established procedure authenticates both humans; the words only compare the
machine transcripts.

The full transcript digest is:

```text
SHA256(
  "OwnTransit enrollment transcript v1\0" ||
  u32be(len(invitation)) || exact_signed_invitation ||
  u32be(len(request))    || exact_signed_request_plaintext ||
  u32be(len(ciphertext)) || exact_encrypted_request_ciphertext
)
```

The direction-specific views are:

```text
target_to_provisioner = SHA256(
  "OwnTransit enrollment target-to-provisioner words v1\0" || transcript_digest
)
provisioner_to_target = SHA256(
  "OwnTransit enrollment provisioner-to-target words v1\0" || transcript_digest
)
```

The first 33 bits of each view become three big-endian 11-bit indices in the
frozen 2,048-word list. The canonical six-word array stores the three
target-to-provisioner words first and the three provisioner-to-target words
second. One group alone is only a 33-bit comparison; the target-first gated
ceremony requires both groups for the complete 66-bit targeted comparison. The
protocol never treats either number as key entropy.

The durable confirmation binds the complete 256-bit transcript digest, not the
six displayed words. The words are only its human comparison view. They are
not credentials and must not be logged, pasted, screenshotted, or sent to
support. The full digest, never a word group, gates issuance and activation.

The phrase therefore binds, at minimum:

- invitation schema, ID, expiry and offline signature;
- deployment verifier and issuer pins;
- release, platform, role, route and connector claims;
- both request-encryption and response-encryption recipients;
- mailbox identifier and capability commitments;
- installation ID, CSRs, request nonce and request sequence; and
- the exact signed request plaintext and exact ciphertext presented to the
  offline provisioner.

The phrase must never be truncated to digits, accepted partially, sent through
the relay as an authority, used as a password, or used to derive an encryption
or signing key. Phrase construction and the frozen word list require external
cryptographic review and byte-exact test vectors.

## Relay exchange contract

The exchange is a distinct versioned surface, not a new controller:

- two opaque slots per invitation: request and response;
- compile-time body, slot, memory, connection and lifetime bounds;
- no listing, search, account, target name, remote policy or issuance API;
- exact-byte idempotent retry, never silent overwrite;
- authorization in non-logged headers or framed fields, never a URL or query;
- one canonical credential-free `wss` endpoint with implicit port 443; literal
  IPs, user information, queries, fragments and non-public-shaped hostnames are
  rejected before dialing;
- generic responses that do not disclose whether another mailbox exists;
- no content logging, crash dump, analytics payload, persistent database, or
  backup;
- in-memory expiry by default, so a relay restart merely requires an
  exact-byte re-upload; and
- independent rate and reverse-proxy limits so exchange traffic cannot consume
  the SSH carrier's entire resource budget.

A fresh route uses an authenticated relay image in temporary exchange-only
mode before any endpoint deployment exists. The command accepts exactly one
canonical relay-visible allocation-credential SHA-256, binds the fixed
packaged address, and routes only the exact `/connects/enrollment` request to
the same bounded handler. It has no carrier service, runtime or authority
mount, endpoint key, issuer, signer, persistent mailbox, route lookup, or
target selector. `/connects`, path/query aliases, and every other request are
rejected.

The exchange-only process must remain up until the first client has fetched
and durably applied the target-bound response. The expected carrier probe then
reports `SETUP SAVED — NOT READY`. The operator stops exchange-only mode,
applies the relay and connector responses, starts the full relay and connector,
and the client runs `owntransit setup --resume` to perform the live
authenticated carrier proof. Mailbox loss at that cutover is harmless because
the response is already retained locally; relay-side cleanup is best-effort.

These rules reduce accidental exposure and third-party abuse. They do not make
the relay honest. Endpoint cryptography and local state remain authoritative.

URL validation alone is not SSRF protection. The courier is a
dedicated unprivileged process with redirects and ambient proxy settings
disabled. On every dial it must resolve all addresses and reject private,
loopback, link-local, multicast and otherwise non-global results, then verify
the connected peer address against the same rule. DNS rebinding or a changed
answer must fail closed.

The relay may observe source addresses, timing, padded size class and
request/response correlation. It may delete, delay, duplicate, reorder,
cross-wire or replace blobs and lie about delivery. Those actions must produce
only a retry, a verification failure, or denial of service. Cross-target age
decryption, invitation/request bindings, deployment signatures, monotonic
state and local tombstones must reject every attempted substitution or replay.

## Failure behavior

- A word mismatch, partial match, reverse-half disclosure before the first
  group matches, or wrong speaking order cancels the invitation and activates
  nothing. Deferring the prompt leaves the exact request pending and also
  activates nothing.
- A stolen invitation, correct words or successful transcript comparison with
  the wrong human provides no issuance authority.
- A changed invitation or request produces a different phrase and requires a
  new comparison.
- Garbage or a response for another request remains bounded and fails before
  state publication.
- Expiration cannot be extended by the relay or by local clock rollback beyond
  the authenticated lifecycle policy.
- Pending, transcript-confirmed and response-verified sessions cannot advance
  after their invitation/request expiry. An already committed `Applied — NOT
  READY` session may revalidate its retained artifacts at the originally
  recorded verification time solely to reconcile the exact anchored active
  response and perform a current live carrier proof; this grants no new
  enrollment authority.
- Courier compromise exposes only ciphertext and limited mailbox capabilities.
- Provisioner or issuer compromise remains a route-authority compromise and is
  outside what the exchange can repair.
- Endpoint compromise can falsify the displayed phrase and is handled by
  release authentication, host security and recovery—not by trusting the
  relay.

## Release and assurance status

The in-repository implementation includes strict schemas and bounds, frozen
phrase vectors, crash-safe state transitions, root-protected transcript
confirmations, age-encrypted padded requests, exact signed response and
three-target request-set binding, an online courier with no offline signing
keys, hostile mailbox replay/cross-wire/restart tests, a complete guided client
transition test, an authenticated carrier-only READY proof, and deterministic
local retirement after READY.

The implementation intentionally cannot certify its own human procedure or
all platform behavior. The 0.1.0 artifact result requires native execution, an
authenticated read-only macOS launcher check with no system mutation, and exact
signed connector install/activation on both Linux architectures with enabled-service restart,
actual host reboot, direct host reacquisition, post-boot running/retrying,
binary-identity, systemd-confinement and no-listener checks. Its live result
separately proves SSH and SCP through the
deployed untrusted relay with the exact signed client and connector, using the
pre-existing operator-supplied client configuration and SSH key without macOS
system mutation and leaving those client inputs plus the deployed connector
configuration and endpoint credentials unchanged. Neither result claims a
candidate enrollment ceremony, macOS client installation or launcher
activation, macOS provisioner package lifecycle, Linux client, provisioner, or
relay package lifecycle, or clean-host state.
Enrollment source tests remain part of the source/security/publication result.
Broader clean-host install, resume, upgrade, rollback and recovery matrices
remain additional assurance. An independent review is
invited to challenge the phrase construction, phishing assumptions,
invitation theft and races, self-authenticating-verifier attempts, a malicious
relay that knows the words, transcript replacement, response cross-wiring,
cleanup interruption and false READY reporting.

OwnTransit 0.1.0 does not claim that independent cryptographic, application or
human-factors assessment. That is disclosed additional assurance, not a
missing setup path or authority granted to the relay.
