# One-code pairing (0.5.0)

The user copies one private code from the receiving SSH machine to the client.
The VPS only approves a public receiver ID through its existing local privileged
control path. Approval is retained: removing it would allow strangers to consume
the relay's bandwidth. No administrator, additional identity service, clipboard
integration or third-party rendezvous service is introduced.

## Authentication before secret disclosure

The receiver creates the existing signed advertisement and 256-bit random
one-use pairing secret. `otpair2.` encodes that secret plus a four-byte typo
checksum using canonical unpadded base64url: exactly 56 characters. The checksum
is not an authenticator and does not reduce the secret to a PIN.

The separate public offer contains a secret-derived locator, the exact signed
advertisement, and a full HMAC-SHA256 over those advertisement bytes. Independent
fixed domains separate locator, MAC and checksum derivations. The relay sees
only the locator, advertisement and MAC; it never sees the secret or short code.

The client derives the locator locally and fetches the offer from the exact
operator-selected HTTPS/WebSocket origin. It verifies the full MAC and locator
before interpreting recipient keys, then verifies the existing advertisement
signature, profile, expiry and exact origin. A self-signed attacker advertisement
without the correct MAC is rejected before creating local client state or
sending any secret-bearing message. A hash-only locator would not provide this
protection and is deliberately insufficient.

After verification, the client reconstructs the exact original canonical
`otpair1.` bytes locally and uses the unchanged pairing exchange. It fetches only
the already-approved registration and matching relay server information. The
existing exchange independently checks the exact advertisement digest again.
One-use claim/spent-code enforcement, recipient encryption, peer authorization,
inner TLS, alarms and fixed SSH target are unchanged. A stolen private code can
still authorize its holder before the intended client; use an independently
authenticated transfer and never send it in support tickets.

## Versioned, bounded public transport

The offer schema is `owntransit.receiver-offer.v1`. Its canonical JSON has the
ordered fields `schema`, `locator` (lowercase hex), `advertisement` and `proof`
(unpadded base64url), followed by one newline. Maximum advertisement size is
128 KiB and maximum encoded offer size is 192 KiB; proof and locator are 32 bytes.

Explicit OTR2 extension kinds preserve all existing kinds and authenticated
profiles:

| Request | Kind | Payload | Reply |
|---|---:|---|---|
| Offer support | 9 | Exact schema name plus newline | 0x87, same profile |
| Publish offer | 10 | Version 1, big-endian u16 token length, u32 offer length, token, offer | Existing empty OK |
| Fetch offer | 11 | Version 1, 32-byte locator | 0x88, canonical offer |

Headers, lengths, unknown fields, encodings and kinds are checked before use.
Existing pre-auth deadlines, concurrency/rate admission, advertisement quotas
and expiry apply. Offers reuse the bounded advertisement store, not a new
unbounded mailbox. Exact repeats are idempotent; conflicting locator/ad/proof
bindings fail. A relay can deny service or expose traffic metadata, not mint
endpoint authority or choose the receiver's SSH destination.

## Restart and compatibility

Pending receivers retain only a root-private **public** `pair-offer.json`
sidecar. The private code is displayed once, not saved in this sidecar or given
to the unprivileged worker. Candidate setup creates it before retiring the old
pairing. Existing strict authority, receiver and client record schemas remain
unchanged; an existing paired tunnel ignores spent or expired offers.

Until paired, a receiver republishes its offer after relay/network restart. If
already approved, it may restore only the exact unexpired relay token previously
issued to that receiver/route/admission root. This public path cannot mint,
renew or extend admission. Repeating identical VPS approval retains its existing
valid token and expiry. Existing authenticated runtime renewal is unchanged.

New setup explicitly selects the offer extension. The receiver probes support
in its unprivileged discovery worker before preparing or retiring identities.
An older relay rejects the operation; failure does not trigger automatic
downgrade, reset trust, change origin or generate a second client request.
`pair setup --legacy-codes` / `pair init --legacy-codes` deliberately select
the old two-code setup; only that mode uses the old `register` output.

Upgrade the relay and endpoints to use one-code setup. Existing completed
pairings continue without re-pairing. An older pending legacy attempt cannot
be converted without its private secret, which was intentionally not retained;
explicit new receiver setup creates a fresh attempt. Interrupted client pairing
uses `pair resume` and its exact saved request. Rolling the binary back does
not reinterpret a short code as legacy input or unlock an alarm; older software
may serve completed compatible pairings, but new pending offer lookup requires
an offer-capable relay and receiver. Whole-state rollback and host root
compromise remain outside this guarantee.

## Required regression evidence

Cover deterministic public vectors, every MAC/locator-byte tamper, a malicious
relay replacing the recipient advertisement, wrong origin/profile/expiry,
malformed/oversized input, old/new mixed setup, no-state-on-failure, repeated
approval, pending receiver/relay restarts, complete SSH with both TLS boundaries,
and native Linux/macOS hidden-input PTYs including paste, cancellation and
terminal restoration. Repository tests and agent review are not independent
external security certification.
