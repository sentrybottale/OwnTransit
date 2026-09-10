# One-code pairing (0.5.0 protocol; 0.6.1 local recovery)

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

Pending receivers retain a root-private **public** `pair-offer.json` sidecar.
The private code is never placed in that public sidecar or given to the worker.
Versions 0.5.0–0.6.0 displayed the private code once without retaining it.
Since 0.6.1, new one-code setup additionally retains the exact canonical private
code in `authority/private-pairing-code.v1`, mode 0600 under the private authority
root. It is not part of any snapshot, worker RPC, advertisement or relay request.

Explicit local `pair code` retrieval requires the authority owner and checks the
current policy, pending attempt, exact stored code digest, receiver/attempt IDs,
advertisement, origin and expiry. The public offer must match too. It cannot
recover a code from an older uncached attempt, extend validity, return a spent
code, clear an alarm or generate new identity. Public receiver-ID lookup is only
a bounded local selector; it gives no remote reading or enrollment authority.
Claim/cancellation/retirement commit their existing denial state before attempting
to unlink the cache. Even a retained or restored cache cannot revive authority;
secure erasure from storage or backups is not claimed. Expiry denies retrieval
and pairing without a background secret-cleanup process.

Candidate setup completes both sidecars before retiring the old pairing. Existing
strict authority, receiver and client record schemas and all wire formats remain
unchanged. Older binaries ignore the optional private cache; state still prevents
newer code from revealing it after an old binary consumes the attempt. A paired
tunnel never depends on either spent sidecar.

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
