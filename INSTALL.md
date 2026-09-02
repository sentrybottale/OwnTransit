# Install OwnTransit

> [!WARNING]
> OwnTransit 0.1.0 is currently a candidate for Apple-silicon macOS and Linux
> amd64, not an official stable publication. The repository can build a signed,
> installable candidate handoff, but use it only for qualification unless its
> exact signed qualification record is independently verified and reports every
> hard release gate as passed. A Git checkout, unsigned local build, or checksum
> downloaded beside an archive is not an authenticated package. Independent
> external security certification is not claimed. Keep an operator-owned
> alternative access and recovery path throughout qualification and canarying.

## The recipient experience

This section is for the practical IT operator who installs laptops, printers
and servers and already knows how to use SSH. They should not need to
understand OwnTransit relays, certificates, routes, JSON, systemd or PKI.

After the program is installed, the complete v1 flow is one setup
command, one short verified call, and then SSH:

```sh
owntransit setup ~/Downloads/office.otinvite
# Then run the exact SSH command from IT, for example:
ssh office-computer
```

The setup command guides the word comparison and waits for the transport
check. Everything below explains that one guided step and what to do when it
stops safely; it is not extra cryptographic homework for the recipient.

Before you begin, you need four things:

1. one authenticated package method for your computer;
2. one file whose name ends in `.otinvite` from your OwnTransit administrator;
3. one already-known OwnTransit administrator and a procedure that was
   established before the invitation and authenticates both of you; and
4. either an exact one-shot SSH command, or an SSH alias that IT has already
   installed, to use afterward.

The OwnTransit administrator must be a different, already-known person:
self-approval is not supported. They do **not** need your password or SSH
private key. They must also identify you using the organization's existing
procedure and records; they must not rely on the invitation, safety words,
caller ID or a phone number you provide during setup. Never use contact details
from the invitation, relay, error page, email containing the invitation or an
unsolicited caller.

### 1. Install an authenticated release

OwnTransit deliberately has no `curl | sh` installer and this source tree is
not a trusted package merely because it is on GitHub. A release must provide
the signed manifest, monotonic release policy, detached signatures, exact
digests, SBOMs and license evidence described in
[scripts/release/README.md](scripts/release/README.md).

For Apple-silicon macOS, the no-fee distribution lane is a signed source
archive and rendered Homebrew formula for the normal unprivileged frontend,
plus the separately authenticated native handoff that creates the protected
runtime and fixed launcher. Once the canonical tap publishes 0.1.0, the
frontend command is:

```sh
brew install sentrybottale/owntransit/owntransit
```

Homebrew alone does not activate the protected runtime and must never be run as
root. The release-specific native handoff is mandatory. After independently
authenticating the handoff trust and its signed outer `SHA256SUMS`, copy and
extract it into the release instructions' protected root-owned location. On
macOS the handoff supports the `client` and `provisioner` roles.

On Linux amd64, the authenticated native handoff supports `client`,
`connector`, `relay`, and `provisioner`. Both platforms use the same short
entry point:

```sh
sudo /ABSOLUTE/NATIVE/packaging/scripts/install.sh --bundle /ABSOLUTE/NATIVE --assets /ABSOLUTE/assets --trust /ABSOLUTE/trust --role client --client-user LOCAL_USER
```

Use `--role connector`, `--role relay`, or `--role provisioner` without
`--client-user` where that role is supported. The command must run as root and
the native bundle, signed assets, and independently authenticated trust must be
three separate canonical, root-owned trees that are not group- or
world-writable. The entry point verifies the outer asset signature again,
verifies the native checksum signature, derives the exact release ID and
selected artifact hashes from those authenticated records, and then executes
the fail-closed platform installer. It does not decide that the supplied trust
directory is trustworthy: the release instructions must identify those keys
through an independent channel first.

The protected staging rule is intentional. Do not run any installer directly
from a user-writable checkout, download, or extraction directory, and do not
replace the independent trust check with a checksum downloaded beside the
archive. The entry point never downloads, imports trust, edits SSH, or starts a
service.

The repository intentionally does not pretend that an unsigned local build is
an official installation. Connector and relay installation also deliberately
leave their services disabled; enabling each installed service is a separate,
explicit operator action after its local enrollment is complete.

Do not use a command from an advertisement, direct message, search result, or
relay error page. Never use a command that downloads a script and immediately
runs it as root.

### 2. Open the invitation and perform the safety check

Point the CLI at the invitation file. The intended entry point is:

```sh
owntransit setup ~/Downloads/office.otinvite
```

The initial command requires the invitation path. A later resume uses retained
tentative state and therefore needs only:

```sh
owntransit setup --resume
```

Before activation, `owntransit setup --cancel` terminally abandons the current
invitation. A new setup always requires a new invitation.

The client creates its OwnTransit private keys locally, sends an encrypted
request through the untrusted relay, and waits for approval. It guides a
target-first, two-way comparison. The exact UI is deliberately terse:

```text
Independently authenticate the administrator using your pre-established contact procedure.
Read these target words to the administrator: river april window
Only then type the three words the administrator reads back; press Enter to resume later:
```

There is no `YES` button. The administrator's screen reveals its three words
only after it accepts the three words read by the recipient. The recipient's
screen records its confirmation only after all three reverse-direction words
match. Both records bind the full 256-bit transcript digest; the six words
grant no authority by themselves.

Pressing Enter before submitting the administrator's group safely retains this
exact request for later. A submitted mismatch is terminal for the invitation,
activates nothing, and reports no correct word positions. Stop as well if the
other person reads their words first or if the contact procedure is not the one
you already trusted. The words are not credentials, a password, a wallet seed,
or an encryption key. Compare them only during the verified call; never paste,
message, screenshot, or send them to support. A homophone, uncertain spelling,
or remotely controlled screen is not a trustworthy comparison.

The authenticated package instructions must identify any expected **computer
privilege prompt** and exactly when it appears. OwnTransit must never display
its own password field or collect a computer administrator password, SSH
password, SSH private-key contents or SSH private-key passphrase. Stop on an
unexpected prompt.

After both confirmations, the command waits for approval and checks the
transport. Success is exactly:

```text
OwnTransit carrier READY; SSH was not attempted.
```

If setup was saved but the transport check failed, it reports:

```text
SETUP SAVED — NOT READY
```

`READY` means the OwnTransit transport check passed. It does not mean an SSH
login was attempted or succeeded.

If the command says **STOP**, stop and tell the OwnTransit administrator only
the short, secret-free support code displayed for that failure. Never send the
invitation, safety words, screenshots, keys or raw logs. Do not try to bypass
the error.

If the OwnTransit administrator is not immediately available, press Enter at
the first unanswered word prompt, or close the command before answering it. Run
`owntransit setup --resume` later; you do not need to find the original file
again. The same target-to-administrator words must appear. If they change,
cancel and stop.

### 3. Use SSH normally

Run the exact one-shot SSH command supplied separately by the OwnTransit
administrator. If IT already installed an SSH alias such as
`office-computer`, use:

```sh
ssh office-computer
```

An SSH private-key passphrase prompt at this point is normal: it belongs to
OpenSSH, not OwnTransit. OwnTransit transports SSH bytes but does not create or
change SSH users, passwords, keys, host-key policy, port forwards, or access
rules.

OwnTransit never edits `~/.ssh/config`. A config stanza that has merely been
sent to you, but not installed by IT, is not a ready-to-use alias.

That is the whole recipient workflow: install, point the CLI at one invitation,
compare three words in each direction, wait for `READY`, and use SSH. The
recipient never moves a request or response file.

If somebody else operates OwnTransit for you, stop here. The remaining sections
are for that administrator and security reviewers.

## What the OwnTransit administrator handles

The administrator, not the recipient, is responsible for:

- independently authenticating the OwnTransit release and its monotonic
  release policy;
- installing and enrolling the relay and connector;
- keeping the route authority and deployment signer offline;
- creating a target-bound invitation with the correct role, route, release,
  issuer pins, deployment verifier and relay information;
- using an untrusted network courier to move encrypted enrollment blobs between
  the relay mailbox and the offline provisioner;
- accepting the recipient's target-to-administrator words first, then revealing
  the reverse-direction words only after an exact match, over a previously
  trusted channel;
- authenticating the intended recipient from pre-existing operator records,
  never from invitation possession, words, caller ID or enrollment-supplied
  contact details;
- approving the request offline and returning its signed, target-encrypted
  response through the courier;
- verifying the carrier before declaring it ready; and
- supplying and supporting the separate OpenSSH command, account, key and host
  recovery path.

The relay is never an installation, enrollment, issuance, update, recovery, or
rollback authority. An invitation, key, release, or safety code accepted only
because the relay delivered it is invalid by construction. The administrator's
offline signer never needs a network connection.

### Fresh-route cutover

A brand-new relay cannot run its authenticated carrier before it has an
enrolled endpoint identity, but the first client response needs a mailbox. The
installed relay package therefore includes a temporary, non-enableable
exchange-only service. It runs the authenticated relay image with one
relay-visible allocation-credential hash and exposes only the bounded opaque
`/connects/enrollment` mailbox through the existing reverse proxy. It has no
carrier, runtime or authority mount, endpoint key, issuer, signer, persistence,
route lookup, or target selection.

Keep that temporary service running until the client has fetched and durably
applied its bound response and reports `SETUP SAVED — NOT READY`. Then stop it,
apply the relay and connector responses, start the enrolled full relay and
connector, and have the client run:

```sh
owntransit setup --resume
```

The resumed command performs the live authenticated carrier proof and reports
`READY`. Never stop the temporary exchange before the client reaches the
Applied state; its mailbox is intentionally memory-only. After apply, losing
the mailbox is harmless and cannot block local cleanup.

OwnTransit 0.1.0 performs this initial ceremony for exactly one relay, one
connector, one route, and one client. Adding a second client to an existing
route is not implemented; do not treat route rotation as client enrollment.

## The hostile-mailbox design

The client creates its OwnTransit private keys on the client machine. They
never leave it. That means an administrator cannot safely manufacture a
finished client identity in advance.

The invitation supplies signed but tentative public facts and one-time mailbox
capabilities. Its exact transcript becomes trusted only through the human
ceremony above. The client encrypts its signed request to a one-invitation
provisioner recipient. An online courier can fetch that opaque request for the
offline provisioner, then upload the signed response that is encrypted to the
client's one-request recipient. The client polls for that response and applies
it only after all ordinary enrollment checks pass.

The six safety words are a human view of a full SHA-256 digest over the exact
signed invitation, exact signed request plaintext, and exact encrypted request
ciphertext. Separate domain tags derive three target-to-administrator words and
three administrator-to-target words. The words bind all nonces and release,
role, route, connector, key, and signer claims carried by those exact bytes.
Only the full digest is durable authority; the words are never a PIN, password,
wallet seed, signing input, or key-derivation secret.

The relay sees the public invitation and encrypted request, but normally lacks
the signed request plaintext needed to calculate the words. The words still
must not be treated as secret or as proof of either person's identity: an
endpoint, an attacker-controlled invitation, or a compromised human device may
know them. The independently established procedure authenticates both humans;
the gated two-way words only compare their machine transcripts.

Mailbox identifiers and authorization capabilities must be independent random
values and must not appear in URLs or logs. Request and response slots are
bounded, expiring, one-write and non-listable. Endpoint state—not a relay
claim—enforces nonce consumption, replay tombstones and monotonic floors.

A fully malicious relay may still correlate timing and sizes, refuse storage,
delete either blob, return garbage, or replay an old blob. It cannot decrypt a
request or response, alter a transcript without changing its full digest,
forge the signed response, or make a response valid for another target. Any
substitution must also survive the gated human comparison. Its remaining power
is denial of service.

## Release and assurance status

The OwnTransit 0.1.0 candidate provides the SSH-only client, connector, relay,
offline provisioner, guided enrollment, authenticated package lifecycle, and
native installer paths described here. The tooling can build a signed
installable handoff for qualification. An official stable handoff must bind its
exact signed artifacts, release policy, SBOM and license evidence to an
independently verified signed supported-platform qualification record whose
hard gates all pass; this document does not assert that such a record exists.

Independent implementation review, penetration testing, clean-builder
reproduction, legal review, custody rehearsal, and environment canary results
are disclosed when available; OwnTransit 0.1.0 does not claim that external
certification. Those activities improve assurance but are not authorities
granted to the relay and are not substitutes for the signed installation
boundary.

## Product boundary

The client is an on-demand outbound-only process. The connector is an
outbound-only daemon whose production binary can deliver only to literal
`tcp4 127.0.0.1:22`. Neither private endpoint opens an OwnTransit listener or
needs a public address. Only the relay is publicly reachable.

OwnTransit owns only its binaries, endpoint credentials and local lifecycle
state. Bring a working OpenSSH setup and an out-of-band host recovery method.
An OwnTransit carrier proof is not an SSH login proof, and an SSH login is not
OwnTransit enrollment authority.

The detailed command and trust design is in
[OWNTRANSIT_SHIPPING_PLAN.md](OWNTRANSIT_SHIPPING_PLAN.md). Credential
lifecycle rules are in [CREDENTIALS.md](CREDENTIALS.md), the automatic hostile
exchange is specified in
[ENROLLMENT_EXCHANGE.md](ENROLLMENT_EXCHANGE.md), release mechanics are in
[scripts/release/README.md](scripts/release/README.md), and release and
assurance requirements are in [ROADMAP.md](ROADMAP.md).
