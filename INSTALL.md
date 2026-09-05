# Install OwnTransit

## Linux quick install

Client computer:

```sh
curl -fsSL https://raw.githubusercontent.com/sentrybottale/OwnTransit/f1eb0003ad49ff73617d3f3bea0b10f0da2f0a18/install-linux.sh | sudo sh -s -- client
```

Connector beside the SSH server:

```sh
curl -fsSL https://raw.githubusercontent.com/sentrybottale/OwnTransit/f1eb0003ad49ff73617d3f3bea0b10f0da2f0a18/install-linux.sh | sudo sh -s -- connector
```

That is the package installation. The same commands work on Linux
`amd64`/`x86_64` and `arm64`/`aarch64`; the installer selects the build,
downloads and verifies the exact 0.1.0 release, and removes its temporary
files. The client command uses the non-root account that invoked `sudo`; add an
explicit existing username after `client` only when running from a root
automation session.

Start a new login session before using the client. A fresh connector remains
disabled and stopped until enrollment; an update preserves its existing
service state. Package installation does not create SSH keys, edit SSH, or
enroll either role.

If a retry reports pending connector package recovery, do not delete its
`.intent` or `.restart` record. When the selected lifecycle is already stable
0.1.0, run `sudo /usr/libexec/owntransit/roles/connector/current/owntransitctl package-recover --role connector`, then retry the installer.

This quick path trusts GitHub to deliver the initial installer. The URL pins a
specific source commit; it does not authenticate a compromised GitHub delivery
channel. The independently authenticated/offline path remains available under
step 1 below; [installation trust](SECURITY.md#installation-trust) explains the distinction.
The bootstrap is a convenience script added after v0.1.0; the published
release binaries and their signatures are unchanged.

Existing `0.1.0-rc.*` role state cannot be upgraded in place to stable `0.1.0`.
The installer stops without erasing that state.

<details>
<summary>Release scope and pre-release upgrade limits</summary>

> [!WARNING]
> OwnTransit 0.1.0 is published for Apple-silicon macOS (`arm64`), 64-bit x86
> Linux (`amd64`/`x86_64`), and 64-bit ARM Linux (`arm64`/`aarch64`). Intel
> macOS is outside the 0.1.0 support matrix. Its exact signed qualification
> record has
> `schema=owntransit.qualification.v1`,
> `gate_set=owntransit-0.1.0-minimal.v1`, and overall `status=PASS`. That status
> requires zero unresolved Critical/High defects and all four bounded release
> results to pass. A Git checkout, unsigned local build, or checksum
> downloaded beside an archive is not an authenticated package. Independent
> external security certification is not claimed. Keep an operator-owned
> alternative access and recovery path throughout qualification and canarying.

OwnTransit `0.1.0-rc.*` packages were qualification artifacts and are not a
supported in-place upgrade source for stable `0.1.0`. Do not install stable
`0.1.0` over retained RC package state. The supplied uninstall commands are
intentionally non-purging: they preserve selectors, rollback anchors, receipts,
identities, credentials, and recovery state, so they do not turn an RC host
into a stable-install target. Use a different unused role state if exercising
stable installation on an existing host. A separately reviewed destructive RC
trust-reset followed by complete re-enrollment is not currently implemented.
Release qualification requires no new machine and makes no pristine-host
claim.

For 0.1.0, the bounded Mac result executes and version-checks the exact native
artifacts, authenticates and inspects the launcher, records its expected
fail-closed rejection, and performs no system mutation. The separate live
SSH/SCP path exercises the exact Mac client transport using the pre-existing
operator-supplied client configuration and SSH key, performs no Mac system
mutation, and leaves those client inputs plus the deployed connector
configuration and endpoint credentials unchanged; neither result qualifies
stable native macOS client lifecycle activation. The Linux
amd64 and arm64 results do qualify exact signed connector install/activation,
enabled-service restart, actual host reboot, direct host reacquisition, and the
connector running or retrying post-boot on existing hosts. Keep
independent access while canarying every installation.

</details>

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

The normal Linux commands are at the top of this page. To inspect the bootstrap
before running it, download that same URL to `install-linux.sh`, read it, and
then run `sudo sh ./install-linux.sh client` or `connector`.

<details>
<summary>Advanced: independently authenticated/offline handoff</summary>

<br>

The strict path does not treat a source tree as trusted merely because it is on
GitHub. A release must provide the signed manifest, monotonic release policy,
detached signatures, exact digests, SBOMs and license evidence described in
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

On Linux, the authenticated architecture-specific `linux-amd64` or
`linux-arm64` native handoff supports `client`, `connector`, `relay`, and
`provisioner`. The Linux names correspond to `x86_64`/`amd64` and
`aarch64`/`arm64` hardware respectively. All three supported
platform/architecture targets use the same short entry point:

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

The Linux provisioner role additionally requires the host kernel setting
`fs.protected_hardlinks=1`; installation and every later provisioner package
operation fail closed otherwise. On macOS, the protected provisioner release
tree stays mode `0750` and the installer publishes a distinct mode-`0755`
public copy—there is no directory-permission migration to perform manually.

The protected staging rule is intentional. Do not run any installer directly
from a user-writable checkout, download, or extraction directory, and do not
replace the independent trust check with a checksum downloaded beside the
archive. The entry point never downloads, imports trust, edits SSH, or starts a
service.

The repository intentionally does not pretend that an unsigned local build is
an official installation. Connector and relay installation also deliberately
leave their services disabled; enabling each installed service is a separate,
explicit operator action after its local enrollment is complete.

Do not use an installation command copied from an advertisement, direct
message, search result, or relay error page. Use the canonical repository or an
independently authenticated handoff.

</details>

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

### Reverse-proxy quota boundary

The supplied Nginx snippets deliberately rate-limit by
`$realip_remote_addr`: the address of the immediate TCP peer before the
[Nginx Real-IP module](https://nginx.org/en/docs/http/ngx_http_realip_module.html)
applies any request-carried replacement address. Do not substitute
`$remote_addr`, `$binary_remote_addr`, `X-Forwarded-For`, `X-Real-IP`, or
another request header. A shared host may have an overly broad RealIP policy;
that ambient policy must not let an Internet client select an OwnTransit quota
identity.

This boundary requires Nginx 1.9.7 or newer with `ngx_http_realip_module`. If
Nginx reports an unknown `$realip_remote_addr`, that build is unsupported for
these snippets; falling back to a rewritten address is not safe. Install both
snippets, verify the
complete candidate configuration with `nginx -t`, inspect `nginx -T` to ensure
the four OwnTransit per-peer zones retain the exact key, and only then perform
a graceful reload. The `*_per_peer` names intentionally do not reuse the
earlier `*_per_ip` shared-memory zones: Nginx rejects a live zone whose key
changes during reload.

Do not remove or rewrite host-wide RealIP directives as part of an OwnTransit
deployment. That could change unrelated website or control-panel behavior and
is unnecessary for this boundary. If another proxy or CDN connects directly
to Nginx, all clients using the same immediate proxy address share a per-peer
bucket. That conservative availability tradeoff is intentional; the global
virtual-server buckets remain an independent ceiling.

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

The OwnTransit 0.1.0 release provides the SSH-only client, connector, relay,
offline provisioner, guided enrollment, authenticated package lifecycle, and
native installer paths described here. The tooling can build a signed
installable handoff for qualification. An official stable handoff must bind its
exact signed artifacts, release policy, SBOM and license evidence to an
independently verified signed qualification record with
`schema=owntransit.qualification.v1`,
`gate_set=owntransit-0.1.0-minimal.v1`, and overall `status=PASS`. Its four
bounded results cover source/security/publication, release-signature
verification, supported-artifact execution on existing hosts, and live SSH plus
SCP through the untrusted relay using the exact signed client and connector.
The live path uses the pre-existing operator-supplied client configuration and
SSH key, performs no macOS system mutation, and leaves those client inputs plus
the deployed connector configuration and endpoint credentials unchanged.
The platform result executes the exact native binaries, inspects the relay OCI
archives and Darwin launcher, records the launcher's expected fail-closed
rejection, and performs no macOS system mutation. On Linux amd64 and arm64 it
also proves exact signed
connector install/activation, enabled-service restart, actual host reboot,
direct host reacquisition, post-boot running/retrying, binary identity, systemd
confinement, and absence of an
OwnTransit listener. It does not claim stable native macOS client lifecycle
activation, macOS provisioner package lifecycle, Linux client, provisioner, or
relay package lifecycle, or pristine-host qualification. The exact results are
published with [v0.1.0](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.1.0).

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
