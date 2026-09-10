# OwnTransit

**Your SSH. Your keys. Untrusted transit.**

Connect two private computers over SSH when neither can accept a public
connection. Both connect outward to your public relay. OwnTransit adds separate
end-to-end encryption: even a compromised relay must not read the stream or
impersonate either endpoint. Keep your existing SSH keys and login rules.

| Machine | Install here | Purpose |
|---|---|---|
| Public VPS | Relay | Carries encrypted traffic |
| Private SSH machine | Connector / receiver | Delivers the authenticated stream to local SSH |
| Your laptop or workstation | Client | The computer you connect **from** |

The client is **not** installed on the VPS. SSH itself must already work on the
receiving machine. OwnTransit does not configure SSH accounts, keys or permissions.

## Quickstart

Install **0.6.1** on each role. Linux supports amd64/x86_64 and arm64/aarch64.
The Mac client supports Apple silicon.

Run one block at a time. When a program asks a question, answer it—do not paste
the next shell command into its prompt.

### 1. On the public VPS

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- relay
```

Enter your real public URL, such as `wss://relay.example/connects`
(**example only**). A new relay needs an existing HTTPS site on the VPS.

The URL selects the matching local relay. You do not need to know its instance
name. For a recognized older manual installation, setup shows what it will
replace and asks for confirmation. It preserves the relay keys, URL and existing
website route, then removes the superseded service/container after verification.
Other relay instances and websites are not selected for cleanup.

Wait for setup's **NEXT** instruction. Keep this terminal for step 3.

If your access policy returns HTTP 403 to the VPS itself, setup may report
**local verification only**. It does not weaken that policy or claim public
reachability. Receiver/client setup from an allowed network checks the public
path as part of the normal flow below.

### 2. On the private machine running your SSH server

Install the receiver:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- connector
```

For a **new pairing**, run:

```sh
sudo owntransit-connector-preview pair setup
```

Enter the same relay URL. Setup starts the receiver and enables it for reboot.
It prints two things:

- A complete approval **command** for the VPS.
- One private, 56-character `otpair2.` **code** for your client.

Keep the private code away from the VPS, logs and support tickets. Transfer it
through your existing authenticated SSH or console access.

**Lost the code?** No memorising or rebuilding is needed while it is unused and
unexpired. On this receiving machine, run the exact `pair code --receiver-id …`
command printed by setup or VPS approval. `sudo owntransit-connector-preview pair list`
also prints a retrieval command for each local tunnel.

**Already paired?** Installation and repeated setup preserve your pairing.
Use the printed restart instruction for an upgrade. Creating new identities
requires explicit `pair setup --replace`; a paired receiver asks for confirmation.

### 3. Back on the VPS: run the printed approval command

Copy the **whole command from receiver setup**, including its URL and public ID.
Its shape is:

```sh
sudo owntransit-relay-preview approve --url wss://relay.example/connects RECEIVER_ID
```

Do not type the example domain or placeholder above. The real command prints
**Receiver approved — UNDER CONSTRUCTION**. There is no VPS code to copy.

The relay step is complete, not the tunnel. Its output tells you how to retrieve
the private code on the receiving machine and continue on the client.

### 4. On your client computer

**Linux client** — install:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- client
```

Then, as your ordinary user without sudo:

```sh
/usr/local/bin/owntransit-preview pair setup
```

**Apple-silicon Mac client** — install without sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-macos.sh | sh -s -- client
```

Then:

```sh
"$HOME/.local/bin/owntransit-preview" pair setup
```

Enter the relay URL and paste the private `otpair2.` code from step 2.
That is the **only code** the client needs. Public routing data is fetched
automatically and the receiver's offer is authenticated before its keys are used.

### Connect

Client setup checks the actual authenticated end-to-end carrier and the
receiver's fixed local SSH socket before printing **TUNNEL READY**. Pairing alone,
relay approval and a local status report are not that proof. If the check fails,
the pairing stays saved and setup prints the exact retry command.

After a successful check, run the SSH command printed by the client. Replace
`USER@SSH_ALIAS` with your SSH user and independently verified host label:

```sh
ssh -o 'ProxyCommand=owntransit-preview pair proxy' USER@SSH_ALIAS
```

On Mac, use the printed command: it includes the exact executable path.
Your normal SSH options, including `-i`, `-L`, SCP and SFTP, remain yours.
`Permission denied (publickey)` means SSH needs an authorized key—not another
OwnTransit pairing code.

## Upgrades, more tunnels and recovery

- **Upgrade:** rerun the same installer for the local role. On the VPS, enter
  its existing URL. On a paired receiver, use the printed restart command.
- **What now?** Run `pair next` on the endpoint you are using. It prints exact,
  state-specific commands for that local tunnel without changing identities.
- **Lost code:** the receiver's `pair code` command retrieves the same unused,
  unexpired code. The relay never receives it. Codes created by 0.6.0 or earlier
  were not retained; the recovery command explains the one-time explicit rebuild.
- **More tunnels:** use `pair setup --tunnel NAME`. Each client–receiver pairing
  has its own keys and alarm state. Multiple pairings can share one relay or
  reach the same SSH machine.
- **Interrupted client pairing:** use `pair resume` with the same tunnel/state.
  Keep the saved request; do not regenerate keys to solve a network failure.
- **Inspect:** use `sudo owntransit-relay-preview list` on the VPS or the
  `pair list` subcommand of your endpoint executable.
- **Security alarm:** `pair alarm --tunnel NAME` permanently disables that pairing.
  Recovery requires deliberate fresh pairing; ordinary outages never trigger it.

The [full installation guide](PAIRING_INSTALL.md) covers migration, explicit
instance selection, upgrades, named tunnels, uninstall and SSH/SCP examples.
See [setup recovery](SETUP_RECOVERY.md) for lost/expired codes and interrupted setup.

## Security boundary

Each endpoint has an outer TLS 1.3 mutually authenticated connection to the
relay. Inside those two connections, the endpoints establish an independent
end-to-end TLS 1.3 mutually authenticated stream. OpenSSH runs inside it with its
own encryption and host/user authentication.

The relay, its host, keys and reverse proxy are assumed compromised. They can
observe addresses, timing and traffic sizes or deny service. They must not read
the inner stream, authorize an endpoint or choose the receiver's destination.

The receiver dials only build-fixed `tcp4 127.0.0.1:22`, after peer authentication
and fresh session-bound authorization. Reconnects and authorization renewal use
retained identities without user prompts. Interrupted SSH streams are not replayed.

An explicit local alarm survives restart and cannot be cleared to revive the old
pairing. A malicious relay can suppress its notification; peer cutoff is bounded
by the remaining authorization lease (at most 60 seconds), plus scheduling and
shutdown latency. It cannot retract delivered bytes or guarantee that SSH-started
jobs stop.

OwnTransit is an SSH byte carrier—not a VPN, controller, DNS layer, dashboard,
identity provider or general-purpose proxy. It never edits SSH keys, accounts,
`authorized_keys`, client/server configuration or forwarding rules.

The initial curl installer trusts GitHub's HTTPS delivery; downloaded archives
are then signature-verified. See [installation trust](SECURITY.md#installation-trust).
No Apple signing subscription is required; the Mac client is not notarized.

Release checks cover source/security, supported-platform tests, installer and
migration fixtures, authenticated artifacts and a brief end-to-end check.
**Independent security certification, pristine-host qualification and extended
soak testing are not claimed.** Keep independent SSH or console recovery access.

## Further reading

[Architecture](ARCHITECTURE.md) · [Security and private disclosure](SECURITY.md) ·
[Pairing protocol](RECEIVER_PAIRING.md) · [Compatibility](COMPATIBILITY.md) ·
[Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Provenance](PROVENANCE.md)

The immutable [0.1.0 release](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.1.0)
uses an older administrator-led setup. Its [legacy guide](INSTALL.md) is for that
release only; do not mix its credentials or instructions with this flow.

OwnTransit is licensed under the [Apache License 2.0](LICENSE).
