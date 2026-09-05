# Test OwnTransit 0.1.2

This is the **signed development preview**, installed separately from 0.1.0.
It is not a stable or production-qualified release. Keep another access path.
The three roles are client, public relay and private receiver/connector.

## 1. Install and start the relay

On Linux amd64 or arm64:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- relay
```

Enter the full public URL at the visible prompt, such as
`wss://relay.example/connects`. If the server hosts several websites, that
hostname selects exactly which HTTPS site receives the route.

You can also pass the URL in the same installation command:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- relay wss://relay.example/connects
```

Setup detects Docker or Podman, installs Podman through a supported package
manager if needed, loads the authenticated image, creates its private state,
runs the relay as an unprivileged container user, and enables the systemd
service. You do not create an operating-system account or type container commands.

It first checks existing HTTPS routing. If routing is missing, it selects the
matching Nginx, Apache or Caddy site, keeps a private backup, adds only the exact
`/connects` route, validates the server configuration and reloads it. Other sites
and locations are retained. The relay's host port is `127.0.0.1:9087`.

Only an identified OwnTransit relay is eligible for automatic replacement.
Its previous state is preserved; an existing paired relay's keys are adopted.
If the public WebSocket check fails, setup stops its new service and restores
the previous relay and any site configuration it changed. A rollback error is
reported explicitly.

Supported managed setup requires Linux with systemd and an existing HTTPS site.
It understands standard local Nginx/Apache/Caddy layouts and can reuse a correct
route provided by any other proxy. Custom layouts, conflicting services and a
domain without an HTTPS site are reported without silently rewriting them.
No SSH, website content, database, account or provider firewall settings are edited.

If the package is already installed, the same setup is available directly:

```sh
sudo owntransit-relay-preview setup
```

Keep the relay running before setting up either endpoint.

## 2. Install the receiver on the SSH server

These commands work on both supported Linux architectures, including a 64-bit
Raspberry Pi:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- connector
sudo owntransit-connector-preview pair setup
```

Enter your relay URL, for example `wss://relay.example/connects`.
Setup initializes the receiver and enables its installed systemd service for
reboot. It displays a **public receiver ID** and a **private pairing code**.

Give only the public ID to the relay. Keep the private code for your intended
client, transferring it through existing authenticated SSH/local-console access.
It expires after 24 hours and authorizes one device, not a human identity.

The receiver's local authority process keeps signing, age and issuer keys in
root-private state. Its separate network worker runs as UID/GID 65534 without
supplementary groups, dumps or permission to read the authority store. All
network connections are outbound. Its SSH target is fixed to
`tcp4 127.0.0.1:22`; SSH itself must already be configured by you.

## 3. Register the receiver at the relay

In another relay terminal, replace `RECEIVER_ID` with the public ID:

```sh
sudo owntransit-relay-preview register RECEIVER_ID
```

Copy the printed relay code to the client. The running receiver picks up its
registration automatically; you do not paste that code back into the receiver.

## 4. Install and pair a Linux client

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- client
owntransit-preview pair setup
```

Run setup as your ordinary user. It asks for the relay URL, relay code and
private receiver code. Secret input is not echoed; never put codes in shell
arguments, environment variables, logs or support tickets.

If the initial exchange was interrupted, keep the exact saved request:

```sh
owntransit-preview pair resume
```

### Apple-silicon macOS client

Download `owntransit-preview-0.1.2-darwin-arm64.tar.gz` from the
[0.1.2 development release](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.1.2).
Verify its digest against the signed `DEVELOPMENT-SHA256SUMS`, then extract it.
The archive contains the client, capsule identity, checksums and license notices.
It does not alter your Mac or require Apple notarization.

Run the extracted `./owntransit pair setup`. Use that executable's absolute
path in your ProxyCommand, or put it on your own PATH under `owntransit-preview`.
Intel macOS is outside the supported matrix.

## 5. SSH normally

Use your existing SSH user, private key and independently verified host key:

```sh
ssh -o 'ProxyCommand=owntransit-preview pair proxy' USER@SSH_ALIAS
scp -o 'ProxyCommand=owntransit-preview pair proxy' ./file USER@SSH_ALIAS:./
```

`SSH_ALIAS` is your operator-owned SSH destination/host-key alias, not a
relay-selected target. OwnTransit never selects SSH keys, creates accounts,
edits SSH configuration or changes forwarding policy. Normal SSH options
including `-i` and `-L` remain yours. Proxy stdout contains SSH bytes only.

## Normal recovery versus a security alarm

**Ordinary restart or network trouble:** keep the same state. The receiver's
installed service restarts and retries. New client connections use retained
identities, fresh mTLS and authorization leases. Expired operational credentials
refresh automatically. Missing packets, failed authentication or a hostile
relay do not create a permanent alarm or reset trust. A broken carrier can
disconnect the current SSH session; it is never replayed into a new carrier.

Check the receiver without changing its state:

```sh
sudo systemctl status owntransit-connector-pair.service --no-pager
sudo owntransit-connector-preview pair status
```

**Explicit local security alarm:**

```sh
owntransit-preview pair alarm
# Or on the receiver:
sudo owntransit-connector-preview pair alarm
```

This permanently disables that pairing, blocks renewal and closes local
workers. There is no flag-down or unlock operation. A failed shutdown
acknowledgement can still leave the terminal alarm recorded. Remote cutoff is
bounded by the remaining lease (at most 60 seconds) plus OS shutdown latency;
the relay may suppress an immediate notification.

Recovery is deliberate: retain the alarmed state for inspection, rebuild with
fresh OwnTransit state and identities on both endpoints, register the new
receiver ID, and repeat pairing. Never restore the old alarmed state as an
unlock shortcut. This does not rotate or repair your independently managed SSH
keys/accounts, retract delivered bytes or terminate SSH-started jobs.

The current terminal-alarm policy uses strict local schema v2. Earlier
clearable-lock development state is rejected rather than silently converted.

## What installation changes

Only the requested role is installed below `/opt/owntransit-preview/0.1.2`,
with a separately named `*-preview` alias. An exact reinstall is idempotent;
an unmanaged conflicting file is not overwritten. The connector installer
creates a disabled service; only your explicit `pair setup` enables it.

The default receiver state is `/var/lib/owntransit-pair`. Client state is
`owntransit-pair` below the OS user configuration directory. Advanced
`pair init`/`pair serve`/client commands accept `--state ABSOLUTE_PATH`;
the installed receiver service deliberately uses its fixed default state.

The old 0.1.0 install and credentials are preserved. Do not use its installer
or enrollment workflow for this preview. Relay setup can explicitly migrate an identified older relay and configure
only the selected site's route. No account management, SSH or provider firewall
changes are performed.

## Verification and assurance

The Linux bootstrap pins the existing distribution public key, verifies the
`owntransit-development-v1` SSHSIG over the exact development inventory, and
checks the selected archive before root extraction/execution. The initial curl
script itself still trusts GitHub delivery. Independent manual verification uses
the already trusted distribution key; a key fetched beside an archive does not
establish independent trust.

The source includes integrated WebSocket, dual-mTLS and SSH exec tests,
normal restart/renewal tests, terminal alarm and fresh-rebuild tests, and
negative identity/profile tests. Disposable installer tests cover Linux amd64
and arm64. Signatures authenticate bytes; they do not claim independent
security assessment, a new-machine lab or production qualification.
