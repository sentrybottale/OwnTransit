# Install and operate OwnTransit 0.6.1

This is the signed receiver-owned release line, installed separately from the
legacy 0.1.0 package/qualification profile. Keep independent recovery access.
Extended soak testing and independent security assessment are not claimed.
The three roles are client, public relay and private receiver/connector.

Use setup as the normal local user on the client, not root. This does not
restrict which SSH account you authenticate to on the receiving machine.

## Non-purging removal

The 0.6.1 Linux installer accepts the installed local role followed by
`--uninstall`, for example:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- client --uninstall
```

Use `connector` or `relay` on those machines. It removes only recognized 0.6.1
software; pairing and SSH settings remain. Relay keys, disabled unit
configuration, website routing and cached rollback images are intentionally
retained. Explicit reinstall/setup reuses that configuration. Modified units,
overrides or unrecognized package contents are refused rather than guessed.
The Mac installer prints its offline uninstall command; see the Mac section.

## 1. Install and start the relay

The 0.1.8 relay timer fix is retained in 0.6.1. Compatible clients, receivers and
pairing keys remain valid; do not re-pair. The 0.1.7 terminal-input fixes and
0.1.6 managed-container fixes are retained.

Setup supports real Docker and Podman inspection formats and explicitly
cleans up stopped managed instances during restart/upgrade. It does not depend
solely on the engine's auto-remove behavior and will not force-remove a running
or unrelated container. Old images remain available for rollback.

On Linux amd64 or arm64:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- relay
```

Enter the full public URL at the visible prompt, such as
`wss://relay.example/connects`. If the server hosts several websites, that
hostname selects exactly which HTTPS site receives the route.
Without `--instance`, setup selects the matching existing local relay by URL;
it no longer assigns every request to `default`. An explicit instance name
still refuses a URL belonging to a different instance.

You can also pass the URL in the same installation command:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- relay wss://relay.example/connects
```

Setup detects Docker or Podman, installs Podman through a supported package
manager if needed, loads the authenticated image, creates its private state,
runs the relay as an unprivileged container user, and enables the systemd
service. You do not create an operating-system account or type container commands.

It first checks existing HTTPS routing. If routing is missing, it selects the
matching Nginx, Apache or Caddy site, keeps a private backup, adds only the exact
`/connects` route, validates the server configuration and reloads it. Other sites
and locations are retained. The default relay's host port is `127.0.0.1:9087`;
named instances receive separate persistent loopback-only ports.

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

If the website returns HTTP 403 to requests from the VPS, setup can finish only
with a clearly labelled local-verification result after checking the exact local
route, running relay and identity. It does not claim public reachability or change
your access rules. Continue on the receiving machine and client from allowed
networks; their normal pairing verifies the public path. Other failures, including
TLS errors or the wrong relay identity, do not qualify for this result.

### Migrating an older manual relay

Run that same installer/setup command and enter the existing URL. For a
recognized manual OwnTransit service, setup displays the exact old unit,
container, state directory and port. Confirm the displayed migration.

Setup reuses the original keys and correct website route, completes the managed
instance records, verifies the new service and retires the superseded unit and
container. It can reconcile a recognized unused same-URL reservation without
replacing another relay. Existing paired endpoints keep their identities; a
pending legacy advertisement may need its public approval again after restart.

After migration, use the ordinary `approve --url` command printed by receiver
setup. No Podman/Docker command or private host-specific recipe is required.
An interrupted migration is recovered by rerunning the same setup; unknown
ownership or modified files are reported rather than deleted. The precise
supported layout and recovery contract are in [relay migration](RELAY_MIGRATION.md).

### Upgrading instead of pairing again

Run the same 0.6.1 installer for the local role. For the relay, use its existing
public URL: setup recognizes a known managed service, preserves its keys and
website routing, restarts the new immutable image and verifies the running image
and public protocol response. Failed cutover restores the old unit, selection
and enabled/running state. An interrupted upgrade has a protected journal;
rerun the same setup command to recover. Custom units/drop-ins fail closed.

For an already paired connector, follow the installer's restart instruction:
`sudo systemctl restart owntransit-connector-pair.service`. Do not use receiver
`pair setup --replace` for a routine upgrade: that explicitly replaces identities.
Clients use the new binary on the next SSH connection. Existing client setup
shows its connection/resume instruction without generating a second identity.
Keep independent SSH/local-console access; upgrading may disconnect active carriers.

### Several relay instances on the same VPS

For independent relays on one VPS, add `--instance NAME` to relay installation
and administration. For example, on the VPS:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- relay --instance office wss://office.example/connects
sudo owntransit-relay-preview approve --instance office RECEIVER_ID
sudo owntransit-relay-preview list
```

Run registration after the receiving machine has advertised its public ID.
Each instance has a unique canonical HTTPS hostname and a separate, persistent
loopback port. Creating another instance never adopts the default relay's keys
or container. A conflicting route or occupied port is refused. The original
unnamed relay is `default`; its paths, keys and port 9087 remain compatible.
Named setup automatically allocates from host ports 9088–9151; users do not
choose a bind address or change the container's internal port. Reservations
remain across failed setup, stop, removal and reinstall.

Use `setup --instance office --url wss://office.example/connects` to rerun setup
or upgrade only that relay. To stop/remove only that instance's running container:

```sh
sudo owntransit-relay-preview uninstall-managed --instance office
```

This retains its keys, disabled unit, website route and shared executable.
The installer also accepts `relay --instance office --uninstall` for that scoped
operation. `relay --uninstall` without an instance removes the whole relay
package after validating/stopping all managed instances. Neither path purges keys.

Relay instance names and endpoint tunnel names are local labels, not identities.
For endpoint setup below, enter the selected instance's exact public URL. A
pairing remains bound to that relay origin; there is no automatic relay
switching/failover or migration of an existing pairing to a new origin.

## 2. Install the receiver on the SSH server

These commands work on both supported Linux architectures, including a 64-bit
Raspberry Pi:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- connector
sudo owntransit-connector-preview pair setup
```

Enter your relay URL, for example `wss://relay.example/connects`.
Setup initializes the receiver and enables its installed systemd service for
reboot. It displays a **complete VPS approval command** and **one private
56-character pairing code** (`otpair2.`).

It reports the receiver component's startup only after the worker observes relay
acknowledgement. The tunnel is still **UNDER CONSTRUCTION**, not ready end to end.

Lost the code? Run the exact `pair code --receiver-id …` command printed by setup
or VPS approval on this receiving machine. It retrieves the **same** pending code;
no new receiver ID or approval is needed. `pair list` prints exact retrieval and
next-step commands for each named tunnel. Repeated ordinary `pair setup` retains
an existing pending or paired identity.

An expired, spent, missing old-version or deliberately abandoned code needs
explicit `pair setup --replace`. This creates a **new receiver ID and code**;
approve that new ID on the VPS and start a fresh client pairing. A paired receiver
asks before replacement. Use independent SSH or console access for this action.
Old state is retained in a private, terminally locked generation under
`/var/lib/owntransit-pair.setup`; it is not an automatic rollback target.
Interrupted preparation leaves the old pairing unchanged; interruption after
retirement keeps it locked. Rerunning explicit `setup --replace` creates fresh identities.
Normal restart uses `sudo systemctl restart owntransit-connector-pair.service`,
not `pair setup`, and does not require new codes.

Give only the public ID to the relay. Keep the private code for your intended
client, transferring it through existing authenticated SSH/local-console access.
It expires after 24 hours and authorizes one device, not a human identity.

The receiver's local authority process keeps signing, age and issuer keys in
root-private state. Its separate network worker runs as UID/GID 65534 without
supplementary groups, dumps or permission to read the authority store. All
network connections are outbound. Its SSH target is fixed to
`tcp4 127.0.0.1:22`; SSH itself must already be configured by you.

## 3. Approve the receiver at the relay

In another VPS terminal, copy the receiver's printed approval command; it
already includes the exact relay URL. The example form is:

```sh
sudo owntransit-relay-preview approve --url wss://relay.example/connects RECEIVER_ID
```

Use your real URL and public receiver ID. `--url` selects only an exact protected
local instance registration; it cannot create a relay, switch an endpoint origin
or fall back to another instance. `--instance NAME` is an alternative selector,
not an additional flag. Approval requires the one-code release's administration
tool. Unsupported versions fail explicitly; no different relay is selected.

The VPS prints **Receiver approved**, not another code. The receiver and client
pick up public registration data automatically. Never paste the private
receiver code into the VPS.

Approval is a saved step, not a working tunnel. Its **UNDER CONSTRUCTION** output
includes the exact receiver-code retrieval command and client setup commands.

**Older manual installation?** Complete the migration above first. Approval
then uses the same ordinary command as a fresh managed relay. The low-level
`pair approve --state` API remains available for deliberately manual deployments;
it is not the normal 0.6.1 quickstart.

## 4. Install and pair a Linux client

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-linux.sh | sudo sh -s -- client
```

After the installer finishes, run as your ordinary user:

```sh
/usr/local/bin/owntransit-preview pair setup
```

It asks for the relay URL and **one private code from receiver setup**.
Secret input is not echoed; never put codes in shell
arguments, environment variables, logs or support tickets.

If the initial exchange was interrupted, keep the exact saved request:

```sh
owntransit-preview pair resume
```

### Apple-silicon macOS client

Install without sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.1/install-preview-macos.sh | sh -s -- client
```

Use the exact setup command printed by installation. The per-user software lives
under `~/Library/Application Support/OwnTransitSoftware/0.6.1`; command aliases
are under `~/.local/bin`. The printed absolute path works without changing PATH.
Existing legacy/manual binaries elsewhere are preserved, not overwritten.

For an independently verified manual handoff:

Download `owntransit-preview-0.6.1-darwin-arm64.tar.gz` from the
[0.6.1 release](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.6.1).
Verify its digest against the signed `DEVELOPMENT-SHA256SUMS`, then extract it.
The archive contains the client, capsule identity, checksums and license notices.
It does not alter your Mac or require Apple notarization.

Run the extracted `./owntransit pair setup`. Use that executable's absolute
path in your ProxyCommand, or put it on your own PATH under `owntransit-preview`.
Setup prints a connection example using the executable you actually ran and
includes a custom `--state` path if selected. Pasting the short code works directly:
do not change your terminal settings with `stty`. Backspace corrects input,
Ctrl-U clears the entry, and Ctrl-C cancels. Paste one code per prompt.

### Older versions

Upgrade all three installed roles before creating a one-code pairing. Existing
completed tunnels need no new codes. If you deliberately need the old two-code
setup, select `pair setup --legacy-codes` on receiver and client, and use VPS
`register` instead of `approve`. This is an explicit compatibility mode, never
an automatic downgrade after an offer or signature failure. Older pending
legacy attempts cannot be converted because their private secret was not saved.

**Upgrading an already paired Mac:** rerun the installer and use its printed
client path in your ProxyCommand. Pairing stays in the user's configuration
directory; do not remove it or obtain new codes. No SSH files are edited by the
installer. To uninstall software while retaining pairing, run the printed
`sh .../install-macos.sh --uninstall` command.
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

Use the endpoint's `pair next` command for commands specific to its current state.
Client `pair setup`/`pair resume` automatically perform a real carrier check after
pairing. `pair check` repeats that check without replacing identity. Only success
reports **TUNNEL READY**: both TLS boundaries, fresh authorization and the fixed
receiver-local SSH dial have completed. SSH host-key/user authentication remains
separate and must use your existing SSH policy. [Recovery examples](SETUP_RECOVERY.md).

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

## Several tunnels through the same relay

For multiple clients on one private SSH machine, set up one receiver tunnel per
client. The same flow works across several private SSH machines:

```sh
sudo owntransit-connector pair setup --tunnel laptop
sudo owntransit-connector pair setup --tunnel desktop
```

Use your relay URL and register each public receiver ID separately on the VPS:

```sh
sudo owntransit-relay approve RECEIVER_A_ID
sudo owntransit-relay approve RECEIVER_B_ID
```

Registering the second receiver does not replace the first route. Give each
client only the private receiver code for its intended route.
Never share the private receiver code with the relay.

On each client, select a local tunnel name when pairing. One client can have
several names for several receiving machines:

```sh
owntransit pair setup --tunnel office --relay wss://relay.example/connects
owntransit pair setup --tunnel home --relay wss://relay.example/connects
```

Use your real relay URL and the actual executable path from installation.
Each setup prints the SSH command with its `--tunnel` included. The same selector
must be present for `pair proxy`, `pair resume`, `pair status` and `pair alarm`.
Names are local labels and need not match between the two endpoints. For example:

```sh
owntransit pair list
owntransit pair status --tunnel office
ssh -o 'ProxyCommand=owntransit pair proxy --tunnel office' USER@SSH_ALIAS
```

An alarm affects the selected pairing and its active connections. All pairings
still share the relay's network, capacity and outage exposure. The current
defaults cap each route at four active carriers and the relay at 64; global
connection and pending-work caps can become limiting sooner.

Each named receiver uses a separate service such as
`owntransit-connector-pair@laptop.service`. It starts automatically on reboot.
Restart one with `sudo owntransit-connector pair restart --tunnel laptop`.
For package upgrades, follow the printed restart commands for the installed
tunnels. Removal stops/removes all owned receiver units but retains their state.

To add another client, choose another receiver tunnel name. Reusing an existing
name for setup deliberately retires that tunnel's old pairing after confirmation.
The original unnamed receiver remains `default`; selecting `--tunnel default`
uses its original state/service. There is one authorized client identity per
tunnel, with multiple independent receiver tunnels supported on one SSH host.

## What installation changes

Only the requested role is installed below `/opt/owntransit-preview/0.6.1`,
with a separately named `*-preview` alias. An exact reinstall is idempotent;
an unmanaged conflicting file is not overwritten. The connector installer
creates a disabled service; only your explicit `pair setup` enables it.

The default receiver state is `/var/lib/owntransit-pair`. Named receiver state
is `/var/lib/owntransit-tunnels/NAME`. On clients, both directories are beneath
the OS user configuration directory. Names use 1–32 lowercase letters, digits
or hyphens, starting with a letter; `default` selects the original state and
`all` is reserved. Use either `--tunnel NAME` or `--state ABSOLUTE_PATH`, never
both. Advanced receiver `pair init`/`pair serve` still support custom state paths.

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
