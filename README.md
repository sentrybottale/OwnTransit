# OwnTransit

**Your SSH. Your keys. Untrusted transit.**

Connect two private computers over SSH when neither can accept a public
connection. OwnTransit carries their traffic through a public relay, with a
separate end-to-end encryption layer that keeps the relay outside the
conversation. You keep your existing SSH keys and login rules.

## Three roles. One private connection.

| Role | Where it runs | What it does |
|---|---|---|
| Client | The computer you connect from | Carries your existing SSH connection |
| Receiver / connector | The private machine running your SSH server | Authorizes its paired client and delivers traffic to local SSH |
| Relay | Your public VPS | Joins the two outbound connections and carries encrypted bytes |

Both endpoints connect outward. Neither exposes an OwnTransit listener or
needs a public address. The relay is the only publicly reachable component.

The relay is assumed compromised—not trusted because you happen to own it.
It can observe addresses, timing and traffic sizes, or deny service. It must
not read the inner stream, impersonate an endpoint accepted by its peer, or
choose where the receiver sends traffic.

## Install 0.4.0

0.4.0 is the signed receiver-owned release line, separate from the older 0.1.0
package/qualification profile. Linux amd64/x86_64 and arm64/aarch64 use the same
command. Existing preview filenames and aliases remain for compatibility;
normal command names are added where available. Follow the command printed by
the installer if a legacy name conflicts. No unrelated command is overwritten.

First, on the public VPS (installation starts relay setup):

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- relay
```

Then install the package on the private SSH server:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- connector
```

On a Linux client:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- client
```

For a new pairing, follow **Pair and connect** below once both packages are
installed. The setup commands below are interactive programs: answer their
prompts, rather than pasting the command again into an input field.

The relay installer starts one setup workflow and asks for the full public URL,
for example `wss://relay.example/connects`. That selects the website when the VPS
hosts several domains. Setup detects Docker or Podman, starts an unprivileged
relay container, enables its reboot service and verifies the public WebSocket
route. Existing routing is reused; a missing route in a recognized Nginx, Apache
or Caddy site is backed up, added only to that site, validated and reloaded.

The same interface works across providers on supported Linux/systemd hosts with
an existing HTTPS site. Bespoke proxy layouts or a missing HTTPS site produce a
specific setup error; they are not guessed. Failed cutover restores the previous
relay and any route changed by setup. Start the relay before endpoint setup.

On an Apple-silicon Mac, install the client **without sudo**:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-macos.sh | sh -s -- client
```

The Mac installer prints the exact setup command, normally
`"$HOME/.local/bin/owntransit" pair setup`. It requires no PATH or SSH-file edits.
Intel macOS is not supported. No Apple signing subscription is required; the
client is not Apple-notarized.

The initial curl script trusts GitHub delivery, then pins the existing
distribution key and verifies the signed archive before executing its installer.
See the [complete guide](PAIRING_INSTALL.md) for the relay commands, verification,
macOS use and recovery. **Do not use the old 0.1.0 curl command for this flow.**

## Upgrade without new pairing codes

0.4.0 includes the 0.1.8 fix for the relay timer that closed active tunnels.
Endpoint authentication and wire compatibility are unchanged.

Use the same 0.4.0 installer above for each installed role. It preserves pairing
state and accepts known 0.1.1/0.1.2/0.1.3/0.1.5/0.1.6/0.1.7/0.1.8 and 0.2.0/0.3.0 packages; stable 0.1.0 remains
separate. On the relay, supply the existing URL. Managed upgrade restarts onto
the new image, verifies it and the public route, and rolls back on failure;
it does not rewrite website routing or relay keys. Rerunning after an interrupted
upgrade recovers the previous service first.

After the connector package upgrade, activate it without new pairing codes:

```sh
sudo systemctl restart owntransit-connector-pair.service
```

Use independent access during maintenance: active SSH carriers may disconnect.
The client uses its new executable on the next connection. **Do not rerun
receiver `pair setup` just to upgrade**—that deliberately creates new identities.

On Mac, rerun the same installer and use its printed executable path in your
ProxyCommand. Existing pairing state is reused. Older manually installed Mac
binaries are not overwritten or selected silently.

## More than one relay on the same VPS

Use a different local **instance name** and HTTPS hostname for each relay:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- relay --instance work wss://work.example/connects
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- relay --instance personal wss://personal.example/connects
```

Each instance has separate relay keys, private state, container, reboot service
and a persistent loopback-only host port. Setup selects only the requested HTTPS
site. Existing unnamed installations remain `default`, with their original keys,
URL and port. Omit `--instance` when upgrading that existing default relay.

After package installation, the equivalent commands are:

```sh
sudo owntransit-relay setup --instance work --url wss://work.example/connects
sudo owntransit-relay register --instance work RECEIVER_ID
sudo owntransit-relay list
```

Receiver setup prints a registration command with `--url` filled in. That selects
the exact configured local instance by URL, so you do not need to know its VPS
label. You may use either `register --instance NAME` or `register --url PUBLIC_URL`,
never both. An unknown or unavailable selected relay is an error, not a fallback.

Choose this relay's URL on the receiving SSH machine and client. Relay
`--instance` selects local VPS plumbing; endpoint `--tunnel` selects an independent
pairing. Those names need not match. One relay instance can still carry many
tunnels. An existing pairing never switches relay, automatically or otherwise;
using a different relay requires a new pairing with its own identities.

Rerun the same named install/setup command to upgrade that instance. Other
instances are not restarted. Their keys and reservations remain independent,
but they share the VPS's resources and failure exposure—not separate trusted hosts.
Adding a missing website route reloads the shared webserver; its reload behavior
may affect existing connections, so keep independent access during setup.

## Uninstall without deleting pairing state

For Linux 0.4.0, use the same installer with the local role and `--uninstall`:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- client --uninstall
```

Replace `client` with `connector` or `relay` as appropriate. **Unqualified relay
package removal stops all managed relay instances.** To stop only one and keep
the shared package and other instances, specify its name:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.4.0/install-preview-linux.sh | sudo sh -s -- relay --instance work --uninstall
```

Its keys, disabled service, website route and URL/port reservation remain for
explicit reinstall. Use `--instance default` to select only the original relay.
Upgrade older
packages to 0.4.0 first. Receiver removal stops/disables its service. Relay
removal disables its verified managed unit and removes the stopped container;
its keys, disabled unit configuration, website route and rollback images are
retained for explicit reinstall/setup. Modified/unrecognized files are not
silently removed. SSH configuration and pairing state are never purged.

On Mac, use the installer's printed uninstall command, normally:

```sh
sh "$HOME/Library/Application Support/OwnTransitSoftware/0.4.0/install-macos.sh" --uninstall
```

Reinstalling restores software without requiring new pairing codes.

## Pair and connect

Once the relay is running and the executables are in place:

The examples retain compatible `*-preview` names. Fresh installations also
provide normal aliases (`owntransit`, `owntransit-connector`, `owntransit-relay`)
where those names are free. On Mac, use the absolute path printed by installation.

### 1. On the private SSH server

```sh
sudo owntransit-connector-preview pair setup
```

Enter your relay URL, such as `wss://relay.example/connects`, when prompted.
Setup starts the installed receiver service and enables it for reboot. It prints two
different values:

- a **public receiver ID** to register at the relay; and
- a **private, one-use pairing code** to give directly to your client.

Setup waits until the receiver has advertised and prints the exact next command
to run on the relay. Running receiver `pair setup` again creates a **fresh ID and
fresh code**, permanently retiring the old pairing. A paired receiver asks before
disconnecting its existing client. Use `pair status` to inspect the receiver or
`sudo systemctl restart owntransit-connector-pair.service` to restart it without
changing identities. The package installer itself preserves pairing state.

Never give the private code to the relay. Transfer it through your existing
authenticated SSH or local-console access. Possession authorizes one device;
the code expires after 24 hours and is spent when pairing commits.

### 2. On the relay

In another terminal on your VPS, run the registration command printed by receiver
setup. It includes the exact relay URL. For example:

```sh
sudo owntransit-relay-preview register --url wss://relay.example/connects RECEIVER_ID
```

Use your actual URL and public ID from receiver setup, not the example domain.
Copy the printed relay code to the client. The running receiver retrieves
its relay registration automatically.

### 3. On the client

```sh
owntransit-preview pair setup
```

Paste the **VPS registration code** (`otrelay1.…`) from the public VPS, then the
**private receiving-machine code** (`otpair1.…`) from the private SSH machine.
Input is hidden; paste once and press Enter. Long codes work directly on macOS
and Linux; no `stty` workaround is needed. Do not
put either in shell arguments or environment variables. The endpoints generate
their own keys, authenticate the exchange and save the pairing. No comparison
words or approval call are involved.

Then use your existing SSH user, key and independently verified host identity:

```sh
ssh -o 'ProxyCommand=owntransit-preview pair proxy' USER@SSH_ALIAS
```

Normal SSH options, including `-i` and `-L`, remain yours. SCP can use the same
ProxyCommand. OwnTransit does not create an SSH alias, choose your SSH key or
change your login policy.

Each tunnel pairs one client identity with one receiver identity. See the
[full walkthrough](PAIRING_INSTALL.md) for custom state paths, interrupted
pairing, SCP syntax and restart instructions.

## More than one tunnel

Named tunnel commands require the 0.3.0 or newer client/connector. Existing compatible
relays can carry them without new relay configuration or pairing migration.

One VPS relay and public URL can carry several independent client–receiver
pairings. Register each receiver's public ID on the same relay. Each pairing
keeps its own keys, receiver authority and alarm state.

To let several client computers access the same SSH machine, create a named
receiver tunnel for each client on that machine:

```sh
sudo owntransit-connector pair setup --tunnel laptop
sudo owntransit-connector pair setup --tunnel desktop
```

Register both public receiver IDs on your relay. Give each client only the codes
for its own tunnel. On each client, pair and select a local name:

```sh
owntransit pair setup --tunnel office
ssh -o 'ProxyCommand=owntransit pair proxy --tunnel office' USER@SSH_ALIAS
```

One client can also create several named tunnels to different SSH machines.
Names are local labels: the client and receiver do not have to use the same
name. Use the executable path printed by installation if it is not on PATH.

List local tunnels or select one to inspect, restart or alarm:

```sh
owntransit pair list
owntransit pair status --tunnel office
sudo owntransit-connector pair list
sudo owntransit-connector pair restart --tunnel laptop
```

Use `pair alarm --tunnel NAME` on the desired endpoint to permanently disable
that individual tunnel. Every receiver tunnel has separate keys, state and a
reboot-enabled service, all delivering to the same local SSH port. Existing
unnamed installations remain the `default` tunnel; `--state` is still supported
as an alternative selector.

After reinstalling a receiver package, use `pair list` and restart each retained
named tunnel that you want to bring back. Software installation does not
silently enable previously removed services.

Multiple SSH/SCP connections can also share one pairing. Current admission
ceilings are four active carrier connections per pairing and 64 across the
relay; other connection/resource limits still apply. These are limits, not a
throughput or simultaneous-capacity guarantee. One SSH connection may itself
carry several OpenSSH channels.

An individual pairing still authorizes one client identity. A physical SSH
server accepts multiple client computers through separate named pairings, so
their keys and alarms remain independent.

## Encryption and authorization

Each endpoint has an outer TLS 1.3 mutually authenticated connection to the
relay. Inside those two connections, the endpoints establish a separate,
end-to-end TLS 1.3 mutually authenticated stream. SSH runs inside that stream,
with its own independent encryption and host/user authentication.

The receiver owns its route-scoped issuance keys. They remain in a protected
local authority process, separate from the unprivileged network worker.
The client generates its operational private keys locally; the relay receives
no endpoint issuer or signing authority.

Before the receiver opens **build-fixed `tcp4 127.0.0.1:22`**, the inner
handshake must verify the exact peer identity and key, and both endpoints must
grant fresh, session-bound authorization. The relay cannot select another
target or negotiate a weaker endpoint profile.

Reconnects use retained identities and fresh authentication. Operational
certificates refresh automatically. During a live connection, authorization
leases renew without user prompts; ordinary SSH bytes cannot extend them.

## Emergency security alarm

On the client:

```sh
owntransit-preview pair alarm
```

Or on the receiver:

```sh
sudo owntransit-connector-preview pair alarm
```

An explicit local alarm is terminal for that pairing. It survives restart,
blocks authorization and closes active local workers. It cannot be cleared to
restore the tunnel. Recovery means deliberately rebuilding and re-pairing with
fresh OwnTransit identities; SSH keys remain yours and are not changed.
Success is reported only after local shutdown is confirmed; a timeout can leave
the durable alarm set without confirming shutdown.

The relay can suppress a kill notification. Remote cutoff is therefore bounded
by the remaining authorization lease—at most 60 seconds—plus operating-system
scheduling and shutdown latency. Rebuilding never replays an old SSH stream.
A tunnel kill cannot retract delivered bytes or
guarantee that SSH-started jobs stop.

## Scope and current limits

0.4.0 uses bounded source/security, fast timer/reconnect/concurrency and
alarm/rebuild fixtures, isolated installer checks, authenticated artifacts and
a brief final end-to-end check. **Extended soak testing, pristine-host
certification and independent security assessment are not claimed.** Historical
`DEVELOPMENT-SHA256SUMS` and signing namespace names identify the retained
distribution format; they are not legacy 0.1.0 release-policy authority.

OwnTransit carries SSH byte streams only. It is not a VPN, subnet router, DNS
layer, identity provider, dashboard or general-purpose proxy.

Bring your own working SSH setup and independent recovery access. OwnTransit
never creates or edits SSH keys, accounts, `authorized_keys`, client/server
configuration, forwarding rules or host recovery.

The connector installer supplies a disabled systemd service; explicit setup
initializes it and enables reboot startup. No existing installation is migrated.
Normal restarts, relay outages, failed authentication and missing lease messages
close affected carriers and retry with retained identities—not a security alarm
or fresh pairing. A broken carrier may disconnect its current SSH session; its
bytes are never replayed. Lost identities or expired, uncompleted pairing can
require explicit new pairing state; the relay cannot authorize a silent reset.

Integrated tests exercise real WebSocket carriage, both TLS boundaries, SSH
protocol authentication and exec, receiver restart, credential renewal,
terminal client/receiver alarms, deliberate rebuilding and profile rejection.
The signed receiver-owned artifacts do not claim independent security assessment,
production qualification or a new-machine/reboot certification.

For protocol and threat-model details, read
[receiver-owned pairing](RECEIVER_PAIRING.md),
[security](SECURITY.md) and [wire compatibility](COMPATIBILITY.md).

## Earlier release

The immutable [0.1.0 release](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.1.0)
uses an older setup protocol. Its [installation](INSTALL.md) and
[first-deployment](FIRST_DEPLOYMENT.md) guides are retained for that release
only. Do not mix those instructions or credentials with receiver-owned pairing.

## Contributing and disclosure

See [CONTRIBUTING.md](CONTRIBUTING.md) and
[PROVENANCE.md](PROVENANCE.md) for contributor requirements. Report suspected
vulnerabilities through the private process in [SECURITY.md](SECURITY.md),
not a public issue.

OwnTransit is licensed under the [Apache License 2.0](LICENSE).
