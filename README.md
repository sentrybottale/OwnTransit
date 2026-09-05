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

## Install the 0.1.2 development preview

This is a **signed development preview**, not a stable or production-qualified
release. It installs separately from 0.1.0. Explicit relay setup can replace an
identified old relay while preserving its rollback state. Linux amd64/x86_64 and
arm64/aarch64 use the same command.

On the private SSH server:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- connector
sudo owntransit-connector-preview pair setup
```

On a Linux client:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- client
owntransit-preview pair setup
```

On the public relay:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2/install-preview-linux.sh | sudo sh -s -- relay
```

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

Apple-silicon macOS uses the [signed client archive](https://github.com/sentrybottale/OwnTransit/releases/tag/v0.1.2).
Intel macOS is not supported. No Apple signing subscription is required; the
client is not Apple-notarized.

The initial curl script trusts GitHub delivery, then pins the existing
distribution key and verifies the signed archive before executing its installer.
See the [complete guide](PAIRING_INSTALL.md) for the relay commands, verification,
macOS use and recovery. **Do not use the old 0.1.0 curl command for this flow.**

## Pair and connect

Once the relay is running and the executables are in place:

### 1. On the private SSH server

```sh
sudo owntransit-connector-preview pair setup
```

Enter your relay URL, such as `wss://relay.example/connects`, when prompted.
Setup starts the installed receiver service and enables it for reboot. It prints two
different values:

- a **public receiver ID** to register at the relay; and
- a **private, one-use pairing code** to give directly to your client.

Never give the private code to the relay. Transfer it through your existing
authenticated SSH or local-console access. Possession authorizes one device;
the code expires after 24 hours and is spent when pairing commits.

### 2. On the relay

In another terminal, register the public receiver ID:

```sh
sudo owntransit-relay-preview register RECEIVER_ID
```

Copy the printed relay code to the client. The running receiver retrieves
its relay registration automatically.

### 3. On the client

```sh
owntransit-preview pair setup
```

Paste the relay code and the private receiver code into the prompts. Do not
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

The current pairing profile supports one client per receiver. See the
[full walkthrough](PAIRING_INSTALL.md) for custom state paths, interrupted
pairing, SCP syntax and restart instructions.

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
The signed development artifacts do not claim independent security assessment,
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
