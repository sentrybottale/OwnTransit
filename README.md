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

## Get the executables

Receiver-owned pairing is available in the **0.1.1-dev self-test builds**.
Download the artifact for your machine from a successful
[release-candidate workflow run on main](https://github.com/sentrybottale/OwnTransit/actions/workflows/release-candidate.yml?query=branch%3Amain):

| Your machine | Download |
|---|---|
| Linux x86_64 / amd64 | `owntransit-pairing-linux-amd64` |
| Linux aarch64 / arm64 | `owntransit-pairing-linux-arm64` |
| Apple-silicon macOS | `owntransit-pairing-darwin-arm64` |

Linux archives contain the client, connector and relay executables, plus the
relay container image. The macOS archive contains the client. Intel macOS is
not supported.

**These are development outputs, not a signed stable release.** They trust
GitHub's build and artifact delivery; macOS outputs are not Apple-notarized.
The existing curl installer still installs 0.1.0 and does not include this
pairing flow.

Start with the [installation and pairing guide](PAIRING_INSTALL.md) for
extraction, executable placement and the rootless Podman relay commands.
It also explains the existing HTTPS prerequisite: forward the exact
`/connects` WebSocket path to the relay's host-loopback port 9087. OwnTransit
does not edit your reverse proxy, website, firewall or SSH configuration.

## Pair and connect

Once the relay is running and the executables are in place:

### 1. On the private SSH server

```sh
sudo /usr/local/bin/owntransit-connector pair init --relay wss://relay.example/connects
sudo /usr/local/bin/owntransit-connector pair serve
```

Replace `relay.example` with your relay's domain. Initialization prints two
different values:

- a **public receiver ID** to register at the relay; and
- a **private, one-use pairing code** to give directly to your client.

Never give the private code to the relay. Transfer it through your existing
authenticated SSH or local-console access. Possession authorizes one device;
the code expires after 24 hours and is spent when pairing commits.

### 2. On the relay

In another terminal, register the public receiver ID:

```sh
podman exec owntransit-relay-pair /owntransit-relay pair register --state /state/relay RECEIVER_ID
```

Copy the printed relay code to the client. The running receiver retrieves
its relay registration automatically.

### 3. On the client

```sh
owntransit pair init --relay wss://relay.example/connects
```

Paste the relay code and the private receiver code into the prompts. Do not
put either in shell arguments or environment variables. The endpoints generate
their own keys, authenticate the exchange and save the pairing. No comparison
words or approval call are involved.

Then use your existing SSH user, key and independently verified host identity:

```sh
ssh -o 'ProxyCommand=owntransit pair proxy' USER@SSH_ALIAS
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

## Emergency lock

On the client:

```sh
owntransit pair lock
owntransit pair unlock
```

Or on the receiver:

```sh
sudo /usr/local/bin/owntransit-connector pair lock
sudo /usr/local/bin/owntransit-connector pair unlock
```

A lock survives restart, blocks new authorization and closes active local
workers. Success is reported only after local shutdown is confirmed; a timeout
can leave the durable lock set without confirming shutdown.

The relay can suppress a kill notification. Remote cutoff is therefore bounded
by the remaining authorization lease—at most 60 seconds—plus operating-system
scheduling and shutdown latency. Unlock requires a fresh connection; it never
replays an old SSH stream. A tunnel kill cannot retract delivered bytes or
guarantee that SSH-started jobs stop.

## Scope and current limits

OwnTransit carries SSH byte streams only. It is not a VPN, subnet router, DNS
layer, identity provider, dashboard or general-purpose proxy.

Bring your own working SSH setup and independent recovery access. OwnTransit
never creates or edits SSH keys, accounts, `authorized_keys`, client/server
configuration, forwarding rules or host recovery.

The development walkthrough runs foreground processes; it does not install
reboot-start services or migrate an existing installation. Missing network
traffic fails closed without permanently locking the endpoint. Lost identities
or expired, uncompleted pairing can require explicit new pairing state; the
relay cannot authorize a silent reset.

Integrated tests exercise real WebSocket carriage, both TLS boundaries, SSH
protocol authentication and exec, receiver restart, credential renewal,
client/receiver lock, unlock/reconnect and profile rejection. This is source
integration evidence—not an independent security assessment, live-host
qualification or a claim that a signed 0.1.1 installer has shipped.

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
