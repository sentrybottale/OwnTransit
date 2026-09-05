# Try receiver-owned pairing

This walkthrough is for the **0.1.1 development source**, not the 0.1.0 download.
There are three roles: public relay, private receiver/connector, and client.
The receiver authorizes one client. No separate administrator/provisioner runs.

OwnTransit does not set up SSH. Bring a working SSH server listening on loopback
port 22, your existing SSH user/key, and independently verified SSH host key.
Keep another access path while testing. Nothing here edits SSH, Nginx, websites,
firewalls, accounts or the currently installed OwnTransit release.

## Get the new executables

Open this repository's **Actions → release-candidate** run for the exact merged
commit. Its successful native test jobs provide downloadable artifacts:

- `owntransit-pairing-linux-amd64` for x86_64 Linux;
- `owntransit-pairing-linux-arm64` for aarch64 Linux; and
- `owntransit-pairing-darwin-arm64` for Apple-silicon macOS.

These are explicitly unreleased **0.1.1-dev** self-test executables, not the
signed stable release. They trust GitHub's build and artifact delivery. Extract
the archive and restore the executable bit if ZIP extraction removed it. For
example, `chmod 755 owntransit` on the client. The old curl installer still
installs 0.1.0; it cannot install these new commands. No old install is replaced
automatically. macOS artifacts are not Apple-notarized.

Alternatively, build the checked-out source with repository-pinned Go 1.26.7:

On the client (Apple-silicon macOS, Linux amd64 or Linux arm64):

```sh
go build -trimpath -o owntransit ./cmd/owntransit
```

Do not run client pairing as root. Put the built client on your existing PATH,
or use its absolute path in the SSH ProxyCommand below.

On each Linux server, build only its required role:

```sh
go build -trimpath -o owntransit-connector ./cmd/owntransit-connector
# On the public relay instead:
go build -trimpath -o owntransit-relay ./cmd/owntransit-relay
```

Install the receiver executable as root in a root-owned directory whose parents
are not writable by other users, for example `/usr/local/bin`. The receiver
broker refuses to spawn a worker from a user-writable executable path. Use a
separate name/path if an existing installation owns that name; do not overwrite
an existing release inadvertently.

For a machine without an existing executable at that path:

```sh
sudo install -m 0755 owntransit-connector /usr/local/bin/owntransit-connector
# On the relay instead:
sudo install -m 0755 owntransit-relay /usr/local/bin/owntransit-relay
```

## 1. Start your public relay

The Linux self-test archive includes `owntransit-relay-pair-image.tar`. On a
normal non-root Linux account with rootless Podman available:

```sh
podman load -i owntransit-relay-pair-image.tar
install -d -m 0700 "$HOME/.local/share/owntransit-relay-pair"
podman run --rm --network=none --read-only --cap-drop=all --security-opt=no-new-privileges \
  --volume="$HOME/.local/share/owntransit-relay-pair:/state:rw,nosuid,nodev,noexec" \
  owntransit-relay-pair:0.1.1-dev pair init --state /state/relay

podman run --rm --name owntransit-relay-pair --pull=never \
  --read-only --cap-drop=all --security-opt=no-new-privileges \
  --pids-limit=128 --memory=256m --cpus=1 \
  --volume="$HOME/.local/share/owntransit-relay-pair:/state:rw,nosuid,nodev,noexec" \
  --publish=127.0.0.1:9087:9087/tcp \
  owntransit-relay-pair:0.1.1-dev
```

The container's only published port is **`127.0.0.1:9087`**. Your existing HTTPS reverse proxy must already
forward the exact `/connects` WebSocket path to that address. OwnTransit does not
change the proxy or open a firewall port. If another relay occupies that port,
plan the cutover explicitly; this command will not evict it. The development
command is foreground; it does not install or enable a system service.

For native development instead, use `owntransit-relay pair init` followed by
`pair serve`, both with `--state /var/lib/owntransit-relay-pair` and sudo. That
native build binds only host loopback. The container build has a separate fixed
listener profile; never run its executable directly on a host.

## 2. Initialize the private receiver

On the SSH server:

```sh
sudo /usr/local/bin/owntransit-connector pair init --relay wss://relay.example/connects
sudo /usr/local/bin/owntransit-connector pair serve
```

Initialization displays a **public receiver ID** and a separate **private pairing
code**. Give only the public ID to the relay. Transfer the private code directly
to the intended client using your existing authenticated SSH/local-console
access. Possession of that code authorizes one device; it does not identify a
human. It expires after 24 hours and is spent atomically when pairing commits.

The root-owned authority process retains issuer/signing/age keys in its private
state. A separate Linux worker runs as UID/GID 65534 with no supplementary groups
and no access to those keys. The worker originates all network connections. Only
authenticated streams can reach build-fixed `tcp4 127.0.0.1:22`.

## 3. Register that receiver at the relay

In a second terminal on the relay, replace `RECEIVER_ID` with the public ID:

```sh
podman exec owntransit-relay-pair /owntransit-relay pair register --state /state/relay RECEIVER_ID
```

Copy the printed `otrelay1.` code to the client. The running receiver retrieves
its registration automatically; you do not paste this code back into it.

## 4. Pair the client and use SSH

```sh
owntransit pair init --relay wss://relay.example/connects
```

Paste the relay code, then the private receiver code into the prompts. Neither
belongs in shell arguments, environment variables, tickets or logs. Input on a
terminal is not echoed. The exact generated request and private client keys are
saved before transmission. For an interrupted initial exchange:

```sh
owntransit pair resume
```

Use your existing SSH identity and independently established host-key policy:

```sh
ssh -o 'ProxyCommand=owntransit pair proxy' USER@SSH_ALIAS
scp -o 'ProxyCommand=owntransit pair proxy' ./file USER@SSH_ALIAS:./
```

`SSH_ALIAS` is your operator-owned SSH destination/host-key alias; it is not a
relay-selected target. OwnTransit forwards to loopback SSH only. It never edits
your SSH configuration or chooses your SSH key. `pair proxy` stdout contains
only SSH bytes. Normal SSH `-i`, port-forwarding and host-key options remain yours.

Default client state is `owntransit-pair` below the operating system's user
configuration directory. Receiver state is `/var/lib/owntransit-pair`. Every
command accepts an explicit absolute `--state PATH`; use the same path throughout.

## Stop, restart and emergency lock

```sh
owntransit pair status
owntransit pair lock
owntransit pair unlock
# On the private SSH server:
sudo /usr/local/bin/owntransit-connector pair lock
sudo /usr/local/bin/owntransit-connector pair unlock
sudo /usr/local/bin/owntransit-connector pair serve
```

A lock is persistent. It blocks admission and credential renewal and waits for
active local workers to stop before acknowledging success. A timeout leaves
the durable lock in place but does not claim shutdown was confirmed. Unlock is
local and explicit; it never revives a previous SSH byte stream. Start the
receiver again after unlocking if it was running in the foreground.

Reconnects use retained identities, fresh inner mTLS and fresh session-bound
authorization. Leases last at most 60 seconds and are normally renewed every
20 seconds without prompts. Receiver operational certificates refresh locally;
clients refresh theirs when opening a new stream. Missing grants close traffic,
not permanently lock it. A malicious relay can suppress a kill notice; remote
cutoff is bounded by the remaining lease plus OS scheduling/shutdown latency.

Restart the same `pair serve` command with the same state to retain identities.
This source walkthrough does **not** install reboot-start services. Relay
registration delivery is memory-only; a relay restart before both endpoints
save it requires registering the receiver again. Lost/expired uncompleted
pairing requests can require a new explicit pairing state; no silent trust reset
or identity replacement occurs. Existing SSH-started jobs and delivered bytes
cannot be retracted by a tunnel kill.

## What the tests establish

The in-repository integrated test uses real WebSocket carriage, both TLS 1.3
mTLS boundaries, receiver pairing, and a generated disposable SSH protocol
fixture with a pinned host key. It exercises SSH exec, receiver restart,
credential renewal, client/receiver lock, unlock/reconnect, and mixed-profile
rejection before SSH dial. The fixture's SSH authentication settings belong only
to that generated test; OwnTransit installs no equivalent SSH configuration.

This is source integration evidence, not a signed release, a test of your hosts,
an SCP interoperability qualification, or an independent security assessment.
