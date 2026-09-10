# OwnTransit

**Your SSH. Your keys. Untrusted transit.**

Connect two private computers over SSH when neither accepts a public connection.
Both connect outward to your Relay. Independent end-to-end encryption keeps
even a compromised Relay from reading the stream or impersonating an endpoint.

| Role | Install on | Purpose |
|---|---|---|
| Client | Your laptop or workstation | The computer you connect from |
| Relay | A public Linux VPS | Carries encrypted traffic |
| Target | The private Linux SSH machine | Delivers authenticated traffic to local SSH |

OwnTransit **0.7.0** supports Linux amd64/arm64 and an Apple-silicon Mac Client.
SSH must already work on the Target. OwnTransit never configures SSH accounts,
keys, permissions or forwarding.

## 1. Start on the Relay VPS

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- relay
```

The installer opens Relay setup when an interactive terminal is available.
To open or return to its menu:

```sh
sudo owntransit-relay setup
```

For a new Relay, enter its public URL, such as `wss://relay.example/connects`
(**example only**). The VPS needs an existing HTTPS site. Choose **New tunnel**
and give it a name. The entry is **UNDER CONSTRUCTION**; follow its Target step.

## 2. On the Target running SSH

Install the Target, then open its menu:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- target
sudo owntransit-target setup
```

Choose **New tunnel**, an unused local name and the Relay URL.
The Target starts and enables its service for reboot. It prints a public
Target ID for the Relay and one private `otpair2.` code for the Client.

Transfer the private code directly to the intended Client through your existing
authenticated SSH or console access. **Never give it to the Relay.**

## 3. Return to the Relay menu

Run `sudo owntransit-relay setup`, choose **Continue a tunnel**, select the
draft and enter the **public Target ID**. Approval is a saved step; the tunnel
remains **UNDER CONSTRUCTION**. Follow the displayed Client step.

## 4. On the Client computer

**Linux:** install, then open setup as your ordinary user without sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- client
owntransit-client setup
```

**Apple-silicon Mac:** install and open setup without sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-macos.sh | sh -s -- client
"$HOME/.local/bin/owntransit-client" setup
```

Choose **New tunnel**, an unused local name, the Relay URL and the private
code from the Target. Run one command at a time; answer prompts before running
the next command. Secret input is hidden.

Only the Client's actual authenticated end-to-end check can report
**TUNNEL READY**. Then run its printed SSH command with your own SSH user and
independently verified host identity. The printed command includes the executable
path and tunnel selection. OpenSSH still decides whether your login is allowed.

## Manage or recover a tunnel

Open the local role's `setup` menu again.

| Choice | What it does |
|---|---|
| New tunnel | Creates a separate tunnel with an unused name |
| Continue tunnel | Resumes the saved step; on the Client, checks transport |
| List tunnels | Shows local state, not proof of end-to-end readiness |
| Remove tunnel | Removes the local endpoint connection or Relay admission |
| Killswitch | Client/Target only: permanently disables that pairing |
| Restore removed tunnel | Client/Target only: restores retained, unalarmed state |

Endpoint removal keeps private state and can be restored explicitly. A
killswitch cannot be undone. Relay removal never triggers an endpoint
killswitch. **Uninstalling the whole program is a separate installer action**;
see the [installation guide](PAIRING_INSTALL.md).

Lost the code? On the Target, choose **Continue tunnel** to retrieve the same
unused, unexpired code. Interrupted Client setup uses **Continue tunnel** too.
Keep existing identities during outages and software upgrades.
[Recovery details](SETUP_RECOVERY.md).

## Security and release scope

The Relay, its host, keys and reverse proxy are assumed compromised. Each
endpoint uses outer TLS 1.3 mTLS; an independent inner TLS 1.3 mTLS stream
authenticates the endpoints. The Target dials only build-fixed
`tcp4 127.0.0.1:22`, after authorization. OpenSSH adds its own encryption and
authentication. OwnTransit is an SSH byte carrier, not a VPN or general proxy.

Installers retain existing pairing state and migrate only recognized managed
software/services. No CLI compatibility is promised before 1.0; use the current
commands after upgrading. Published versions remain immutable. Do not replace
pairings just to update software or mix historical enrollment instructions.

Initial installer delivery trusts GitHub HTTPS; archives are signature-verified.
Independent security certification, pristine-host qualification and extended
soak testing are not claimed. Keep independent SSH or console recovery access.

[Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) ·
[Protocol compatibility](COMPATIBILITY.md) · [Roadmap](ROADMAP.md) ·
[Contributing](CONTRIBUTING.md) · [Apache 2.0 license](LICENSE)
