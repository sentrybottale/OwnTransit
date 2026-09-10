# Install and use OwnTransit 0.7.0

The three roles are **Client**, **Relay** and **Target**. The Client is the
computer you connect from; the Target is the private computer running SSH.
Both connect outward to the public Relay. Only the Relay is publicly reachable.

Linux amd64/x86_64 and arm64/aarch64 support all three roles. The Mac Client
supports Apple silicon. Every installer operates only on the local machine and
selected role. SSH must already be configured by its operator.

## Relay: create the tunnel entry

On the public Linux VPS:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- relay
```

The installer opens the Relay menu if it has an interactive terminal. Otherwise,
or whenever you want to return:

```sh
sudo owntransit-relay setup
```

For a new Relay, enter your public URL. `wss://relay.example/connects` is an
example, not an address to copy. The VPS needs an existing HTTPS site and systemd.
Setup supports recognized Nginx, Apache and Caddy layouts, or an existing correct
route from another proxy. It validates the selected site and retains unrelated
sites and routes. Unknown ownership or conflicting configuration is refused.

If several managed Relays exist on this VPS, the menu asks which one to use.
Choose **New tunnel** and give the draft a short lowercase name. The Relay saves
that local entry as **UNDER CONSTRUCTION**, then gives you the Target step.

A Relay entry is planning and admission state. It grants no endpoint identity
or access to SSH. The Relay does not receive the private pairing code.

## Target: create its endpoint

On the private Linux machine running your SSH server:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- target
```

After installation:

```sh
sudo owntransit-target setup
```

Choose **New tunnel**, enter an unused local name and the Relay's public URL.
The Target creates its own identities, starts its outbound service and enables
it for reboot. Setup prints its public Target ID and one private, one-use
`otpair2.` code. The displayed expiry applies to that exact code.

Give the Relay only the public Target ID. Transfer the private code directly
to the intended Client through existing authenticated SSH or console access.
Do not put it in shell arguments, environment variables, shared logs or tickets.

The Target retains an unused code locally so **Continue tunnel** can display
the same code again. That does not change the Target ID, approval or expiry.
A consumed or expired code cannot be made valid by retrying.

The Target's signing and issuer material stays in its private local authority.
Its separate network worker has no access to that authority store. The only
SSH destination is build-fixed `tcp4 127.0.0.1:22`, reached after end-to-end
authentication and authorization. OwnTransit does not edit SSH.

## Relay: continue and approve

Return to `sudo owntransit-relay setup`. Choose **Continue a tunnel**, select
the draft and enter the Target's public ID. The menu saves approval and shows
the next Client step. It does not generate a Client code.

The entry remains **UNDER CONSTRUCTION**. Approval, a running Relay process and
local status cannot prove that the Client can reach the Target.

## Client: finish the tunnel

For a Linux Client, install with sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- client
```

Then run setup as your ordinary user:

```sh
owntransit-client setup
```

For an Apple-silicon Mac Client, install without sudo:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-macos.sh | sh -s -- client
```

Then use the printed path:

```sh
"$HOME/.local/bin/owntransit-client" setup
```

Choose **New tunnel**, an unused local name, the Relay URL and the private
Target code. Input for the code is hidden. Paste one code, then press Enter.
Run commands separately and answer each program's prompts before continuing.

Setup authenticates the Target's offer before using its keys. Once pairing is
saved, it checks the actual end-to-end carrier and the Target's fixed local
SSH socket. Only success reports **TUNNEL READY**. A failed check retains the
pairing; use **Continue tunnel** to retry.

Run the SSH command printed by the Client, replacing `USER@SSH_ALIAS` with your
own SSH account and independently verified host label. It includes the selected
tunnel and exact Client executable path, including on Mac. Your SSH key and
host verification remain required. `Permission denied (publickey)` is an SSH
authorization result, not a request for another OwnTransit code.

SCP, SFTP and ordinary SSH options use the same printed ProxyCommand.
OwnTransit neither creates SSH accounts nor selects keys, edits SSH configuration
or sets forwarding rules. Proxy stdout contains only SSH bytes.

## Return to the local menu

Run `owntransit-client setup`, `sudo owntransit-target setup` or
`sudo owntransit-relay setup` on the corresponding machine. On Mac, use the
printed absolute Client path if it is not on PATH.

Client and Target menus offer **New tunnel**, **Continue tunnel**, **List
tunnels**, **Remove tunnel**, **Killswitch** and **Restore removed tunnel**.
The Relay offers the first four and **Start or update this relay**.

**Continue** uses the selected tunnel's saved state. On the Target it starts or
restarts that service and, while awaiting pairing, retrieves the same valid
pending code. On the Client it resumes a saved request if necessary and checks
the carrier. On the Relay it continues that entry's approval or Client handoff.

## Several tunnels through the same relay

Names are local labels: 1–32 lowercase letters, digits or hyphens, starting with
a letter. They do not have to match across machines. Use a separate Target
tunnel for each independently paired Client, even when they reach the same SSH
machine. Names do not select a network destination or change a saved Relay origin.

## Remove, restore or permanently stop

**Remove tunnel on a Client or Target** stops that local connection and retains
its private pairing state. Target removal disables its selected service.
The menu asks you to type the tunnel name. Use **Restore removed tunnel**
explicitly to reuse retained identities; then Continue on the Client to check
transport. Restoration requires the rest of the original path to remain valid.

**Remove a tunnel on the Relay** removes that local entry/admission and can
interrupt its traffic. It does not erase endpoint state or trigger their
killswitches. The Relay has no restore menu action for removed admission;
follow **New tunnel** when deliberately building a new path.

**Killswitch on a Client or Target** permanently alarms that pairing, blocks
future authorization and closes local carriers. Type the selected tunnel's
name to confirm. There is no unlock or restore of an alarmed pairing.
A malicious Relay may delay peer cutoff until its remaining authorization lease
expires: at most 60 seconds, plus scheduling and shutdown latency. This cannot
retract delivered bytes or guarantee that SSH-started jobs stop.

An outage never triggers the killswitch automatically. Keep alarmed state for
inspection and use fresh tunnel names and fresh pairing when recovery is
deliberately required. [Recovery guide](SETUP_RECOVERY.md).

## Upgrade software without replacing pairing

Rerun the current installer for the local role. Then open its setup menu.
On the Relay, choose **Start or update this relay** for the selected instance.
On each existing Target tunnel, choose **Continue tunnel** to run the installed
version. Existing Clients use the new executable on the next connection;
Continue verifies their retained tunnels.

Recognized prior installations keep their state and credentials. The package
installer migrates exact owned service hooks and names; unknown commands or
modified units are not overwritten. Failed or interrupted Relay cutover retains
its recovery state. Rerun the displayed setup step with the same public URL;
do not delete journals, replace identities or change SSH to bypass an error.

No CLI compatibility is promised before 1.0. Use 0.7.0 commands after upgrading;
published earlier versions remain immutable. Retained paired state is not an
invitation to mix different historical enrollment profiles.
Routine installation, retry and restart do not silently replace a pairing.

## Uninstall the program

Whole-program uninstall is separate from **Remove tunnel** in a menu.

On Linux, select the local role explicitly; replace `client` below with
`target` or `relay` only on that role's machine:

```sh
curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.7.0/install-linux.sh | sudo sh -s -- client --uninstall
```

Target uninstall stops its owned services and retains their pairing state.
Relay uninstall without an instance selector stops all managed instances and
removes the shared package; keys, disabled units and website routes remain.
It does not remove tunnels from Client or Target machines.

On Mac, use the installed local uninstaller:

```sh
sh "$HOME/Library/Application Support/OwnTransitSoftware/0.7.0/install-macos.sh" --uninstall
```

Uninstall keeps private pairing and alarm state. Reinstallation does not clear
a killswitch or restore an explicitly removed endpoint tunnel automatically.

## Installation trust

The first installer download trusts GitHub HTTPS. The bootstrap then verifies
the pinned distribution signer, exact signed inventory and selected archive
before extraction or execution. Signing keys never belong on the Relay.

Linux software lives under `/opt/owntransit/0.7.0/`; Mac software remains under
the user's `Library/Application Support/OwnTransitSoftware`. Existing default
and named endpoint state locations are retained. No Apple signing subscription
is needed; the Mac Client is not notarized.

Signatures authenticate bytes. Independent security certification,
pristine-host qualification and extended soak testing are not claimed.
Keep independent SSH or console recovery access.
