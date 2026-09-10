# Recover an OwnTransit 0.7.0 tunnel

A new tunnel stays **UNDER CONSTRUCTION** until the Client completes its actual
authenticated end-to-end check. Relay approval and local pairing state are
saved steps, not proof of a working connection. SSH login uses your own keys
and independently verified host identity afterward.

## Open the menu on the machine you are using

| Machine | Command |
|---|---|
| Relay VPS | `sudo owntransit-relay setup` |
| Target running SSH | `sudo owntransit-target setup` |
| Linux Client | `owntransit-client setup` as your ordinary user |
| Apple-silicon Mac Client | `"$HOME/.local/bin/owntransit-client" setup` without sudo |

Choose **List tunnels** to identify the local entry, then choose **Continue
tunnel** for it. Use the saved name and Relay URL.
A normal retry never needs a new identity.

## Lost the private code

On the **Target**, choose **Continue tunnel** and select the tunnel waiting
for its Client. It starts that service and displays the same unused, unexpired
`otpair2.` code. The public Target ID, Relay approval and expiry stay unchanged.

The code is recoverable only on that Target. The Relay may print an exact
Target-local retrieval command, but it cannot reveal the code.
Transfer the code directly to the intended Client through your independently
authenticated SSH or console access. Never paste it into a Relay terminal,
shell argument, environment variable or support ticket.

If the Target is already paired, no new code is needed: continue the matching
Client tunnel. If the code expired, was consumed, or was created by an older
release that did not retain it, it cannot be reconstructed or extended.

## Interrupted setup or an unavailable service

| Situation | Next action |
|---|---|
| Target stopped or software was upgraded | Target menu → Continue tunnel |
| Relay approval missing | Relay menu → Continue a tunnel → select the draft → enter the public Target ID |
| Client request was saved before interruption | Client menu → Continue tunnel; it resumes that request |
| Pairing saved, end-to-end check failed | Client menu → Continue tunnel; it checks the retained pairing |
| Relay needs its installed software activated | Relay menu → Start or update this relay |
| Local state or a managed service cannot be read safely | Keep the state; resolve the reported ownership/configuration problem before retrying |

If a Relay operation reported an interruption, reopen its setup menu and use
the same Relay URL. Do not delete its recovery records. Unknown units and
modified ownership are deliberately refused.

A Relay self-check blocked by HTTP 403 can be reported as **local verification
only**. That is not proof of public reachability and does not change the access
policy. Continue from an allowed Client network and require its real check.

Outages, failed authentication and lost packets never trigger a permanent
killswitch or automatic trust reset. Active SSH sessions can disconnect and
are not replayed through a new connection.

## When a fresh pairing is deliberate

For an unusable old code or a deliberately new relationship, start with
**New tunnel** in the Relay menu. Follow its Target and Client steps with
unused local names. The Target creates a new public ID and private code;
the Relay must approve that new ID.

Keep old state for inspection. Remove an old tunnel separately if you intend
to stop using it. Do not replace or delete a saved pairing merely because an
ordinary network retry failed. Published versions are immutable; use the
current commands after upgrading, without assuming CLI compatibility before 1.0.

## Removed is different from alarmed

**Removed on a Client or Target:** the local connection is disabled and private
state is retained. Choose **Restore removed tunnel**, select it and type its
name to confirm. Then Continue on the Client to check the original path.

If removal was interrupted, repeat **Remove tunnel** on that same entry until
it completes before attempting restoration. A failed Target start after restore
can be retried with **Continue tunnel**; it does not require fresh keys.

**Removed on the Relay:** that Relay's entry/admission is removed. Endpoint
state and killswitch state are unchanged. Restoring only an endpoint cannot
repair a removed Relay admission; the Relay menu directs you to **New tunnel**
when you deliberately build a new path.

**Killswitch / security alarm:** the old pairing is permanently disabled.
Neither Restore nor reinstall can unlock it. Keep the alarmed state and follow
the fresh-pairing flow when deliberate recovery is appropriate. Do not restore
a backup to bypass the alarm.

The killswitch closes local carriers and blocks authorization. A malicious
Relay can delay peer cutoff until the remaining lease expires, at most
60 seconds plus scheduling and shutdown latency. Delivered bytes and
SSH-started jobs remain outside that guarantee.

## Uninstalling is a separate action

**Remove tunnel** affects the selected tunnel, not the installed program.
Use the local installer for whole-program uninstall. Software uninstall retains
pairing and alarm state and does not manage SSH.

See [installation and uninstall](PAIRING_INSTALL.md) for the exact role-specific
commands. Keep independent SSH or console access for recovery.
