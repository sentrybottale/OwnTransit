# Setup recovery

**Receiver configured → relay approved → client paired → end-to-end check passed.**
Until the final check passes, a new tunnel is **UNDER CONSTRUCTION**.
SSH login still requires your independently managed SSH keys and host verification.

## Lost the private code

The relay never holds a readable private code. Its approval output prints a
complete retrieval command for the exact public receiver ID. Run that command
on the **receiving SSH machine**, not the VPS. No memorising is required.

If you lost the command too, run on the receiving machine:

```sh
sudo owntransit-connector-preview pair list
```

The list prints a **Private code** command for each local tunnel. Run that exact
command. It shows the same unused, unexpired `otpair2.` code: the receiver ID,
VPS approval and expiration do not change. Transfer the code directly to your
client using your existing authenticated SSH/console access. Never put it in a
VPS terminal, ticket or shared log.

Codes created by 0.6.0 and earlier were not retained and cannot be reconstructed
from their hash. Upgrade the connector to 0.6.1, then run its retrieval command:
it will print the exact explicit replacement command if the old code is missing.

## Expired or deliberately replaced code

On the receiving machine, use the printed `pair setup --replace` command with
the same local tunnel selector. This is deliberately **not** a normal retry:

- It creates a new receiver ID and code and retires the old pairing.
- A paired receiver asks for confirmation before replacement.
- Run its **new approval command** on the VPS.
- Start a fresh client pairing with the new code. If the client retains an old
  request or pairing, `pair next` prints an unused local name for this explicit
  new pairing, preserving the old state.

Do not use replacement merely because the network or a service is temporarily down.

## What do I run next?

These commands inspect local state and print the actual scoped next commands:

| Where you are | Command |
|---|---|
| Receiving SSH machine | `sudo owntransit-connector-preview pair next` |
| Linux client | `/usr/local/bin/owntransit-preview pair next` |
| Apple-silicon Mac client | `"$HOME/.local/bin/owntransit-preview" pair next` |
| VPS | `sudo owntransit-relay-preview list` |

For a named tunnel, use the `Next commands` line from `pair list` rather than
guessing a name. An explicit custom `--state` path must stay the same.

| What happened | Safe next action |
|---|---|
| Receiver service stopped | Run the receiver's printed `pair restart` command; keys and code stay unchanged. |
| VPS approval missing | Client setup prints the exact public VPS approval command, after authenticating the receiver offer. Run it, then retry with the same code. |
| Client setup interrupted after saving its request | Run the exact `pair resume` command from `pair next`; no new code or keys. |
| Pairing saved but transport check failed | Run the exact client `pair check` command from `pair next`. Keep the pairing. |
| Already paired | Repeated setup preserves identities and checks the client's transport; it does not silently re-pair. |
| Security alarm | The old pairing stays disabled. `pair next` explains deliberate fresh pairing, never an unlock. |
| State cannot be read safely | Inspect the displayed local path/permissions. Do not delete state or disable verification. A deliberate separate pairing is offered when appropriate. |

The client check uses the same outer mTLS, inner mTLS, fresh authorization and
receiver-local fixed SSH dial as a real connection. Only that live result prints
**TUNNEL READY**. Local pairing files and a relay approval are not evidence that
the peer is reachable now. Ordinary outages never become permanent security alarms.
