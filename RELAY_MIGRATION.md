# Relay migration in 0.6.0

The normal relay installer accepts the operator's public URL first. Without an
explicit instance name, setup selects the exact protected local URL binding.
It does not assume that every URL belongs to `default`. An explicit
`--instance NAME` remains restrictive: a different existing URL is rejected,
never silently reassigned. This is local deployment selection, not endpoint
relay switching or a new network authority.

## Supported older installations

A recognized manual relay has an exact OwnTransit systemd launch contract,
same-named container, digest-selected image, derived state path, fixed container
command, loopback-only host publication and expected unprivileged confinement.
The selected existing website route and relay identity must match that
local deployment. Public verification is normally required; the narrowly
reported HTTP 403 case below is separate. Modified units, overrides, conflicting owners, unknown state
files or inaccessible required inventories stop migration before ownership
changes. Setup does not guess at arbitrary services or containers.

The migration review shows the selected URL, local instance, old unit/container,
retained data directory and port. The operator confirms that exact local
operation. Applying the plan rechecks its evidence under the global manager
lock; a changed plan is not accepted as the earlier consent.

## What is retained and removed

- Retain the exact relay key/certificate files, public URL and existing website
  route. No SSH or endpoint identity is copied, reset, issued or edited.
- Reuse the original key directory as the managed instance's validated data
  mount. Do not duplicate or move live key material.
- Create the regular managed unit/container and complete its protected binding
  and setup records. Ordinary URL-based approval, upgrade and scoped uninstall
  then use this same managed identity.
- Retire the superseded manual unit, its automatic restart configuration and
  its stopped container through exact ownership checks. Never force-remove an
  unrecognized container, prune images globally or delete volumes.
- Retain private migration evidence and the old immutable image for recovery.
  Retained key data or rollback evidence is not a second running installation.
- Leave other relays, their keys and website configuration outside the operation.
  Shared host compromise/resources remain outside instance isolation.

## Protected binding and state boundaries

Existing ordinary `owntransit.relay-instance.v1` bindings remain supported.
An imported instance uses `owntransit.relay-instance.v2` with a validated
`legacy_data_label`, from which its historical data path is derived. It is not
an arbitrary host path. Reserved names, paths overlapping the default or another
instance, equal underlying directories and shared container mounts are rejected.
All managed operations must use the same derived data root: migration, setup,
approval, cleanup, upgrade, rollback and removal.

An unused same-URL reservation may have a different allocated port from the
working manual relay. It is eligible for reconciliation only when it has no
independent installed identity or completed setup and its remaining unit/pending
record are recognized and inactive. The migration journal retains that previous
reservation before selecting the verified working port. Other management cannot
allocate around an unfinished transaction.

Older managers reject the new binding schema. Installing an older manager is
not a supported rollback of an imported instance; use the transaction's recovery
path. Existing unimported v1 instances keep their ordinary compatibility.

## Transaction and recovery

The root-private `owntransit.relay-migration.v1` journal binds the old and new
reservations, exact source unit/container/image, intended managed configuration,
public relay identity and identity-file digests. It contains no private key
contents. The bounded journal and protected records are checked before use.

1. Validate the source, destination and rollback image; authenticate the new
   installed image before changing services.
2. Persist the prepared journal and guard the old unit against restarting
   across an interrupted handoff. Stop only that validated source.
3. Select the new protected binding, start the managed service with the same
   keys and loopback port, and verify its actual image/confinement and public
   protocol identity.
4. Persist the completed setup and committed journal before final old-unit and
   stopped-container cleanup. Remove the global journal only after completion.

A precommit failure restores the previous reservation and old service. A
committed interruption finishes cleanup instead of undoing verified ownership.
Rerunning the same confirmed setup recovers and completes the requested
migration when the same resource and identity still verify; unexpected outside
changes stop it. Failed recovery is reported, never represented as success.
Other operations cannot bypass a pending migration to steal its resources.

This does not preserve a relay's volatile in-memory mailbox. Completed pairings
retain their identity; compatible pending receivers can republish their offers
and previously approved admission. A still-unclaimed legacy attempt may require
its public approval command again. No network error clears alarms or creates
fresh endpoint trust automatically.

## Acceptance evidence

Exercise the real supported container inspection shapes and root-only disposable
fixtures for migration success, rerun, ordinary URL approval and scoped removal;
wrong identity/mount/port/unit/owner; stale reservations with data or active
services; shared state; failed public verification; interrupted prepared and
committed phases; and preservation of an independent default relay and website.
Then test the installed command flow through receiver setup, approval, client
pairing and SSH. Package installation alone is not end-to-end completion.

## Access policies that block the VPS's own probe

Some sites permit their intended client networks but deny requests originating
from the VPS. An administration-only WebSocket probe may classify HTTP 403 only
after direct, certificate-verified TLS 1.3 to the exact selected hostname. It
does not follow redirects, use ambient proxies, change DNS targets or accept a
private address. Endpoint dialers and authentication remain unchanged.

A denial is never converted into invented server information or ordinary
public-verification success. The separate **local-route-http-403** result requires
an exact protected local site-to-port mapping, the running immutable image and
confinement, and the retained locally verified identity and key-file digests.
Migration consent and final output disclose that public reachability remains
unverified from this VPS. Receiver and client setup from permitted networks
must complete the real public connection normally; there are no extra codes.

DNS/connect/TLS errors, redirects, other HTTP statuses, bad WebSocket protocol
and a successful response with the wrong identity still fail. A previously
public-verified migration cannot silently downgrade to local-only verification
during cutover. Fresh setup must install its approved route and reread it as
the exact mapping before it can report limited completion. Older upgrade
journals without the required identity baseline retain strict public checks.
This changes neither the access policy nor OwnTransit endpoint trust.
