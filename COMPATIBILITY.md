# OwnTransit wire compatibility

## Relay management in 0.6.0

The local `owntransit.relay-instance.v2` binding adds a validated derived legacy
data label for explicit manual relay migration. The bounded
`owntransit.relay-migration.v1` journal covers ownership cutover and recovery.
These are local manager formats, not a new carrier/enrollment protocol. Existing
v1 instances remain supported; older managers reject imported v2 bindings instead
of guessing data paths. See [migration and rollback](RELAY_MIGRATION.md).

The 0.5.0 one-code pairing and runtime wire profiles below remain unchanged.

OwnTransit is the only public product and artifact name. A small set of
authenticated byte strings predates that name and remains frozen in the v1
wire profile:

```text
forthgate/1
forthgate-relay/1
forthgate-exact-pins/1
forthgate.carrier.v1
relay.forthgate.invalid
*.forthgate.invalid
```

The rendezvous `FGAT` magic, `FGRD` READY marker, version bytes, frame encoding,
and legacy certificate identity prefix are frozen with those strings. They are
not a compatibility claim about, dependency on, or integration with another
product. They are authenticated inputs: silently renaming one would break
deployed peers or create a downgrade ambiguity.

The exact constants live together in `internal/wireprofile/legacy_v1.go` and
have byte-exact regression tests. Product names, package names, commands,
images, filesystem paths, diagnostics, and documentation must otherwise use
OwnTransit.

Any future change requires a separately identified wire profile, explicit
selection on both endpoints, mixed-version and cross-wire tests, downgrade
analysis, and documented migration and rollback ceremonies. The relay cannot
choose or negotiate a weaker profile on an endpoint's behalf.

## Receiver-owned profile (0.1.1 development)

Selection is explicit through the `pair` commands, never inferred from a relay
response. The public WebSocket subprotocol is `owntransit.carrier.v2`, its outer
TLS ALPN is `owntransit-relay-admission/2`, and the inner TLS ALPN is
`owntransit-paired-lease/1`. The signed setup profile is
`owntransit-receiver-pairing/1`. OTLW frames carry SSH DATA and authorization
controls only inside that authenticated inner session. The existing FGRD READY
marker remains byte-exact, carried as DATA after authorization and fixed dial.

No v1 fallback, TOFU, implicit pin replacement or automatic enrollment conversion
exists. Mixed profiles reject before SSH dial. New state uses separate private
roots. Published 0.1.0 bytes are immutable; rollback selects the old binary and
its separately retained old state, never interprets pairing state as legacy
authority. The operator owns cutover and independent recovery access.

The signed 0.1.1 development preview uses strict local policy schema
`owntransit.paired-policy.v2`: a local alarm is terminal. It rejects earlier
clearable v1 development policy rather than converting it. Older v1 readers
reject v2 records, preventing a casual downgrade from clearing the alarm.
Whole-state rollback/cloning or root compromise remains outside this guarantee.

## One-code setup extension (0.5.0)

The explicitly selected `owntransit.receiver-offer.v1` extension adds OTR2
public operations 9–11 and `otpair2.` input. Existing frame magic, TLS ALPN,
WebSocket subprotocol, signed advertisement and endpoint request/response
formats are unchanged. New setup rejects unsupported relays before replacing
trust; it never silently falls back. Completed pairings need no migration.
The optional public sidecar does not alter strict persisted authority schemas.
See [wire details, mixed-version behavior and rollback](PAIRING_ONE_CODE.md).
