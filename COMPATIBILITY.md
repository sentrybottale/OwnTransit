# OwnTransit wire compatibility

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
