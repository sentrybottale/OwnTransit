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
