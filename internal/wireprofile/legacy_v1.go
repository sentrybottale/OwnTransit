// Package wireprofile owns authenticated compatibility identifiers.
//
// These values are protocol bytes, not product branding. Changing any value
// requires a new wire version, mixed-version tests, downgrade analysis, and an
// explicit migration and rollback design.
package wireprofile

const (
	LegacyV1Protocol             = "forthgate/1"
	LegacyV1RelayALPN            = "forthgate-relay/1"
	LegacyV1RelayDNSName         = "relay.forthgate.invalid"
	LegacyV1ExactPinsProfile     = "forthgate-exact-pins/1"
	LegacyV1WebSocketSubprotocol = "forthgate.carrier.v1"

	LegacyV1IdentityPrefix       = "fg-"
	LegacyV1ConnectorSuffix      = ".connector.forthgate.invalid"
	LegacyV1OuterConnectorSuffix = ".outer-connector.forthgate.invalid"
	LegacyV1ClientSuffix         = ".client.forthgate.invalid"
	LegacyV1OuterClientSuffix    = ".outer-client.forthgate.invalid"
)
