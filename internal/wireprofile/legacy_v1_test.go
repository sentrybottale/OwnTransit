package wireprofile

import "testing"

func TestLegacyV1AuthenticatedBytesRemainExact(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"protocol":            "forthgate/1",
		"relay ALPN":          "forthgate-relay/1",
		"relay DNS name":      "relay.forthgate.invalid",
		"exact-pins profile":  "forthgate-exact-pins/1",
		"WebSocket protocol":  "forthgate.carrier.v1",
		"identity prefix":     "fg-",
		"connector suffix":    ".connector.forthgate.invalid",
		"outer connector":     ".outer-connector.forthgate.invalid",
		"client suffix":       ".client.forthgate.invalid",
		"outer client suffix": ".outer-client.forthgate.invalid",
	}
	got := map[string]string{
		"protocol":            LegacyV1Protocol,
		"relay ALPN":          LegacyV1RelayALPN,
		"relay DNS name":      LegacyV1RelayDNSName,
		"exact-pins profile":  LegacyV1ExactPinsProfile,
		"WebSocket protocol":  LegacyV1WebSocketSubprotocol,
		"identity prefix":     LegacyV1IdentityPrefix,
		"connector suffix":    LegacyV1ConnectorSuffix,
		"outer connector":     LegacyV1OuterConnectorSuffix,
		"client suffix":       LegacyV1ClientSuffix,
		"outer client suffix": LegacyV1OuterClientSuffix,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("%s changed: got %q, want %q", name, got[name], expected)
		}
	}
}
