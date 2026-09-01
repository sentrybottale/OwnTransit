package enrollmentexchange

import "testing"

func TestNewMailboxExchangeSeparatesAllActionCapabilitiesAndRequestIdentity(t *testing.T) {
	target, operator, recipient, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	if err := operator.validateAgainst(target, recipient); err != nil {
		t.Fatal(err)
	}
	if operator.RequestDecryptionIdentity == "" || recipient == "" {
		t.Fatal("request encryption material is absent")
	}
}

func TestOperatorExchangeRejectsCrossWiringAndCapabilityReuse(t *testing.T) {
	target, operator, recipient, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	otherTarget, otherOperator, otherRecipient, err := newMailboxExchange("wss://relay.example.com/connects/enrollment")
	if err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name      string
		target    targetExchange
		operator  operatorExchange
		recipient string
	}{
		{"mailbox", otherTarget, operator, otherRecipient},
		{"identity", target, otherOperator, recipient},
		{"capability reuse", target, func() operatorExchange {
			value := operator
			value.RequestReadCapability = target.RequestWriteCapability
			return value
		}(), recipient},
		{"commitment mismatch", target, func() operatorExchange {
			value := operator
			value.ResponseWriteCapability = testCapability(0xa4)
			return value
		}(), recipient},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.operator.validateAgainst(check.target, check.recipient); err == nil {
				t.Fatal("cross-wired mailbox exchange was accepted")
			}
		})
	}
}
