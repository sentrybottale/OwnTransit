package config

import (
	"strings"
	"testing"
)

func TestInMemoryConfigParsersRejectDuplicateAndCaseAliasedKeys(t *testing.T) {
	for _, encoded := range []string{
		`{"relay_url":"wss://relay.example/connects","relay_url":"wss://other.example/connects"}`,
		`{"relay_url":"wss://relay.example/connects","Relay_URL":"wss://other.example/connects"}`,
	} {
		if _, err := ParseClient([]byte(encoded)); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("ParseClient(%s) error = %v, want duplicate-key rejection", encoded, err)
		}
	}
}

func TestInMemoryConfigParsersRejectUnknownAndTrailingValues(t *testing.T) {
	if _, err := ParseConnector([]byte(`{"unexpected":true}`)); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("ParseConnector unknown-field error = %v", err)
	}
	if _, err := ParseRelay([]byte(`{} {}`)); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("ParseRelay trailing-value error = %v", err)
	}
}
