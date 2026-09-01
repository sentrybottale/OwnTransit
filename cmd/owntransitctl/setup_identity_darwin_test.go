//go:build darwin

package main

import (
	"bytes"
	"testing"
)

func TestDarwinIdentityOutputIsStrictlyCapped(t *testing.T) {
	var output boundedDarwinOutput
	payload := bytes.Repeat([]byte{'x'}, darwinIdentityQueryLimit+4096)
	if written, err := output.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("write = %d, %v", written, err)
	}
	if !output.overflow || len(output.data) != darwinIdentityQueryLimit+1 {
		t.Fatalf("overflow=%v retained=%d", output.overflow, len(output.data))
	}
	if _, err := output.Write(payload); err != nil || len(output.data) != darwinIdentityQueryLimit+1 {
		t.Fatalf("overflow writer grew after cap: %v, %d", err, len(output.data))
	}
}

func TestDarwinGeneratedUIDParserRequiresOneCanonicalField(t *testing.T) {
	const canonical = "A78C1F8A-3193-4B9F-BB6F-9A911F0C411B"
	if value, err := parseDarwinGeneratedUID("GeneratedUID: " + canonical); err != nil || value != canonical {
		t.Fatalf("canonical GeneratedUID = %q, %v", value, err)
	}
	for _, invalid := range []string{
		canonical,
		"GeneratedUID: " + canonical + "\nGeneratedUID: " + canonical,
		"GeneratedUID: 00000000-0000-0000-0000-000000000000",
	} {
		if _, err := parseDarwinGeneratedUID(invalid); err == nil {
			t.Fatalf("accepted invalid GeneratedUID output %q", invalid)
		}
	}
}
