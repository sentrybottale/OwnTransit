package strictjson

import (
	"strings"
	"testing"
)

type testRecord struct {
	Name   string `json:"name"`
	Nested struct {
		Value int `json:"value"`
	} `json:"nested"`
}

func TestDecodeAcceptsOneStrictValue(t *testing.T) {
	var record testRecord
	if err := Decode([]byte(`{"name":"example","nested":{"value":1}}`), &record); err != nil {
		t.Fatal(err)
	}
	if record.Name != "example" || record.Nested.Value != 1 {
		t.Fatalf("unexpected decoded record: %#v", record)
	}
}

func TestDecodeRejectsAmbiguousInput(t *testing.T) {
	tests := map[string]string{
		"top-level duplicate":    `{"name":"first","name":"second","nested":{"value":1}}`,
		"case-aliased duplicate": `{"name":"first","Name":"second","nested":{"value":1}}`,
		"nested duplicate":       `{"name":"example","nested":{"value":1,"value":2}}`,
		"unknown field":          `{"name":"example","nested":{"value":1},"extra":true}`,
		"multiple values":        `{"name":"example","nested":{"value":1}} {}`,
		"empty input":            ``,
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			var record testRecord
			if err := Decode([]byte(encoded), &record); err == nil {
				t.Fatal("ambiguous JSON input was accepted")
			}
		})
	}
}

func TestDecodeRejectsInvalidUTF8(t *testing.T) {
	encoded := append([]byte(`{"name":"`), 0xff)
	encoded = append(encoded, []byte(`","nested":{"value":1}}`)...)
	var record testRecord
	if err := Decode(encoded, &record); err == nil {
		t.Fatal("invalid UTF-8 was accepted")
	}
}

func TestDuplicateErrorDoesNotEchoKey(t *testing.T) {
	const secret = "do-not-echo-this-value"
	var record testRecord
	err := Decode([]byte(`{"`+secret+`":1,"`+secret+`":2}`), &record)
	if err == nil {
		t.Fatal("duplicate key was accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("strict decoder error exposed a JSON key")
	}
}
