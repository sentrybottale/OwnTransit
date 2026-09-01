// Package strictjson decodes one bounded-by-caller JSON value while rejecting
// duplicate object keys, unknown destination fields, and trailing values.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Decode decodes exactly one JSON value into destination. Callers remain
// responsible for applying an input-size limit before calling Decode.
func Decode(encoded []byte, destination any) error {
	if len(encoded) == 0 {
		return errors.New("strictjson: empty input")
	}
	if !utf8.Valid(encoded) {
		return errors.New("strictjson: input is not valid UTF-8")
	}
	if err := rejectDuplicateKeys(encoded); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("strictjson: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("strictjson: more than one JSON value")
		}
		return fmt.Errorf("strictjson: trailing data: %w", err)
	}
	return nil
}

func rejectDuplicateKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := consumeValue(decoder); err != nil {
		return fmt.Errorf("strictjson: structure: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("strictjson: more than one JSON value")
		}
		return fmt.Errorf("strictjson: trailing data: %w", err)
	}
	return nil
}

func consumeValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			// encoding/json matches destination fields without regard to ASCII
			// case after trying an exact match. Reject those aliases as well as
			// byte-identical duplicates so one Go field cannot be assigned twice.
			normalizedKey := strings.ToLower(key)
			if _, duplicate := seen[normalizedKey]; duplicate {
				return errors.New("duplicate or case-aliased object key")
			}
			seen[normalizedKey] = struct{}{}
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object has an invalid closing delimiter")
		}
		return nil

	case '[':
		for decoder.More() {
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array has an invalid closing delimiter")
		}
		return nil

	default:
		return errors.New("unexpected closing delimiter")
	}
}
