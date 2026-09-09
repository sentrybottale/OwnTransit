package relaysetup

import "errors"

// ValidateInstanceName validates a local administrative label, never a wire
// identity or a connector destination. An omitted selector means default.
func ValidateInstanceName(name string) error {
	if name == "" {
		return nil
	}
	if len(name) > 32 || name == "all" || name[0] < 'a' || name[0] > 'z' {
		return errors.New("instance names must be 1–32 lowercase letters, digits or hyphens, start with a letter, and cannot be all")
	}
	for _, c := range []byte(name) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return errors.New("invalid relay instance name")
		}
	}
	return nil
}

func normalizedInstanceName(name string) (string, error) {
	if err := ValidateInstanceName(name); err != nil {
		return "", err
	}
	if name == "" {
		name = "default"
	}
	return name, nil
}
