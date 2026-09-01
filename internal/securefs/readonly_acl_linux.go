//go:build linux

package securefs

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

// verifyNoExtendedACL rejects any extended-attribute name containing "acl".
// This includes the Linux POSIX access/default ACLs and common NFSv4/Samba ACL
// attributes without pretending an unrecognized ACL namespace is harmless.
func verifyNoExtendedACL(fd int, _ bool) error {
	for attempt := 0; attempt < 4; attempt++ {
		size, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return fmt.Errorf("securefs: enumerate extended ACLs: %w", err)
		}
		if size == 0 {
			return nil
		}
		attributes := make([]byte, size)
		read, err := unix.Flistxattr(fd, attributes)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return fmt.Errorf("securefs: read extended ACL names: %w", err)
		}
		if read < 0 || read > len(attributes) {
			return errors.New("securefs: invalid extended-attribute name length")
		}
		for _, rawName := range strings.Split(string(attributes[:read]), "\x00") {
			if rawName == "" {
				continue
			}
			if strings.Contains(strings.ToLower(rawName), "acl") {
				return fmt.Errorf("securefs: extended ACL %q is not permitted", rawName)
			}
		}
		return nil
	}
	return errors.New("securefs: extended-attribute names changed repeatedly")
}
