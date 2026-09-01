//go:build linux

package packagetxn

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/unix"
)

func verifyPackageACL(fd int, _ bool) error {
	for attempt := 0; attempt < 4; attempt++ {
		size, err := unix.Flistxattr(fd, nil)
		if err != nil {
			return fmt.Errorf("enumerate extended ACLs: %w", err)
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
			return fmt.Errorf("read extended ACL names: %w", err)
		}
		if read < 0 || read > len(attributes) {
			return errors.New("invalid extended-attribute name length")
		}
		for _, name := range strings.Split(string(attributes[:read]), "\x00") {
			if strings.Contains(strings.ToLower(name), "acl") {
				return fmt.Errorf("extended ACL %q is not permitted", name)
			}
		}
		return nil
	}
	return errors.New("extended-attribute names changed repeatedly")
}
