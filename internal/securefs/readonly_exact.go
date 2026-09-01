//go:build darwin || linux

package securefs

import (
	"errors"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

// ValidateExactFiles proves that this held read-only directory contains only
// the sorted unique set of exact root:reader-group 0640 regular files named by
// the caller. It does not expose descriptors or directory-entry metadata.
func (root *ReadOnlyRoot) ValidateExactFiles(names []string) error {
	want := append([]string(nil), names...)
	sort.Strings(want)
	for index, name := range want {
		if err := validateComponent(name); err != nil {
			return err
		}
		if index > 0 && want[index-1] == name {
			return errors.New("securefs: read-only exact file set contains a duplicate")
		}
	}
	if root == nil {
		return ErrReadOnlyClosed
	}
	root.mu.RLock()
	defer root.mu.RUnlock()
	if !root.open {
		return ErrReadOnlyClosed
	}
	if err := requireReadOnlyCallerGroup(root.readerGID); err != nil {
		return err
	}
	actual, err := directoryNames(root.fd)
	if err != nil {
		return err
	}
	if len(actual) != len(want) {
		return errors.New("securefs: read-only directory does not contain the exact file set")
	}
	for index, name := range actual {
		if name != want[index] {
			return errors.New("securefs: read-only directory does not contain the exact file set")
		}
		fd, err := unix.Openat(root.fd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("securefs: open exact read-only member %q: %w", name, err)
		}
		if _, err := inspectReadOnlyFile(fd, root.ownerUID, root.readerGID); err != nil {
			_ = unix.Close(fd)
			return err
		}
		if err := unix.Close(fd); err != nil {
			return fmt.Errorf("securefs: close exact read-only member %q: %w", name, err)
		}
	}
	return nil
}
