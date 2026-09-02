//go:build linux

package main

import (
	"errors"
	"os"
)

func acquireNativePackageMutationGuard(role string) (nativePackageMutationGuard, error) {
	if role == "provisioner" {
		value, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
		if err != nil || !validLinuxProtectedHardlinks(value) {
			return nil, errors.New("Linux provisioner package lifecycle requires fs.protected_hardlinks=1")
		}
	}
	return noOpPackageMutationGuard{}, nil
}

func validLinuxProtectedHardlinks(value []byte) bool {
	return string(value) == "1\n"
}
