//go:build darwin

package main

import "errors"

func nativePackageReaderGID(role string) (int, error) {
	if role != "client" {
		return 0, errors.New("macOS package lifecycle supports only the installed client reader identity")
	}
	identity, err := loadInstalledSetupClientIdentity()
	if err != nil {
		return 0, err
	}
	return int(identity.readerGID), nil
}
