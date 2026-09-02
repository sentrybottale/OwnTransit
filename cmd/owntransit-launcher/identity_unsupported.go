//go:build !darwin || (!arm64 && !amd64)

package main

import "errors"

func liveUserUUID(uint32) ([16]byte, error) {
	return [16]byte{}, errors.New("live GeneratedUID resolution is unavailable on this build target")
}
