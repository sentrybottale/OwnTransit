//go:build darwin

package main

import (
	"errors"

	"github.com/sentrybottale/owntransit/internal/packagetxn"
	"github.com/sentrybottale/owntransit/internal/securefs"
)

const (
	darwinIdentityRoot     = "/Library/OwnTransit/identity"
	darwinIdentityReceipt  = "client-reader.v1"
	darwinLauncherAuthRoot = "/Library/OwnTransit/launcher-auth"
	darwinLauncherBinding  = "client.v1"
)

func finalizeNativePackageMutation(role string, result packagetxn.Result) error {
	if role == "provisioner" {
		if result.Role != role || result.Current == "" || result.Runtime.ReleaseID != result.Current || result.Runtime.Role != role {
			return errors.New("Darwin package finalization requires the authenticated current provisioner result")
		}
		return nil
	}
	if role != "client" || result.Role != role || result.Current == "" || result.Runtime.ReleaseID != result.Current {
		return errors.New("Darwin package finalization requires the authenticated current client result")
	}
	identityRoot, err := securefs.OpenRoot(darwinIdentityRoot)
	if err != nil {
		return err
	}
	receipt, readErr := identityRoot.ReadFile(darwinIdentityReceipt, maxDarwinReaderReceipt)
	closeErr := identityRoot.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	binding, readerGID, err := renderDarwinLauncherBinding(receipt, result.Runtime)
	if err != nil {
		return err
	}
	writer, err := securefs.OpenViewRoot(darwinLauncherAuthRoot, readerGID)
	if err != nil {
		return err
	}
	if err := writer.ReplaceFile(darwinLauncherBinding, binding); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return publishDarwinClientFrontend(receipt, result.Runtime)
}
