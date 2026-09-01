//go:build linux

package main

import "github.com/sentrybottale/owntransit/internal/packagetxn"

func finalizeNativePackageMutation(_ string, _ packagetxn.Result) error {
	return nil
}
