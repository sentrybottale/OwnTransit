//go:build darwin

package main

import "github.com/sentrybottale/owntransit/internal/packagetxn"

func runSupervisedPackageMutation(_ string, preflight func() error, operation func() (packagetxn.Result, error)) (packagetxn.Result, error) {
	if err := preflight(); err != nil {
		return packagetxn.Result{}, err
	}
	return operation()
}
