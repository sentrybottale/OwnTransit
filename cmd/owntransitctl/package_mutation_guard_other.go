//go:build !darwin && !linux

package main

func acquireNativePackageMutationGuard(string) (nativePackageMutationGuard, error) {
	return noOpPackageMutationGuard{}, nil
}
