//go:build darwin && (arm64 || amd64)

package main

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

func liveUserUUID(uid uint32) ([16]byte, error) {
	var value [16]byte
	result, _, errno := launcherSyscall6(
		libcMbrUIDToUUIDTrampolineAddress,
		uintptr(uid),
		uintptr(unsafe.Pointer(&value[0])),
		0, 0, 0, 0,
	)
	runtime.KeepAlive(&value)
	if errno != 0 {
		return [16]byte{}, fmt.Errorf("mbr_uid_to_uuid trampoline: %w", errno)
	}
	if result != 0 {
		return [16]byte{}, fmt.Errorf("mbr_uid_to_uuid: %w", syscall.Errno(result))
	}
	if value == ([16]byte{}) {
		return [16]byte{}, fmt.Errorf("mbr_uid_to_uuid returned the zero UUID")
	}
	return value, nil
}

// launcherSyscall6 and the assembly trampoline follow the pinned Go 1.26
// standard-library/x/sys Darwin libc-call convention. This intentional
// go:linkname coupling requires compile and native execution qualification for
// every supported Go toolchain and Darwin architecture.
//
//go:linkname launcherSyscall6 syscall.syscall6
func launcherSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var libcMbrUIDToUUIDTrampolineAddress uintptr

//go:cgo_import_dynamic libc_mbr_uid_to_uuid mbr_uid_to_uuid "/usr/lib/libSystem.B.dylib"
