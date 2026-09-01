//go:build darwin && (arm64 || amd64)

package securefs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// These values and layouts are the stable Darwin getattrlist ABI from
// <sys/attr.h>. The assembly bridge below deliberately calls libSystem rather
// than the unsupported direct syscall entry point.
const (
	darwinAttrBitMapCount          = 5
	darwinAttrCommonReturned       = 0x80000000
	darwinAttrCommonSecurity       = 0x00400000
	darwinAttrVolumeCapabilities   = 0x00020000
	darwinAttrVolumeInfo           = 0x80000000
	darwinFSOptReportFullSize      = 0x00000004
	darwinVolumeSecurityCapability = 0x00000400

	darwinReturnedAttributeSetSize = 20
	darwinAttributeHeaderSize      = 4 + darwinReturnedAttributeSetSize
	darwinAttributeReferenceSize   = 8
	darwinVolumeCapabilitiesSize   = 32
	darwinMaximumAttributeBuffer   = 8192
)

type darwinAttrList struct {
	BitmapCount uint16
	Reserved    uint16
	Common      uint32
	Volume      uint32
	Directory   uint32
	File        uint32
	Fork        uint32
}

// verifyNoExtendedACL rejects every Darwin extended ACL. It first requires the
// filesystem to authoritatively report support for extended security, then
// asks for ATTR_CMN_EXTENDED_SECURITY on the already-open object. Absence is
// accepted only when the complete, bounded response says that attribute was
// not returned.
func verifyNoExtendedACL(fd int, _ bool) error {
	if unsafe.Sizeof(darwinAttrList{}) != 24 {
		return fmt.Errorf("%w: unexpected Darwin attrlist ABI", ErrReadOnlyACLVerificationUnavailable)
	}

	capabilitiesRequest := darwinAttrList{
		BitmapCount: darwinAttrBitMapCount,
		Common:      darwinAttrCommonReturned,
		Volume:      darwinAttrVolumeInfo | darwinAttrVolumeCapabilities,
	}
	var capabilities [darwinAttributeHeaderSize + darwinVolumeCapabilitiesSize]byte
	if err := darwinFgetattrlist(fd, &capabilitiesRequest, capabilities[:]); err != nil {
		return fmt.Errorf("%w: query Darwin volume ACL capability: %v", ErrReadOnlyACLVerificationUnavailable, err)
	}
	if err := validateDarwinVolumeACLCapability(capabilities[:]); err != nil {
		return err
	}

	securityRequest := darwinAttrList{
		BitmapCount: darwinAttrBitMapCount,
		Common:      darwinAttrCommonReturned | darwinAttrCommonSecurity,
	}
	var security [darwinMaximumAttributeBuffer]byte
	if err := darwinFgetattrlist(fd, &securityRequest, security[:]); err != nil {
		return fmt.Errorf("%w: query Darwin extended security: %v", ErrReadOnlyACLVerificationUnavailable, err)
	}
	hasACL, err := darwinSecurityResponseHasACL(security[:])
	if err != nil {
		return err
	}
	if hasACL {
		return errors.New("securefs: extended ACL is not permitted")
	}
	return nil
}

func validateDarwinVolumeACLCapability(response []byte) error {
	response, err := validateDarwinAttributeResponse(response, darwinAttributeHeaderSize+darwinVolumeCapabilitiesSize)
	if err != nil {
		return fmt.Errorf("%w: volume capability response: %v", ErrReadOnlyACLVerificationUnavailable, err)
	}
	if len(response) != darwinAttributeHeaderSize+darwinVolumeCapabilitiesSize {
		return fmt.Errorf("%w: unexpected volume capability response size %d", ErrReadOnlyACLVerificationUnavailable, len(response))
	}
	common, volume, directory, file, fork := darwinReturnedAttributes(response)
	if common & ^uint32(darwinAttrCommonReturned) != 0 ||
		volume & ^uint32(darwinAttrVolumeInfo|darwinAttrVolumeCapabilities) != 0 ||
		directory != 0 || file != 0 || fork != 0 {
		return fmt.Errorf("%w: volume capability response returned an unrequested attribute", ErrReadOnlyACLVerificationUnavailable)
	}
	if common&darwinAttrCommonReturned == 0 || volume&darwinAttrVolumeCapabilities == 0 {
		return fmt.Errorf("%w: filesystem omitted the requested volume capability", ErrReadOnlyACLVerificationUnavailable)
	}

	// vol_capabilities_attr_t is capabilities[4] followed by valid[4].
	// Extended security is an interface capability (array index 1).
	capability := binary.LittleEndian.Uint32(response[28:32])
	valid := binary.LittleEndian.Uint32(response[44:48])
	if valid&darwinVolumeSecurityCapability == 0 {
		return fmt.Errorf("%w: filesystem does not validate its extended-security capability", ErrReadOnlyACLVerificationUnavailable)
	}
	if capability&darwinVolumeSecurityCapability == 0 {
		return fmt.Errorf("%w: filesystem does not support authoritative extended-security inspection", ErrReadOnlyACLVerificationUnavailable)
	}
	return nil
}

func darwinSecurityResponseHasACL(response []byte) (bool, error) {
	response, err := validateDarwinAttributeResponse(response, darwinAttributeHeaderSize+darwinAttributeReferenceSize)
	if err != nil {
		return false, fmt.Errorf("%w: extended-security response: %v", ErrReadOnlyACLVerificationUnavailable, err)
	}
	common, volume, directory, file, fork := darwinReturnedAttributes(response)
	if common & ^uint32(darwinAttrCommonReturned|darwinAttrCommonSecurity) != 0 ||
		volume != 0 || directory != 0 || file != 0 || fork != 0 {
		return false, fmt.Errorf("%w: extended-security response returned an unrequested attribute", ErrReadOnlyACLVerificationUnavailable)
	}
	if common&darwinAttrCommonReturned == 0 {
		return false, fmt.Errorf("%w: filesystem omitted ATTR_CMN_RETURNED_ATTRS", ErrReadOnlyACLVerificationUnavailable)
	}
	if common&darwinAttrCommonSecurity != 0 {
		return true, nil
	}
	if len(response) != darwinAttributeHeaderSize+darwinAttributeReferenceSize {
		return false, fmt.Errorf("%w: unexpected no-ACL response size %d", ErrReadOnlyACLVerificationUnavailable, len(response))
	}
	return false, nil
}

func validateDarwinAttributeResponse(response []byte, minimum int) ([]byte, error) {
	if len(response) < 4 {
		return nil, errors.New("attribute response has no length field")
	}
	fullSize := uint64(binary.LittleEndian.Uint32(response[:4]))
	if fullSize < uint64(minimum) {
		return nil, fmt.Errorf("attribute response length %d is smaller than %d", fullSize, minimum)
	}
	if fullSize > uint64(len(response)) {
		return nil, fmt.Errorf("attribute response requires %d bytes but buffer has %d", fullSize, len(response))
	}
	return response[:int(fullSize)], nil
}

func darwinReturnedAttributes(response []byte) (common, volume, directory, file, fork uint32) {
	return binary.LittleEndian.Uint32(response[4:8]),
		binary.LittleEndian.Uint32(response[8:12]),
		binary.LittleEndian.Uint32(response[12:16]),
		binary.LittleEndian.Uint32(response[16:20]),
		binary.LittleEndian.Uint32(response[20:24])
}

func darwinFgetattrlist(fd int, attributes *darwinAttrList, response []byte) error {
	if fd < 0 || attributes == nil || len(response) == 0 {
		return syscall.EINVAL
	}
	_, _, errno := syscallSyscall6(
		libcFgetattrlistTrampolineAddress,
		uintptr(fd),
		uintptr(unsafe.Pointer(attributes)),
		uintptr(unsafe.Pointer(&response[0])),
		uintptr(len(response)),
		darwinFSOptReportFullSize,
		0,
	)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(response)
	if errno != 0 {
		return errno
	}
	return nil
}

// syscallSyscall6 and the libSystem trampoline intentionally mirror the
// Go 1.26 standard-library/x/sys Darwin convention. This is CGO-free, but it
// is toolchain-coupled: every supported Go toolchain must compile and execute
// the Darwin integration tests before release.
//
//go:linkname syscallSyscall6 syscall.syscall6
func syscallSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

var libcFgetattrlistTrampolineAddress uintptr

//go:cgo_import_dynamic libc_fgetattrlist fgetattrlist "/usr/lib/libSystem.B.dylib"
