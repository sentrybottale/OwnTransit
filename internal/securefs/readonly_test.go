//go:build darwin || linux

package securefs

import (
	"errors"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadOnlyRootMethodSetIsNonMutating(t *testing.T) {
	allowed := map[string]bool{
		"Close":              true,
		"Metadata":           true,
		"OpenDir":            true,
		"ReadFile":           true,
		"ReadRootSymlink":    true,
		"Recheck":            true,
		"TrySharedLock":      true,
		"ValidateExactFiles": true,
	}
	typeOfRoot := reflect.TypeOf((*ReadOnlyRoot)(nil))
	for index := 0; index < typeOfRoot.NumMethod(); index++ {
		method := typeOfRoot.Method(index)
		if !allowed[method.Name] {
			t.Errorf("ReadOnlyRoot unexpectedly exports method %q", method.Name)
		}
		delete(allowed, method.Name)
	}
	for method := range allowed {
		t.Errorf("ReadOnlyRoot is missing expected method %q", method)
	}
}

func TestValidateReadOnlyReaderGIDRequiresExactNonRootPrimaryGroup(t *testing.T) {
	if _, err := validateReadOnlyReaderGID(0, 0); err == nil {
		t.Fatal("accepted the root group as a dedicated runtime reader group")
	}
	if _, err := validateReadOnlyReaderGID(42, 41); err == nil {
		t.Fatal("accepted a reader GID that did not match the effective primary GID")
	}
	if gid, err := validateReadOnlyReaderGID(42, 42); err != nil || gid != 42 {
		t.Fatalf("exact reader GID = %d, %v", gid, err)
	}
}

func TestReadOnlyStatPolicyRejectsWrongOwnerGroupAndMode(t *testing.T) {
	const (
		ownerUID  uint32 = 100
		readerGID uint32 = 200
	)
	directory := unix.Stat_t{
		Mode: unix.S_IFDIR | 0o750,
		Uid:  ownerUID,
		Gid:  readerGID,
	}
	if err := validateReadOnlyDirectoryStat(directory, ownerUID, readerGID); err != nil {
		t.Fatalf("valid directory policy: %v", err)
	}

	wrongOwner := directory
	wrongOwner.Uid++
	if err := validateReadOnlyDirectoryStat(wrongOwner, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a directory owned by the wrong user")
	}
	wrongGroup := directory
	wrongGroup.Gid++
	if err := validateReadOnlyDirectoryStat(wrongGroup, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a directory owned by the wrong group")
	}
	wrongMode := directory
	wrongMode.Mode = unix.S_IFDIR | 0o755
	if err := validateReadOnlyDirectoryStat(wrongMode, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a directory with a non-exact mode")
	}

	file := unix.Stat_t{
		Mode:  unix.S_IFREG | 0o640,
		Nlink: 1,
		Uid:   ownerUID,
		Gid:   readerGID,
		Size:  1,
	}
	if err := validateReadOnlyFileStat(file, ownerUID, readerGID); err != nil {
		t.Fatalf("valid file policy: %v", err)
	}
	wrongFileOwner := file
	wrongFileOwner.Uid++
	if err := validateReadOnlyFileStat(wrongFileOwner, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a file owned by the wrong user")
	}
	wrongFileGroup := file
	wrongFileGroup.Gid++
	if err := validateReadOnlyFileStat(wrongFileGroup, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a file owned by the wrong group")
	}
	wrongFileMode := file
	wrongFileMode.Mode = unix.S_IFREG | 0o440
	if err := validateReadOnlyFileStat(wrongFileMode, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a file with a non-exact mode")
	}
	writableFile := file
	writableFile.Mode = unix.S_IFREG | 0o660
	if err := validateReadOnlyFileStat(writableFile, ownerUID, readerGID); err == nil {
		t.Fatal("accepted a group-writable file")
	}
}

func TestReadOnlyStatPolicyRejectsWritableAncestorAndSpecialFile(t *testing.T) {
	ancestor := unix.Stat_t{Mode: unix.S_IFDIR | 0o755, Uid: 0}
	if err := validateReadOnlyAncestorStat(ancestor, 0); err != nil {
		t.Fatalf("valid ancestor policy: %v", err)
	}
	writable := ancestor
	writable.Mode = unix.S_IFDIR | 0o775
	if err := validateReadOnlyAncestorStat(writable, 0); err == nil {
		t.Fatal("accepted a group-writable ancestor")
	}
	wrongOwner := ancestor
	wrongOwner.Uid = 1
	if err := validateReadOnlyAncestorStat(wrongOwner, 0); err == nil {
		t.Fatal("accepted a non-root-owned ancestor")
	}

	special := unix.Stat_t{
		Mode:  unix.S_IFIFO | 0o640,
		Nlink: 1,
		Uid:   0,
		Gid:   42,
	}
	if err := validateReadOnlyFileStat(special, 0, 42); err == nil {
		t.Fatal("accepted a special file")
	}
	hardlinked := special
	hardlinked.Mode = unix.S_IFREG | 0o640
	hardlinked.Nlink = 2
	if err := validateReadOnlyFileStat(hardlinked, 0, 42); err == nil {
		t.Fatal("accepted a multiply linked regular file")
	}
}

func TestOpenReadOnlyRootRejectsNonCanonicalPathAndWrongCallerGID(t *testing.T) {
	readerGID := unix.Getegid()
	if readerGID == 0 {
		readerGID = 42
	}
	for _, path := range []string{"", ".", "/", "/tmp/../tmp/runtime", "/tmp//runtime", "/tmp/not portable"} {
		if _, err := OpenReadOnlyRoot(path, readerGID); err == nil {
			t.Errorf("OpenReadOnlyRoot accepted non-canonical path %q", path)
		}
	}

	effective := unix.Getegid()
	wrong := effective + 1
	if wrong == 0 {
		wrong++
	}
	if _, err := OpenReadOnlyRoot("/definitely-not-opened", wrong); err == nil {
		t.Fatal("OpenReadOnlyRoot accepted a mismatched caller primary GID")
	}
}

func TestReadOnlyRootClosedErrors(t *testing.T) {
	var root *ReadOnlyRoot
	if _, err := root.Metadata(); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("nil Metadata = %v, want ErrReadOnlyClosed", err)
	}
	if _, err := root.OpenDir("child"); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("nil OpenDir = %v, want ErrReadOnlyClosed", err)
	}
	if _, err := root.ReadFile("file", 1); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("nil ReadFile = %v, want ErrReadOnlyClosed", err)
	}
	if _, err := root.ReadRootSymlink("current", 64); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("nil ReadRootSymlink = %v, want ErrReadOnlyClosed", err)
	}
	if err := root.Recheck(); !errors.Is(err, ErrReadOnlyClosed) {
		t.Fatalf("nil Recheck = %v, want ErrReadOnlyClosed", err)
	}
	if err := root.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}
