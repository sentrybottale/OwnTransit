//go:build darwin

package securefs

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateDarwinVolumeACLCapability(t *testing.T) {
	valid := darwinVolumeCapabilityResponse(darwinVolumeSecurityCapability, darwinVolumeSecurityCapability)
	if err := validateDarwinVolumeACLCapability(valid); err != nil {
		t.Fatalf("valid capability response rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short response", mutate: func(response []byte) []byte { return response[:20] }},
		{name: "reported truncation", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[:4], uint32(len(response)+1))
			return response
		}},
		{name: "unexpected extra bytes", mutate: func(response []byte) []byte {
			response = append(response, 0)
			binary.LittleEndian.PutUint32(response[:4], uint32(len(response)))
			return response
		}},
		{name: "missing returned set", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[4:8], 0)
			return response
		}},
		{name: "missing capability attribute", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[8:12], 0)
			return response
		}},
		{name: "unrequested attribute", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[12:16], 1)
			return response
		}},
		{name: "capability not valid", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[44:48], 0)
			return response
		}},
		{name: "capability unsupported", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[28:32], 0)
			return response
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := append([]byte(nil), valid...)
			err := validateDarwinVolumeACLCapability(test.mutate(response))
			if !errors.Is(err, ErrReadOnlyACLVerificationUnavailable) {
				t.Fatalf("error = %v, want ErrReadOnlyACLVerificationUnavailable", err)
			}
		})
	}
}

func TestDarwinSecurityResponseHasACL(t *testing.T) {
	noACL := darwinSecurityResponse(false)
	hasACL, err := darwinSecurityResponseHasACL(noACL)
	if err != nil || hasACL {
		t.Fatalf("no-ACL response = (%v, %v), want (false, nil)", hasACL, err)
	}

	withACL := darwinSecurityResponse(true)
	hasACL, err = darwinSecurityResponseHasACL(withACL)
	if err != nil || !hasACL {
		t.Fatalf("ACL response = (%v, %v), want (true, nil)", hasACL, err)
	}

	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "short response", mutate: func(response []byte) []byte { return response[:20] }},
		{name: "reported truncation", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[:4], uint32(len(response)+1))
			return response
		}},
		{name: "missing returned set", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[4:8], 0)
			return response
		}},
		{name: "unexpected no-ACL payload", mutate: func(response []byte) []byte {
			response = append(response, 0, 0, 0, 0)
			binary.LittleEndian.PutUint32(response[:4], uint32(len(response)))
			return response
		}},
		{name: "unrequested attribute", mutate: func(response []byte) []byte {
			binary.LittleEndian.PutUint32(response[16:20], 1)
			return response
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := append([]byte(nil), noACL...)
			_, err := darwinSecurityResponseHasACL(test.mutate(response))
			if !errors.Is(err, ErrReadOnlyACLVerificationUnavailable) {
				t.Fatalf("error = %v, want ErrReadOnlyACLVerificationUnavailable", err)
			}
		})
	}
}

func TestVerifyNoExtendedACLDarwin(t *testing.T) {
	principal := currentDarwinACLPrincipal(t)
	for _, fixture := range []struct {
		name        string
		directory   bool
		permissions os.FileMode
	}{
		{name: "file", permissions: 0o640},
		{name: "directory", directory: true, permissions: 0o750},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "subject")
			if fixture.directory {
				if err := os.Mkdir(path, fixture.permissions); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("fixture"), fixture.permissions); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()

			if err := verifyNoExtendedACL(int(file.Fd()), fixture.directory); err != nil {
				t.Fatalf("clean object rejected: %v", err)
			}
			addDarwinACL(t, path, principal)
			if err := verifyNoExtendedACL(int(file.Fd()), fixture.directory); err == nil || errors.Is(err, ErrReadOnlyACLVerificationUnavailable) || !strings.Contains(err.Error(), "extended ACL") {
				t.Fatalf("ACL object error = %v, want definite extended-ACL rejection", err)
			}
		})
	}
}

func TestVerifyNoExtendedACLDarwinPinsDescriptor(t *testing.T) {
	principal := currentDarwinACLPrincipal(t)
	directory := t.TempDir()
	cleanPath := filepath.Join(directory, "clean")
	replacementPath := filepath.Join(directory, "replacement")
	if err := os.WriteFile(cleanPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacementPath, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	addDarwinACL(t, replacementPath, principal)

	cleanDescriptor, err := os.Open(cleanPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanDescriptor.Close()
	if err := os.Rename(replacementPath, cleanPath); err != nil {
		t.Fatal(err)
	}
	if err := verifyNoExtendedACL(int(cleanDescriptor.Fd()), false); err != nil {
		t.Fatalf("replaced path changed held descriptor result: %v", err)
	}
	replacementDescriptor, err := os.Open(cleanPath)
	if err != nil {
		t.Fatal(err)
	}
	defer replacementDescriptor.Close()
	if err := verifyNoExtendedACL(int(replacementDescriptor.Fd()), false); err == nil || !strings.Contains(err.Error(), "extended ACL") {
		t.Fatalf("replacement descriptor error = %v, want extended-ACL rejection", err)
	}
}

func darwinVolumeCapabilityResponse(capability, valid uint32) []byte {
	response := make([]byte, darwinAttributeHeaderSize+darwinVolumeCapabilitiesSize)
	binary.LittleEndian.PutUint32(response[:4], uint32(len(response)))
	binary.LittleEndian.PutUint32(response[4:8], darwinAttrCommonReturned)
	binary.LittleEndian.PutUint32(response[8:12], darwinAttrVolumeCapabilities)
	binary.LittleEndian.PutUint32(response[28:32], capability)
	binary.LittleEndian.PutUint32(response[44:48], valid)
	return response
}

func darwinSecurityResponse(hasACL bool) []byte {
	response := make([]byte, darwinAttributeHeaderSize+darwinAttributeReferenceSize)
	binary.LittleEndian.PutUint32(response[:4], uint32(len(response)))
	common := uint32(darwinAttrCommonReturned)
	if hasACL {
		common |= darwinAttrCommonSecurity
	}
	binary.LittleEndian.PutUint32(response[4:8], common)
	return response
}

func currentDarwinACLPrincipal(t *testing.T) string {
	t.Helper()
	output, err := exec.Command("/usr/bin/id", "-un").Output()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	username := strings.TrimSpace(string(output))
	if username == "" {
		t.Fatal("current user name is empty")
	}
	return "user:" + username + " allow write"
}

func addDarwinACL(t *testing.T, path, principal string) {
	t.Helper()
	output, err := exec.Command("/bin/chmod", "+a", principal, path).CombinedOutput()
	if err != nil {
		t.Fatalf("add test ACL: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		_ = exec.Command("/bin/chmod", "-N", path).Run()
	})
}
