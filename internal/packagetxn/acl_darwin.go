//go:build darwin

package packagetxn

import "github.com/sentrybottale/owntransit/internal/securefs"

// ErrACLVerificationUnavailable is returned by the shared descriptor verifier
// if the Darwin filesystem cannot authoritatively report extended security.
var ErrACLVerificationUnavailable = securefs.ErrReadOnlyACLVerificationUnavailable

func verifyPackageACL(fd int, directory bool) error {
	return securefs.VerifyNoExtendedACLFD(fd, directory)
}
