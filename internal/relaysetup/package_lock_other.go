//go:build !linux

package relaysetup

import (
	"errors"
	"io"
)

func LockPackage(int) (io.Closer, error) {
	return nil, errors.New("managed relay package operations require Linux")
}
