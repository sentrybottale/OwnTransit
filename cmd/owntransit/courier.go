//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"golang.org/x/sys/unix"
)

const (
	courierRequestFile      = "encrypted-request.otreq"
	courierRegistrationFile = "courier-registration.otreg"
)

func registerCourierMailbox(registrationPath, credentialStore string) error {
	registration, err := readCourierFile(registrationPath, enrollmentexchange.MaxCourierRegistrationSize)
	if err != nil {
		return err
	}
	courier := enrollmentexchange.NewCourier()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return courier.RegisterFromCredentialStore(ctx, registration, credentialStore)
}

func fetchCourierRequest(registrationPath, outputRoot string) error {
	registration, err := readCourierFile(registrationPath, enrollmentexchange.MaxCourierRegistrationSize)
	if err != nil {
		return err
	}
	root, err := createOrOpenCourierRoot(outputRoot)
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock("courier.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := root.EnsureFile(courierRegistrationFile, registration, 0o600); err != nil {
		return err
	}
	if existing, readErr := root.ReadFile(courierRequestFile, enrollmentexchange.MaxEncryptedRequestSize); readErr == nil && len(existing) != 0 {
		return nil
	}
	courier := enrollmentexchange.NewCourier()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	request, err := courier.ReadRegisteredRequest(ctx, registration)
	if err != nil {
		return err
	}
	return root.EnsureFile(courierRequestFile, request, 0o600)
}

func uploadCourierResponse(registrationPath, responsePath string) error {
	registration, err := readCourierFile(registrationPath, enrollmentexchange.MaxCourierRegistrationSize)
	if err != nil {
		return err
	}
	response, err := readCourierFile(responsePath, enrollmentexchange.MaxBoundResponseSize)
	if err != nil {
		return err
	}
	courier := enrollmentexchange.NewCourier()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return courier.PutRegisteredResponse(ctx, registration, response)
}

func createOrOpenCourierRoot(path string) (*securefs.Root, error) {
	if path == "" {
		return nil, errors.New("courier output root is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) == string(filepath.Separator) {
		return nil, errors.New("courier output root is invalid")
	}
	absolute = filepath.Clean(absolute)
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	resolved := filepath.Join(parent, filepath.Base(absolute))
	root, err := securefs.CreateRoot(resolved)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	return securefs.OpenRoot(resolved)
}

func readCourierFile(path string, limit int) ([]byte, error) {
	if path == "" || limit <= 0 || int64(limit) > securefs.MaxReadBytes {
		return nil, errors.New("bounded courier input is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open courier input: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open courier input: invalid descriptor")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size < 1 || before.Size > int64(limit) ||
		before.Uid != uint32(unix.Geteuid()) || os.FileMode(before.Mode).Perm()&0o077 != 0 {
		return nil, errors.New("courier input must be a private bounded single-link regular file")
	}
	encoded, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(encoded) == 0 || len(encoded) > limit {
		return nil, errors.New("courier input changed or exceeded its bound")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || after.Size != int64(len(encoded)) || after.Nlink != 1 {
		return nil, errors.New("courier input changed while being read")
	}
	return encoded, nil
}
