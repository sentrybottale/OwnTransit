//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/enrollmentsetup"
	"github.com/sentrybottale/owntransit/internal/packagetxn"
)

type installedSetupClientIdentity struct {
	clientUser   string
	clientUID    uint32
	primaryGroup string
	primaryGID   uint32
	readerGID    uint32
}

func stageClientSetup() ([]byte, error) {
	invitation, err := enrollmentsetup.ReadFrame(os.Stdin, enrollmentsetup.FrameInvitation, enrollmentexchange.MaxInvitationSize)
	if err != nil {
		return nil, err
	}
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.Stage(invitation, now)
	})
}

func statusClientSetup() ([]byte, error) {
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.Status(now)
	})
}

func confirmClientSetup() ([]byte, error) {
	payload, err := enrollmentsetup.ReadFrame(os.Stdin, enrollmentsetup.FrameReverseWords, 64)
	if err != nil {
		return nil, err
	}
	words, err := enrollmentsetup.DecodeReverseWords(payload)
	if err != nil {
		return nil, err
	}
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.Confirm(words, now)
	})
}

func acceptClientSetup() ([]byte, error) {
	response, err := enrollmentsetup.ReadFrame(os.Stdin, enrollmentsetup.FrameBoundResponse, enrollmentexchange.MaxBoundResponseSize)
	if err != nil {
		return nil, err
	}
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.AcceptAndApply(response, now)
	})
}

func resumeClientSetup() ([]byte, error) {
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.ResumeApply(now)
	})
}

func cancelClientSetup() ([]byte, error) {
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.Cancel(now)
	})
}

func readyClientSetup() ([]byte, error) {
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, identity installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.CompleteReady(context.Background(), func(ctx context.Context) error {
			return runInstalledClientReadyProbe(ctx, identity)
		}, now)
	})
}

func cleanupClientSetup() ([]byte, error) {
	return runClientSetup(func(client *enrollmentsetup.Client, now time.Time, _ installedSetupClientIdentity) (enrollmentsetup.State, error) {
		return client.CleanupReady(now)
	})
}

func runClientSetup(operation func(*enrollmentsetup.Client, time.Time, installedSetupClientIdentity) (enrollmentsetup.State, error)) ([]byte, error) {
	if os.Geteuid() != 0 || operation == nil {
		return nil, errors.New("client setup requires the installed privileged lifecycle boundary")
	}
	setupIdentity, err := loadInstalledSetupClientIdentity()
	if err != nil {
		return nil, err
	}
	manager, err := openNativePackageLifecycle("client")
	if err != nil {
		return nil, err
	}
	var encoded []byte
	err = manager.WithCurrentRuntimeIdentity(func(identity packagetxn.RuntimeIdentity) error {
		binding := enrollment.RuntimeBinding{
			ReleaseID: identity.ReleaseID, ReleaseSequence: identity.ReleaseSequence,
			ArtifactSHA256: identity.ArtifactSHA256, OS: identity.OS, Arch: identity.Arch,
			Role: enrollment.Role(identity.Role), Protocol: enrollment.DeploymentProtocol,
			LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
		}
		client, err := enrollmentsetup.OpenClient(binding, int(setupIdentity.readerGID))
		if err != nil {
			return err
		}
		state, err := operation(client, time.Now().UTC(), setupIdentity)
		if err != nil {
			return err
		}
		encoded, err = enrollmentsetup.EncodeState(state)
		return err
	})
	closeErr := manager.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return encoded, nil
}
