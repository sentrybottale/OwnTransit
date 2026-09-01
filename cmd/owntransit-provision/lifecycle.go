package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

type signLifecyclePolicyOptions struct {
	policyPath string
	signingKey string
	outputPath string
	now        time.Time
}

type signRollbackOptions struct {
	authorizationPath string
	signingKey        string
	outputPath        string
	now               time.Time
}

type signedRecordSummary struct {
	Schema      string `json:"schema"`
	Kind        string `json:"kind"`
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Size        int    `json:"size"`
	SignerKeyID string `json:"signer_key_id"`
}

func signLifecyclePolicy(options signLifecyclePolicyOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, errors.New("current time is required")
	}
	encoded, err := readRegularFile(options.policyPath, enrollment.MaxLifecyclePolicySize, false)
	if err != nil {
		return nil, fmt.Errorf("unsigned lifecycle policy: %w", err)
	}
	var policy enrollment.LifecyclePolicy
	if err := strictjson.Decode(encoded, &policy); err != nil {
		return nil, fmt.Errorf("decode unsigned lifecycle policy: %w", err)
	}
	privateKey, err := loadSigningKey(options.signingKey)
	if err != nil {
		return nil, err
	}
	signed, err := enrollment.SignLifecyclePolicy(policy, privateKey, now)
	if err != nil {
		return nil, err
	}
	if err := writeAtomicPublicFile(options.outputPath, signed); err != nil {
		return nil, err
	}
	return encodeSignedRecordSummary("lifecycle-policy", options.outputPath, signed, privateKey)
}

func signRollbackAuthorization(options signRollbackOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, errors.New("current time is required")
	}
	encoded, err := readRegularFile(options.authorizationPath, enrollment.MaxRollbackAuthorization, false)
	if err != nil {
		return nil, fmt.Errorf("unsigned rollback authorization: %w", err)
	}
	var authorization enrollment.RollbackAuthorization
	if err := strictjson.Decode(encoded, &authorization); err != nil {
		return nil, fmt.Errorf("decode unsigned rollback authorization: %w", err)
	}
	privateKey, err := loadSigningKey(options.signingKey)
	if err != nil {
		return nil, err
	}
	signed, err := enrollment.SignRollbackAuthorization(authorization, privateKey, now)
	if err != nil {
		return nil, err
	}
	if err := writeAtomicPublicFile(options.outputPath, signed); err != nil {
		return nil, err
	}
	return encodeSignedRecordSummary("rollback-authorization", options.outputPath, signed, privateKey)
}

func loadSigningKey(path string) (ed25519.PrivateKey, error) {
	encoded, err := readRegularFile(path, maxOfflineKeyFileSize, true)
	if err != nil {
		return nil, fmt.Errorf("deployment signing key: %w", err)
	}
	privateKey, err := signing.ParsePrivate(encoded)
	if err != nil {
		return nil, fmt.Errorf("deployment signing key: %w", err)
	}
	return privateKey, nil
}

func encodeSignedRecordSummary(kind, outputPath string, signed []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	digest := sha256.Sum256(signed)
	return encodeSummary(signedRecordSummary{
		Schema: "owntransit.provision.signed-record.v1", Kind: kind,
		File: filepath.Base(outputPath), SHA256: hex.EncodeToString(digest[:]), Size: len(signed),
		SignerKeyID: signing.KeyID(privateKey.Public().(ed25519.PublicKey)),
	})
}
