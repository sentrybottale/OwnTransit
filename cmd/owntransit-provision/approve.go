package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const (
	relayResponseFile     = "relay-response.otb"
	connectorResponseFile = "connector-response.otb"
	clientResponseFile    = "client-response.otb"
	responseSummaryFile   = "summary.json"

	initialLeafValidity       = 30 * 24 * time.Hour
	initialDeploymentValidity = 24 * time.Hour
)

type approveInitialRouteOptions struct {
	relayRequest                         string
	connectorRequest                     string
	clientRequest                        string
	outerIssuerCert                      string
	outerIssuerKey                       string
	innerConnectorIssuerCert             string
	innerConnectorIssuerKey              string
	innerClientIssuerCert                string
	innerClientIssuerKey                 string
	deploymentSigningKey                 string
	relayURL                             string
	relayListen                          string
	enrollmentAllocationCapabilitySHA256 string
	outputDir                            string
	deploymentSequence                   uint64
	now                                  time.Time
}

type responseFileSummary struct {
	Role   enrollment.Role `json:"role"`
	File   string          `json:"file"`
	SHA256 string          `json:"sha256"`
	Size   int             `json:"size"`
}

type routeResponseSummary struct {
	Schema             string                `json:"schema"`
	RouteID            string                `json:"route_id"`
	ApprovedUnix       int64                 `json:"approved_unix"`
	DeploymentSequence uint64                `json:"deployment_sequence"`
	SignerKeyID        string                `json:"signer_key_id"`
	Responses          []responseFileSummary `json:"responses"`
}

func approveInitialRoute(options approveInitialRouteOptions) ([]byte, error) {
	options.deploymentSequence = 1
	return approveRouteResponses(options, false)
}

func approveRouteRotation(options approveInitialRouteOptions) ([]byte, error) {
	if options.deploymentSequence <= 1 {
		return nil, errors.New("rotation deployment sequence must be greater than one")
	}
	return approveRouteResponses(options, true)
}

func approveRouteResponses(options approveInitialRouteOptions, rotation bool) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if now.IsZero() {
		return nil, errors.New("current time is required")
	}
	relayRequest, err := readRegularFile(options.relayRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, fmt.Errorf("relay request: %w", err)
	}
	connectorRequest, err := readRegularFile(options.connectorRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, fmt.Errorf("connector request: %w", err)
	}
	clientRequest, err := readRegularFile(options.clientRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, fmt.Errorf("client request: %w", err)
	}

	connectorPayload, err := enrollment.ParseRequest(connectorRequest, now)
	if err != nil || connectorPayload.Role != enrollment.RoleConnector {
		return nil, errors.New("connector request is invalid or has the wrong role")
	}
	route, err := protocol.ParseRouteID(connectorPayload.RouteID)
	if err != nil || route == (protocol.RouteID{}) {
		return nil, errors.New("connector request has an invalid route ID")
	}

	outerIssuer, err := loadIssuerPair(options.outerIssuerCert, options.outerIssuerKey, now)
	if err != nil {
		return nil, fmt.Errorf("outer endpoint issuer: %w", err)
	}
	innerConnectorIssuer, err := loadIssuerPair(options.innerConnectorIssuerCert, options.innerConnectorIssuerKey, now)
	if err != nil {
		return nil, fmt.Errorf("inner connector issuer: %w", err)
	}
	innerClientIssuer, err := loadIssuerPair(options.innerClientIssuerCert, options.innerClientIssuerKey, now)
	if err != nil {
		return nil, fmt.Errorf("inner client capability issuer: %w", err)
	}
	for _, check := range []struct {
		material pki.Material
		purpose  string
	}{
		{outerIssuer, "outer endpoint"},
		{innerConnectorIssuer, "inner connector"},
		{innerClientIssuer, "inner client capability"},
	} {
		if check.material.Certificate.Subject.CommonName != authorityIssuerName(route, check.purpose) {
			return nil, fmt.Errorf("%s issuer is scoped to a different route", check.purpose)
		}
	}

	deploymentKeyPEM, err := readRegularFile(options.deploymentSigningKey, maxOfflineKeyFileSize, true)
	if err != nil {
		return nil, fmt.Errorf("deployment signing key: %w", err)
	}
	deploymentSigner, err := signing.ParsePrivate(deploymentKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("deployment signing key: %w", err)
	}
	approval := enrollment.RouteApproval{
		RelayRequest:                         relayRequest,
		ConnectorRequest:                     connectorRequest,
		ClientRequest:                        clientRequest,
		RelayURL:                             options.relayURL,
		RelayListen:                          options.relayListen,
		EnrollmentAllocationCapabilitySHA256: options.enrollmentAllocationCapabilitySHA256,
		DeploymentSequence:                   options.deploymentSequence,
		Now:                                  now,
		LeafValidity:                         initialLeafValidity,
		DeploymentValidity:                   initialDeploymentValidity,
		Issuers: enrollment.Issuers{
			RelayAdmission: outerIssuer,
			InnerConnector: innerConnectorIssuer,
			InnerClient:    innerClientIssuer,
		},
		DeploymentSigner: deploymentSigner,
	}
	var responses enrollment.RouteResponses
	if rotation {
		responses, err = enrollment.ApproveRouteRotation(approval)
	} else {
		responses, err = enrollment.ApproveInitialRoute(approval)
	}
	if err != nil {
		return nil, err
	}

	files := []struct {
		role enrollment.Role
		name string
		data []byte
	}{
		{enrollment.RoleRelay, relayResponseFile, responses.RelayEnvelope},
		{enrollment.RoleConnector, connectorResponseFile, responses.ConnectorEnvelope},
		{enrollment.RoleClient, clientResponseFile, responses.ClientEnvelope},
	}
	publicFiles := make([]responseFileSummary, 0, len(files))
	for _, file := range files {
		digest := sha256.Sum256(file.data)
		publicFiles = append(publicFiles, responseFileSummary{
			Role: file.role, File: file.name, SHA256: hex.EncodeToString(digest[:]), Size: len(file.data),
		})
	}
	schema := "owntransit.provision.initial-route-responses.v1"
	if rotation {
		schema = "owntransit.provision.route-rotation-responses.v1"
	}
	summary := routeResponseSummary{
		Schema:             schema,
		RouteID:            route.String(),
		ApprovedUnix:       now.Unix(),
		DeploymentSequence: options.deploymentSequence,
		SignerKeyID:        signing.KeyID(deploymentSigner.Public().(ed25519.PublicKey)),
		Responses:          publicFiles,
	}
	summaryBytes, err := encodeSummary(summary)
	if err != nil {
		return nil, err
	}

	root, err := createOutputRoot(options.outputDir)
	if err != nil {
		return nil, fmt.Errorf("create response directory: %w", err)
	}
	// Every member is staged and atomically renamed within the new 0700 root.
	// summary.json is written last and is the only completion marker; an
	// interrupted directory without that marker is never an approved bundle.
	for _, file := range files {
		if err := root.ReplaceFile(file.name, file.data, fs.FileMode(0o600)); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("write encrypted response: %w", err)
		}
	}
	if err := root.ReplaceFile(responseSummaryFile, summaryBytes, fs.FileMode(0o644)); err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("write response summary: %w", err)
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	return summaryBytes, nil
}

func loadIssuerPair(certificatePath, keyPath string, now time.Time) (pki.Material, error) {
	certificatePEM, err := readRegularFile(certificatePath, maxOfflineKeyFileSize, false)
	if err != nil {
		return pki.Material{}, err
	}
	keyPEM, err := readRegularFile(keyPath, maxOfflineKeyFileSize, true)
	if err != nil {
		return pki.Material{}, err
	}
	return pki.ParseIssuer(certificatePEM, keyPEM, now)
}
