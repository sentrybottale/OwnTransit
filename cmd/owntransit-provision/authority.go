package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const (
	authoritySummaryFile       = "summary.json"
	outerIssuerCertFile        = "outer-endpoint-ca-cert.pem"
	outerIssuerKeyFile         = "outer-endpoint-ca-key.pem"
	innerConnectorCertFile     = "inner-connector-ca-cert.pem"
	innerConnectorKeyFile      = "inner-connector-ca-key.pem"
	innerClientIssuerCertFile  = "inner-client-capability-ca-cert.pem"
	innerClientIssuerKeyFile   = "inner-client-capability-ca-key.pem"
	deploymentSignerPublicFile = "deployment-signing-public.pem"
	deploymentSignerKeyFile    = "deployment-signing-key.pem"

	// A route authority is offline and narrowly scoped, but compromise can mint
	// reachability capabilities for that route. Keep its lifetime finite and
	// force an explicit two-year root rotation ceremony.
	authorityValidity = 2 * 365 * 24 * time.Hour
)

type initAuthorityOptions struct {
	outputDir string
	now       time.Time
}

type authorityIssuerSummary struct {
	CertificateFile string `json:"certificate_file"`
	CertificatePin  string `json:"certificate_pin"`
}

type deploymentSignerSummary struct {
	PublicKeyFile string `json:"public_key_file"`
	KeyID         string `json:"key_id"`
}

type authoritySummary struct {
	Schema                string                  `json:"schema"`
	Scope                 string                  `json:"scope"`
	RouteID               string                  `json:"route_id"`
	CreatedUnix           int64                   `json:"created_unix"`
	OuterEndpointIssuer   authorityIssuerSummary  `json:"outer_endpoint_issuer"`
	InnerConnectorIssuer  authorityIssuerSummary  `json:"inner_connector_issuer"`
	InnerClientCapability authorityIssuerSummary  `json:"inner_client_capability_issuer"`
	DeploymentSigner      deploymentSignerSummary `json:"deployment_signer"`
}

func initAuthority(options initAuthorityOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	if options.outputDir == "" || now.IsZero() {
		return nil, errors.New("output directory and current time are required")
	}
	route, err := protocol.NewRouteID()
	if err != nil {
		return nil, fmt.Errorf("generate route ID: %w", err)
	}

	outerIssuer, err := pki.NewCA(authorityIssuerName(route, "outer endpoint"), now, authorityValidity)
	if err != nil {
		return nil, err
	}
	innerConnectorIssuer, err := pki.NewCA(authorityIssuerName(route, "inner connector"), now, authorityValidity)
	if err != nil {
		return nil, err
	}
	innerClientIssuer, err := pki.NewCA(authorityIssuerName(route, "inner client capability"), now, authorityValidity)
	if err != nil {
		return nil, err
	}
	deploymentSigner, err := signing.Generate()
	if err != nil {
		return nil, err
	}
	if err := requireDistinctAuthorityKeys(
		outerIssuer,
		innerConnectorIssuer,
		innerClientIssuer,
		deploymentSigner,
	); err != nil {
		return nil, err
	}

	outerPin, err := pki.CertificatePin(outerIssuer.Certificate)
	if err != nil {
		return nil, err
	}
	innerConnectorPin, err := pki.CertificatePin(innerConnectorIssuer.Certificate)
	if err != nil {
		return nil, err
	}
	innerClientPin, err := pki.CertificatePin(innerClientIssuer.Certificate)
	if err != nil {
		return nil, err
	}
	summary := authoritySummary{
		Schema:      "owntransit.provision.authority.v1",
		Scope:       "single-route",
		RouteID:     route.String(),
		CreatedUnix: now.Unix(),
		OuterEndpointIssuer: authorityIssuerSummary{
			CertificateFile: outerIssuerCertFile, CertificatePin: outerPin,
		},
		InnerConnectorIssuer: authorityIssuerSummary{
			CertificateFile: innerConnectorCertFile, CertificatePin: innerConnectorPin,
		},
		InnerClientCapability: authorityIssuerSummary{
			CertificateFile: innerClientIssuerCertFile, CertificatePin: innerClientPin,
		},
		DeploymentSigner: deploymentSignerSummary{
			PublicKeyFile: deploymentSignerPublicFile, KeyID: deploymentSigner.KeyID,
		},
	}
	summaryBytes, err := encodeSummary(summary)
	if err != nil {
		return nil, err
	}

	root, err := createOutputRoot(options.outputDir)
	if err != nil {
		return nil, fmt.Errorf("create authority directory: %w", err)
	}
	writes := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{outerIssuerCertFile, outerIssuer.CertPEM, 0o644},
		{outerIssuerKeyFile, outerIssuer.KeyPEM, 0o600},
		{innerConnectorCertFile, innerConnectorIssuer.CertPEM, 0o644},
		{innerConnectorKeyFile, innerConnectorIssuer.KeyPEM, 0o600},
		{innerClientIssuerCertFile, innerClientIssuer.CertPEM, 0o644},
		{innerClientIssuerKeyFile, innerClientIssuer.KeyPEM, 0o600},
		{deploymentSignerPublicFile, deploymentSigner.PublicPEM, 0o644},
		{deploymentSignerKeyFile, deploymentSigner.PrivatePEM, 0o600},
		{authoritySummaryFile, summaryBytes, 0o644},
	}
	for _, file := range writes {
		if err := root.CreateExclusive(file.name, file.data, file.mode); err != nil {
			_ = root.Close()
			return nil, fmt.Errorf("write authority material: %w", err)
		}
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	return summaryBytes, nil
}

func authorityIssuerName(route protocol.RouteID, purpose string) string {
	return "OwnTransit route " + route.String() + " " + purpose + " CA"
}

func requireDistinctAuthorityKeys(
	outerIssuer, innerConnectorIssuer, innerClientIssuer pki.Material,
	deploymentSigner signing.KeyPair,
) error {
	deploymentPublic, err := x509.MarshalPKIXPublicKey(deploymentSigner.Public)
	if err != nil {
		return fmt.Errorf("marshal deployment signer: %w", err)
	}
	keys := [][]byte{
		outerIssuer.Certificate.RawSubjectPublicKeyInfo,
		innerConnectorIssuer.Certificate.RawSubjectPublicKeyInfo,
		innerClientIssuer.Certificate.RawSubjectPublicKeyInfo,
		deploymentPublic,
	}
	for first := range keys {
		if len(keys[first]) == 0 {
			return errors.New("generated authority contains an empty public key")
		}
		for second := first + 1; second < len(keys); second++ {
			if bytes.Equal(keys[first], keys[second]) {
				return errors.New("generated authority keys are not distinct")
			}
		}
	}
	return nil
}

func encodeSummary(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode public summary: %w", err)
	}
	return append(encoded, '\n'), nil
}
