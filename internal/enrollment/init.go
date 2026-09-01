package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

type InitOptions struct {
	Role                    Role
	InstallationID          string
	RouteID                 string
	ConnectorInstallationID string
	Sequence                uint64
	Now                     time.Time
	RequestValidity         time.Duration
	Trust                   Trust
	DeploymentSigner        ed25519.PublicKey
	Runtime                 RuntimeBinding
}

// PendingMaterial is generated and retained by one target. Only RequestBytes
// and its digest are public/exportable; private keys and ResponseIdentity never
// leave the target state transaction.
type PendingMaterial struct {
	RequestBytes     []byte
	Payload          RequestPayload
	OuterPrivateKey  []byte
	InnerPrivateKey  []byte
	ResponseIdentity string
}

func NewPendingRequest(options InitOptions) (PendingMaterial, error) {
	now := options.Now.UTC().Truncate(time.Second)
	if now.IsZero() || options.Sequence == 0 || options.RequestValidity <= 0 || options.RequestValidity > MaxRequestValidity {
		return PendingMaterial{}, errors.New("enrollment: request time, sequence, and bounded validity are required")
	}
	if len(options.DeploymentSigner) != ed25519.PublicKeySize {
		return PendingMaterial{}, errors.New("enrollment: deployment verifier is not Ed25519")
	}
	installationID, err := protocol.ParseID(options.InstallationID)
	if err != nil || installationID == (protocol.ID{}) {
		return PendingMaterial{}, errors.New("enrollment: target installation ID is invalid")
	}
	pins, err := IssuerPinsFromTrust(options.Trust, now)
	if err != nil {
		return PendingMaterial{}, err
	}
	if err := options.Runtime.Validate(options.Role); err != nil {
		return PendingMaterial{}, err
	}

	var outerName, innerName string
	switch options.Role {
	case RoleRelay:
		if options.RouteID != "" || options.ConnectorInstallationID != "" {
			return PendingMaterial{}, errors.New("enrollment: relay init cannot select a route or connector")
		}
		outerName = config.RelayDNSName
	case RoleConnector:
		if options.ConnectorInstallationID != "" {
			return PendingMaterial{}, errors.New("enrollment: connector init cannot select another connector")
		}
		route, err := protocol.ParseRouteID(options.RouteID)
		if err != nil || route == (protocol.RouteID{}) {
			return PendingMaterial{}, errors.New("enrollment: connector route ID is invalid")
		}
		outerName = config.OuterConnectorDNSName(route)
		innerName = config.CapabilityConnectorDNSName(installationID, route)
	case RoleClient:
		route, err := protocol.ParseRouteID(options.RouteID)
		if err != nil || route == (protocol.RouteID{}) {
			return PendingMaterial{}, errors.New("enrollment: client route ID is invalid")
		}
		connectorID, err := protocol.ParseID(options.ConnectorInstallationID)
		if err != nil || connectorID == (protocol.ID{}) {
			return PendingMaterial{}, errors.New("enrollment: client connector installation ID is invalid")
		}
		outerName = config.OuterClientDNSName(installationID)
		innerName = config.ClientCapabilityDNSName(installationID, connectorID, route, options.Sequence)
	default:
		return PendingMaterial{}, errors.New("enrollment: target role is invalid")
	}

	outer, err := pki.NewCSR(outerName)
	if err != nil {
		return PendingMaterial{}, err
	}
	var inner pki.CSRMaterial
	if innerName != "" {
		inner, err = pki.NewCSR(innerName)
		if err != nil {
			return PendingMaterial{}, err
		}
	}
	responseIdentity, responseRecipient, err := GenerateResponseIdentity()
	if err != nil {
		return PendingMaterial{}, err
	}
	nonce, err := protocol.NewID()
	if err != nil {
		return PendingMaterial{}, fmt.Errorf("enrollment: generate request nonce: %w", err)
	}
	payload := RequestPayload{
		Schema: RequestSchema, Role: options.Role, InstallationID: installationID.String(),
		RouteID: options.RouteID, ConnectorInstallationID: options.ConnectorInstallationID,
		Nonce: nonce.String(), Sequence: options.Sequence, CreatedUnix: now.Unix(),
		ExpiresUnix: now.Add(options.RequestValidity).Unix(), ResponseRecipient: responseRecipient,
		IssuerPins: pins, DeploymentSignerKeyID: signing.KeyID(options.DeploymentSigner), Runtime: options.Runtime,
		OuterCSR: string(outer.CSRPEM), InnerCSR: string(inner.CSRPEM),
	}
	requestBytes, err := SignRequest(payload, outer.Signer, now)
	if err != nil {
		return PendingMaterial{}, err
	}
	return PendingMaterial{
		RequestBytes: requestBytes, Payload: payload,
		OuterPrivateKey: append([]byte(nil), outer.KeyPEM...), InnerPrivateKey: append([]byte(nil), inner.KeyPEM...),
		ResponseIdentity: responseIdentity,
	}, nil
}

func IssuerPinsFromTrust(trust Trust, now time.Time) (IssuerPins, error) {
	values := []string{trust.RelayAdmissionCA, trust.InnerClientCA, trust.InnerConnectorCA}
	pins := make([]string, len(values))
	for index, encoded := range values {
		certificate, err := parseCA([]byte(encoded))
		if err != nil {
			return IssuerPins{}, fmt.Errorf("enrollment: bootstrap issuer %d: %w", index, err)
		}
		if now.IsZero() || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return IssuerPins{}, fmt.Errorf("enrollment: bootstrap issuer %d is not currently valid", index)
		}
		pins[index], err = pki.CertificatePin(certificate)
		if err != nil {
			return IssuerPins{}, err
		}
	}
	result := IssuerPins{RelayAdmissionCA: pins[0], InnerClientCA: pins[1], InnerConnectorCA: pins[2]}
	if err := result.Validate(); err != nil {
		return IssuerPins{}, err
	}
	return result, nil
}

// ValidateBootstrapAuthorities rejects key reuse across the three route trust
// domains and the deployment signer. Distinct certificate bytes are not enough:
// two self-signed roots made from one key would collapse those authorities even
// though their certificate pins differ.
func ValidateBootstrapAuthorities(trust Trust, deploymentSigner ed25519.PublicKey, now time.Time) error {
	if len(deploymentSigner) != ed25519.PublicKeySize {
		return errors.New("enrollment: deployment verifier is not Ed25519")
	}
	encodedRoots := []string{trust.RelayAdmissionCA, trust.InnerClientCA, trust.InnerConnectorCA}
	publicKeys := make([][]byte, 0, len(encodedRoots)+1)
	for index, encoded := range encodedRoots {
		certificate, err := parseCA([]byte(encoded))
		if err != nil {
			return fmt.Errorf("enrollment: bootstrap issuer %d: %w", index, err)
		}
		if now.IsZero() || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return fmt.Errorf("enrollment: bootstrap issuer %d is not currently valid", index)
		}
		publicKeys = append(publicKeys, append([]byte(nil), certificate.RawSubjectPublicKeyInfo...))
	}
	signerSPKI, err := x509.MarshalPKIXPublicKey(deploymentSigner)
	if err != nil {
		return fmt.Errorf("enrollment: marshal deployment verifier: %w", err)
	}
	publicKeys = append(publicKeys, signerSPKI)
	for first := range publicKeys {
		for second := first + 1; second < len(publicKeys); second++ {
			if bytes.Equal(publicKeys[first], publicKeys[second]) {
				return errors.New("enrollment: bootstrap issuer and deployment-verifier keys must all be distinct")
			}
		}
	}
	return nil
}
