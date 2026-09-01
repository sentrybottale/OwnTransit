package enrollment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pki"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	LifecyclePolicySchema         = "owntransit.lifecycle-policy.v1"
	LifecyclePolicyEnvelopeSchema = "owntransit.lifecycle-policy-envelope.v1"
	MaxLifecyclePolicySize        = 512 << 10
	MaxLifecyclePolicyValidity    = 30 * 24 * time.Hour
)

const lifecyclePolicySignatureDomain = "owntransit.lifecycle-policy.v1"

// PolicyFloors are authenticated monotonic lower bounds. A zero value leaves
// the corresponding existing floor unchanged; a policy can only advance a
// floor to a sequence already observed by the target.
type PolicyFloors struct {
	DeploymentSequence uint64 `json:"deployment_sequence"`
	ReleaseSequence    uint64 `json:"release_sequence"`
	CredentialSequence uint64 `json:"credential_sequence"`
	PolicySequence     uint64 `json:"policy_sequence"`
	TombstoneSequence  uint64 `json:"tombstone_sequence"`
}

// LifecyclePolicy is an offline-signed, target-bound verifier overlay. Trust
// selects issuers for the *next* target-generated request. The active runtime
// continues using its already verified local issuer until a matching rotated
// leaf is activated. Connector capability roots and peer pins are verifier-
// first runtime inputs and are materialized immediately in a derived immutable
// generation.
type LifecyclePolicy struct {
	Schema                       string                  `json:"schema"`
	Role                         Role                    `json:"role"`
	InstallationID               string                  `json:"installation_id"`
	Sequence                     uint64                  `json:"sequence"`
	IssuedUnix                   int64                   `json:"issued_unix"`
	ExpiresUnix                  int64                   `json:"expires_unix"`
	ExpectedStateGeneration      uint64                  `json:"expected_state_generation"`
	ExpectedStateSHA256          string                  `json:"expected_state_sha256"`
	Floors                       PolicyFloors            `json:"floors"`
	Trust                        Trust                   `json:"next_enrollment_trust"`
	CapabilityClientRoots        []string                `json:"capability_client_roots_pem"`
	RelayServerSPKIPins          []string                `json:"relay_server_spki_sha256"`
	ConnectorSPKIPins            []string                `json:"connector_spki_sha256"`
	RelayClients                 []config.AuthorizedPeer `json:"relay_clients"`
	RelayRoutes                  []config.RelayRoute     `json:"relay_routes"`
	RevokedClientInstallationIDs []string                `json:"revoked_client_installation_ids"`
	RevokedClientSPKIPins        []string                `json:"revoked_client_spki_sha256"`
}

type lifecyclePolicyEnvelope struct {
	Schema      string `json:"schema"`
	SignerKeyID string `json:"signer_key_id"`
	Payload     string `json:"payload"`
	Signature   string `json:"signature"`
}

// SignLifecyclePolicy emits exact, domain-separated signed bytes for offline
// transport. The relay is never a policy authority.
func SignLifecyclePolicy(policy LifecyclePolicy, privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	now = now.UTC().Truncate(time.Second)
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("enrollment: lifecycle policy signer is not Ed25519")
	}
	if err := policy.Validate(now, privateKey.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode lifecycle policy: %w", err)
	}
	signature, err := signing.Sign(lifecyclePolicySignatureDomain, payload, privateKey)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(lifecyclePolicyEnvelope{
		Schema: LifecyclePolicyEnvelopeSchema, SignerKeyID: signing.KeyID(privateKey.Public().(ed25519.PublicKey)),
		Payload: base64.StdEncoding.EncodeToString(payload), Signature: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		return nil, fmt.Errorf("enrollment: encode lifecycle policy envelope: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > MaxLifecyclePolicySize {
		return nil, errors.New("enrollment: lifecycle policy exceeds its size limit")
	}
	return encoded, nil
}

// VerifyLifecyclePolicy verifies the pinned deployment signer before parsing
// and validating the target-bound policy payload.
func VerifyLifecyclePolicy(encoded []byte, publicKey ed25519.PublicKey, now time.Time) (LifecyclePolicy, error) {
	now = now.UTC().Truncate(time.Second)
	if len(encoded) == 0 || len(encoded) > MaxLifecyclePolicySize || len(publicKey) != ed25519.PublicKeySize || now.IsZero() {
		return LifecyclePolicy{}, errors.New("enrollment: bounded lifecycle policy, verifier, and current time are required")
	}
	policy, err := verifyLifecyclePolicySignature(encoded, publicKey)
	if err != nil {
		return LifecyclePolicy{}, err
	}
	if err := policy.Validate(now, publicKey); err != nil {
		return LifecyclePolicy{}, err
	}
	return policy, nil
}

// VerifyStoredLifecyclePolicy re-verifies an already activated policy without
// treating its transport/application expiry as a runtime expiry. Certificate
// and structure checks are evaluated at the authenticated issuance time.
func VerifyStoredLifecyclePolicy(encoded []byte, publicKey ed25519.PublicKey) (LifecyclePolicy, error) {
	policy, err := verifyLifecyclePolicySignature(encoded, publicKey)
	if err != nil {
		return LifecyclePolicy{}, err
	}
	if err := policy.Validate(time.Unix(policy.IssuedUnix, 0).UTC(), publicKey); err != nil {
		return LifecyclePolicy{}, err
	}
	return policy, nil
}

func verifyLifecyclePolicySignature(encoded []byte, publicKey ed25519.PublicKey) (LifecyclePolicy, error) {
	if len(encoded) == 0 || len(encoded) > MaxLifecyclePolicySize || len(publicKey) != ed25519.PublicKeySize {
		return LifecyclePolicy{}, errors.New("enrollment: bounded lifecycle policy and verifier are required")
	}
	var envelope lifecyclePolicyEnvelope
	if err := strictjson.Decode(encoded, &envelope); err != nil {
		return LifecyclePolicy{}, fmt.Errorf("enrollment: decode lifecycle policy envelope: %w", err)
	}
	if envelope.Schema != LifecyclePolicyEnvelopeSchema || envelope.SignerKeyID != signing.KeyID(publicKey) {
		return LifecyclePolicy{}, errors.New("enrollment: lifecycle policy envelope or signer is invalid")
	}
	payload, err := decodeCanonicalBase64(envelope.Payload, "lifecycle policy payload")
	if err != nil {
		return LifecyclePolicy{}, err
	}
	signature, err := decodeCanonicalBase64(envelope.Signature, "lifecycle policy signature")
	if err != nil {
		return LifecyclePolicy{}, err
	}
	if err := signing.Verify(lifecyclePolicySignatureDomain, payload, signature, publicKey); err != nil {
		return LifecyclePolicy{}, fmt.Errorf("enrollment: lifecycle policy: %w", err)
	}
	var policy LifecyclePolicy
	if err := strictjson.Decode(payload, &policy); err != nil {
		return LifecyclePolicy{}, fmt.Errorf("enrollment: decode lifecycle policy: %w", err)
	}
	return policy, nil
}

// Validate checks shape, role separation, time bounds, issuer profiles and
// canonical collection ordering. Target-relative monotonic checks happen only
// inside the locked apply transaction.
func (policy LifecyclePolicy) Validate(now time.Time, deploymentSigner ed25519.PublicKey) error {
	if policy.Schema != LifecyclePolicySchema || policy.Sequence == 0 || policy.ExpectedStateGeneration == 0 || !validSHA256(policy.ExpectedStateSHA256) {
		return errors.New("enrollment: lifecycle policy identity, sequence, or state binding is invalid")
	}
	installationID, err := protocol.ParseID(policy.InstallationID)
	if err != nil || installationID == (protocol.ID{}) || installationID.String() != policy.InstallationID {
		return errors.New("enrollment: lifecycle policy installation ID is invalid")
	}
	if policy.IssuedUnix <= 0 || policy.ExpiresUnix <= policy.IssuedUnix ||
		policy.ExpiresUnix-policy.IssuedUnix > int64(MaxLifecyclePolicyValidity/time.Second) ||
		now.Before(time.Unix(policy.IssuedUnix, 0).Add(-5*time.Minute)) || !now.Before(time.Unix(policy.ExpiresUnix, 0)) {
		return errors.New("enrollment: lifecycle policy is not currently valid")
	}
	if _, err := IssuerPinsFromTrust(policy.Trust, now); err != nil {
		return fmt.Errorf("enrollment: lifecycle policy trust: %w", err)
	}
	if err := ValidateBootstrapAuthorities(policy.Trust, deploymentSigner, now); err != nil {
		return err
	}
	if policy.CapabilityClientRoots == nil || policy.RelayServerSPKIPins == nil || policy.ConnectorSPKIPins == nil ||
		policy.RelayClients == nil || policy.RelayRoutes == nil || policy.RevokedClientInstallationIDs == nil || policy.RevokedClientSPKIPins == nil {
		return errors.New("enrollment: lifecycle policy bounded arrays must be present, not null")
	}
	if err := validateCanonicalIDs(policy.RevokedClientInstallationIDs); err != nil {
		return err
	}
	if err := validateCanonicalPins(policy.RevokedClientSPKIPins, true); err != nil {
		return fmt.Errorf("enrollment: lifecycle policy revoked client pins: %w", err)
	}
	if len(policy.RevokedClientInstallationIDs)+len(policy.RevokedClientSPKIPins) > config.MaxCapabilityRevocations {
		return errors.New("enrollment: lifecycle policy revocations exceed the connector bound")
	}

	switch policy.Role {
	case RoleConnector:
		if len(policy.CapabilityClientRoots) < 1 || len(policy.CapabilityClientRoots) > config.MaxCapabilityClientCAs ||
			len(policy.RelayServerSPKIPins) < 1 || len(policy.RelayServerSPKIPins) > 4 ||
			len(policy.ConnectorSPKIPins) != 0 || len(policy.RelayClients) != 0 || len(policy.RelayRoutes) != 0 {
			return errors.New("enrollment: connector lifecycle policy verifier fields are invalid")
		}
		if err := validateCanonicalPins(policy.RelayServerSPKIPins, false); err != nil {
			return err
		}
		rootPins, err := validateCapabilityRoots(policy.CapabilityClientRoots, now)
		if err != nil {
			return err
		}
		trustPins, err := IssuerPinsFromTrust(policy.Trust, now)
		if err != nil {
			return err
		}
		if !containsText(rootPins, trustPins.InnerClientCA) {
			return errors.New("enrollment: next client issuer is absent from connector verifier roots")
		}
	case RoleClient:
		if len(policy.CapabilityClientRoots) != 0 || len(policy.RelayServerSPKIPins) < 1 || len(policy.RelayServerSPKIPins) > 4 ||
			len(policy.ConnectorSPKIPins) < 1 || len(policy.ConnectorSPKIPins) > 4 || len(policy.RelayClients) != 0 || len(policy.RelayRoutes) != 0 ||
			len(policy.RevokedClientInstallationIDs) != 0 {
			return errors.New("enrollment: client lifecycle policy verifier fields are invalid")
		}
		if err := validateCanonicalPins(policy.RelayServerSPKIPins, false); err != nil {
			return err
		}
		if err := validateCanonicalPins(policy.ConnectorSPKIPins, false); err != nil {
			return err
		}
	case RoleRelay:
		if len(policy.CapabilityClientRoots) != 0 || len(policy.RelayServerSPKIPins) != 0 || len(policy.ConnectorSPKIPins) != 0 ||
			len(policy.RevokedClientInstallationIDs) != 0 ||
			len(policy.RelayClients) == 0 || len(policy.RelayRoutes) == 0 {
			return errors.New("enrollment: relay lifecycle policy verifier fields are invalid")
		}
		if err := validateRelayPolicy(policy.RelayClients, policy.RelayRoutes); err != nil {
			return err
		}
	default:
		return errors.New("enrollment: lifecycle policy role is invalid")
	}
	return nil
}

func validateCapabilityRoots(encoded []string, now time.Time) ([]string, error) {
	pins := make([]string, len(encoded))
	for index, value := range encoded {
		certificate, err := parseCA([]byte(value))
		if err != nil || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, fmt.Errorf("enrollment: capability client root %d is invalid or expired", index)
		}
		pins[index], err = pki.CertificatePin(certificate)
		if err != nil {
			return nil, err
		}
		if index > 0 && pins[index-1] >= pins[index] {
			return nil, errors.New("enrollment: capability client roots must be sorted by unique certificate pin")
		}
	}
	return pins, nil
}

func validateCanonicalIDs(values []string) error {
	for index, value := range values {
		parsed, err := protocol.ParseID(value)
		if err != nil || parsed == (protocol.ID{}) || parsed.String() != value {
			return fmt.Errorf("enrollment: revoked client installation %d is invalid", index)
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("enrollment: revoked client installations must be sorted and unique")
		}
	}
	return nil
}

func validateCanonicalPins(values []string, allowEmpty bool) error {
	if !allowEmpty && len(values) == 0 {
		return errors.New("enrollment: SPKI verifier pin list is empty")
	}
	for index, value := range values {
		if _, err := identity.ParseSPKIPin(value); err != nil {
			return fmt.Errorf("enrollment: SPKI verifier pin %d is invalid", index)
		}
		if index > 0 && values[index-1] >= value {
			return errors.New("enrollment: SPKI verifier pins must be sorted and unique")
		}
	}
	return nil
}

func validateRelayPolicy(clients []config.AuthorizedPeer, routes []config.RelayRoute) error {
	seenClients := make(map[string]struct{}, len(clients))
	for index, peer := range clients {
		if err := identity.ValidateDNSName(peer.DNSName); err != nil || validateCanonicalPins(peer.SPKIPins, false) != nil {
			return fmt.Errorf("enrollment: relay policy client %d is invalid", index)
		}
		if _, duplicate := seenClients[peer.DNSName]; duplicate || index > 0 && clients[index-1].DNSName >= peer.DNSName {
			return errors.New("enrollment: relay policy clients must be sorted and unique")
		}
		seenClients[peer.DNSName] = struct{}{}
	}
	seenRoutes := make(map[string]struct{}, len(routes))
	for index, route := range routes {
		parsed, err := protocol.ParseRouteID(route.RouteID)
		if err != nil || parsed == (protocol.RouteID{}) || parsed.String() != route.RouteID || identity.ValidateDNSName(route.DNSName) != nil || validateCanonicalPins(route.SPKIPins, false) != nil {
			return fmt.Errorf("enrollment: relay policy route %d is invalid", index)
		}
		key := route.RouteID + "\x00" + route.DNSName
		if _, duplicate := seenRoutes[key]; duplicate || index > 0 && policyRouteKey(routes[index-1]) >= key {
			return errors.New("enrollment: relay policy routes must be sorted and unique")
		}
		seenRoutes[key] = struct{}{}
	}
	return nil
}

func policyRouteKey(route config.RelayRoute) string { return route.RouteID + "\x00" + route.DNSName }

func containsText(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

// LifecyclePolicySHA256 returns the canonical digest bound into local state.
func LifecyclePolicySHA256(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// CapabilityRootPins validates and returns the canonical sorted certificate
// pins for a lifecycle policy's capability roots.
func CapabilityRootPins(encoded []string, now time.Time) ([]string, error) {
	return validateCapabilityRoots(encoded, now)
}
