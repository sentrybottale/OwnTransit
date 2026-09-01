// Package config defines and strictly validates OwnTransit's local-only JSON
// configuration. The relay protocol contains no configuration or target fields.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const (
	RelayALPN    = wireprofile.LegacyV1RelayALPN
	InnerALPN    = wireprofile.LegacyV1Protocol
	RelayPath    = "/connects"
	RelayDNSName = wireprofile.LegacyV1RelayDNSName

	// InnerProfileRouteCapability is the public route-scoped capability
	// profile. It deliberately negotiates a different ALPN from the legacy
	// exact-pin profile so neither endpoint can silently downgrade identities.
	InnerProfileRouteCapability = "owntransit-route-capability/1"
	CapabilityInnerALPN         = "owntransit-capability/1"

	// InnerProfileLegacyExactPins preserves the stronger per-leaf pin policy
	// only as an explicit migration profile. An absent profile is never treated
	// as either legacy or capability authorization.
	InnerProfileLegacyExactPins = wireprofile.LegacyV1ExactPinsProfile

	MaxCapabilityClientCAs          = 2
	MaxCapabilityRevocations        = 4096
	maxConfigSize                   = 1 << 20
	DefaultConnectorActivePerClient = 2

	// DefaultRelayCarriersGlobal bounds upgraded WebSockets before any outer
	// mTLS work. It is deliberately below the POC relay container's FD limit.
	DefaultRelayCarriersGlobal = 96

	// Existing v1 configurations predate explicit authenticated-session
	// lifetimes. Zero-valued decoded fields receive these finite compatibility
	// defaults so an upgrade cannot accidentally create unbounded sessions.
	DefaultSessionIdle     = 30 * time.Minute
	DefaultSessionLifetime = 24 * time.Hour

	// Existing v1 configurations predate per-client relay fairness. Zero-valued
	// decoded fields receive conservative compatibility defaults. The effective
	// value is also capped below any multi-slot global or per-route capacity so
	// one authenticated client cannot consume every available slot.
	DefaultRelayPendingPerClient = 2
	DefaultRelayActivePerClient  = 4

	// The relay preallocates one fairness account per configured logical client.
	// Keep that state cardinality independent of attacker-controlled input.
	MaxRelayClients = 1024
)

type ServerTLS struct {
	CertFile     string `json:"cert_file"`
	KeyFile      string `json:"key_file"`
	ClientCAFile string `json:"client_ca_file"`
	IssuerCAFile string `json:"issuer_ca_file,omitempty"`
	LocalDNSName string `json:"local_dns_name,omitempty"`
}

type ClientTLS struct {
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	CAFile       string   `json:"ca_file"`
	ServerName   string   `json:"server_name"`
	SPKIPins     []string `json:"spki_sha256"`
	IssuerCAFile string   `json:"issuer_ca_file,omitempty"`
	LocalDNSName string   `json:"local_dns_name,omitempty"`
}

type AuthorizedPeer struct {
	DNSName  string   `json:"dns_name"`
	SPKIPins []string `json:"spki_sha256"`
}

type RelayRoute struct {
	RouteID  string   `json:"route_id"`
	DNSName  string   `json:"connector_dns_name"`
	SPKIPins []string `json:"connector_spki_sha256"`
}

type RelayLimits struct {
	CarriersGlobal   int      `json:"carriers_global,omitempty"`
	OuterHandshakes  int      `json:"outer_handshakes"`
	PendingGlobal    int      `json:"pending_global"`
	PendingPerRoute  int      `json:"pending_per_route"`
	PendingPerClient int      `json:"pending_per_client,omitempty"`
	ActiveGlobal     int      `json:"active_global"`
	ActivePerRoute   int      `json:"active_per_route"`
	ActivePerClient  int      `json:"active_per_client,omitempty"`
	Handshake        Duration `json:"handshake_timeout"`
	Preface          Duration `json:"preface_timeout"`
	Join             Duration `json:"join_timeout"`
	Drain            Duration `json:"drain_timeout"`
	SessionIdle      Duration `json:"session_idle_timeout,omitempty"`
	SessionLifetime  Duration `json:"session_lifetime,omitempty"`
}

// CarrierGlobal returns the explicit pre-upgrade carrier cap or the backwards-
// compatible POC default for configs generated before this field existed.
func (limits RelayLimits) CarrierGlobal() int {
	if limits.CarriersGlobal == 0 {
		return DefaultRelayCarriersGlobal
	}
	return limits.CarriersGlobal
}

// SessionIdleValue returns the finite authenticated-session inactivity limit,
// including the compatibility default for older v1 configuration files.
func (limits RelayLimits) SessionIdleValue() time.Duration {
	if limits.SessionIdle == 0 {
		return DefaultSessionIdle
	}
	return limits.SessionIdle.Value()
}

// SessionLifetimeValue returns the finite absolute authenticated-session
// lifetime, including the compatibility default for older v1 configurations.
func (limits RelayLimits) SessionLifetimeValue() time.Duration {
	if limits.SessionLifetime == 0 {
		return DefaultSessionLifetime
	}
	return limits.SessionLifetime.Value()
}

// PendingPerClientValue returns the explicit per-client pending limit or a
// conservative value for configurations created before this field existed.
func (limits RelayLimits) PendingPerClientValue() int {
	if limits.PendingPerClient != 0 {
		return limits.PendingPerClient
	}
	return boundedPerClientDefault(DefaultRelayPendingPerClient, limits.PendingGlobal, limits.PendingPerRoute)
}

// ActivePerClientValue returns the explicit per-client active limit or a
// conservative value for configurations created before this field existed.
func (limits RelayLimits) ActivePerClientValue() int {
	if limits.ActivePerClient != 0 {
		return limits.ActivePerClient
	}
	return boundedPerClientDefault(DefaultRelayActivePerClient, limits.ActiveGlobal, limits.ActivePerRoute)
}

func boundedPerClientDefault(preferred, global, perRoute int) int {
	if global <= 0 || perRoute <= 0 {
		return preferred
	}
	capacity := min(global, perRoute)
	if capacity > 1 {
		capacity--
	}
	return min(preferred, capacity)
}

type ConnectorLimits struct {
	Pending         int      `json:"pending"`
	Active          int      `json:"active"`
	ActivePerClient int      `json:"active_per_client,omitempty"`
	ConnectTimeout  Duration `json:"connect_timeout"`
	Handshake       Duration `json:"handshake_timeout"`
	LocalDial       Duration `json:"local_dial_timeout"`
	Drain           Duration `json:"drain_timeout"`
	ReconnectMin    Duration `json:"reconnect_min"`
	ReconnectMax    Duration `json:"reconnect_max"`
	SessionIdle     Duration `json:"session_idle_timeout,omitempty"`
	SessionLifetime Duration `json:"session_lifetime,omitempty"`
}

func (limits ConnectorLimits) SessionIdleValue() time.Duration {
	if limits.SessionIdle == 0 {
		return DefaultSessionIdle
	}
	return limits.SessionIdle.Value()
}

func (limits ConnectorLimits) SessionLifetimeValue() time.Duration {
	if limits.SessionLifetime == 0 {
		return DefaultSessionLifetime
	}
	return limits.SessionLifetime.Value()
}

// ActivePerClientValue leaves one connector slot for another authenticated
// capability whenever total capacity is greater than one. Legacy exact-pin
// sessions do not consume this account.
func (limits ConnectorLimits) ActivePerClientValue() int {
	if limits.ActivePerClient != 0 {
		return limits.ActivePerClient
	}
	if limits.Active <= 1 {
		return 1
	}
	return min(DefaultConnectorActivePerClient, limits.Active-1)
}

type Relay struct {
	Listen                               string           `json:"listen"`
	Path                                 string           `json:"path"`
	EnrollmentAllocationCapabilitySHA256 string           `json:"enrollment_allocation_capability_sha256,omitempty"`
	OuterTLS                             ServerTLS        `json:"outer_tls"`
	Clients                              []AuthorizedPeer `json:"clients"`
	Routes                               []RelayRoute     `json:"routes"`
	Limits                               RelayLimits      `json:"limits"`
}

type ConnectorInnerTLS struct {
	CertFile         string           `json:"cert_file"`
	KeyFile          string           `json:"key_file"`
	ClientCAFile     string           `json:"client_ca_file,omitempty"`
	ClientCAFiles    []string         `json:"client_ca_files,omitempty"`
	ClientCARotation bool             `json:"client_ca_rotation,omitempty"`
	IssuerCAFile     string           `json:"issuer_ca_file,omitempty"`
	LocalDNSName     string           `json:"local_dns_name,omitempty"`
	ServerName       string           `json:"server_name"`
	Clients          []AuthorizedPeer `json:"clients,omitempty"`
	// Revocations are rendered only from authenticated local deployment state;
	// the relay and connecting client never supply them.
	RevokedClientIDs   []string `json:"revoked_client_ids,omitempty"`
	RevokedClientSPKIs []string `json:"revoked_client_spki_sha256,omitempty"`
}

type Connector struct {
	RelayURL             string            `json:"relay_url"`
	CarrierCAFile        string            `json:"carrier_ca_file,omitempty"`
	AllowInsecureCarrier bool              `json:"allow_insecure_carrier,omitempty"`
	InstallationID       string            `json:"installation_id,omitempty"`
	RouteID              string            `json:"route_id"`
	InnerProfile         string            `json:"inner_profile"`
	OuterTLS             ClientTLS         `json:"outer_tls"`
	InnerTLS             ConnectorInnerTLS `json:"inner_tls"`
	SSHTarget            string            `json:"ssh_target"`
	Limits               ConnectorLimits   `json:"limits"`
}

type Client struct {
	RelayURL                string    `json:"relay_url"`
	CarrierCAFile           string    `json:"carrier_ca_file,omitempty"`
	AllowInsecureCarrier    bool      `json:"allow_insecure_carrier,omitempty"`
	InstallationID          string    `json:"installation_id,omitempty"`
	ConnectorInstallationID string    `json:"connector_installation_id,omitempty"`
	CredentialEpoch         uint64    `json:"credential_epoch,omitempty"`
	RouteID                 string    `json:"route_id"`
	InnerProfile            string    `json:"inner_profile"`
	OuterTLS                ClientTLS `json:"outer_tls"`
	InnerTLS                ClientTLS `json:"inner_tls"`
	ConnectTimeout          Duration  `json:"connect_timeout"`
	HandshakeTimeout        Duration  `json:"handshake_timeout"`
	ReadyTimeout            Duration  `json:"ready_timeout"`
	DrainTimeout            Duration  `json:"drain_timeout"`
}

// Duration accepts a positive Go duration string and emits the same canonical
// representation. Numeric JSON durations are deliberately unsupported.
type Duration time.Duration

func (duration *Duration) UnmarshalJSON(encoded []byte) error {
	var text string
	if err := json.Unmarshal(encoded, &text); err != nil {
		return errors.New("duration must be a string")
	}
	parsed, err := time.ParseDuration(text)
	if err != nil || parsed <= 0 {
		return fmt.Errorf("duration %q must be positive: %w", text, err)
	}
	*duration = Duration(parsed)
	return nil
}

func (duration Duration) MarshalJSON() ([]byte, error) {
	if duration <= 0 {
		return nil, errors.New("duration must be positive")
	}
	return json.Marshal(time.Duration(duration).String())
}

func (duration Duration) Value() time.Duration { return time.Duration(duration) }

func LoadRelay(path string) (Relay, error) {
	var value Relay
	if err := load(path, &value); err != nil {
		return Relay{}, err
	}
	if err := value.Validate(); err != nil {
		return Relay{}, fmt.Errorf("config: invalid relay configuration: %w", err)
	}
	return value, nil
}

// ParseRelay strictly decodes one bounded relay configuration from an
// already-authenticated local runtime bundle. Duplicate, case-aliased,
// unknown and trailing JSON values are rejected before policy validation.
func ParseRelay(encoded []byte) (Relay, error) {
	var value Relay
	if err := parse(encoded, &value); err != nil {
		return Relay{}, err
	}
	if err := value.Validate(); err != nil {
		return Relay{}, fmt.Errorf("config: invalid relay configuration: %w", err)
	}
	return value, nil
}

func LoadConnector(path string) (Connector, error) {
	var value Connector
	if err := load(path, &value); err != nil {
		return Connector{}, err
	}
	if err := value.Validate(); err != nil {
		return Connector{}, fmt.Errorf("config: invalid connector configuration: %w", err)
	}
	return value, nil
}

// ParseConnector is the in-memory counterpart to LoadConnector for immutable
// generation directories selected by target-local lifecycle state.
func ParseConnector(encoded []byte) (Connector, error) {
	var value Connector
	if err := parse(encoded, &value); err != nil {
		return Connector{}, err
	}
	if err := value.Validate(); err != nil {
		return Connector{}, fmt.Errorf("config: invalid connector configuration: %w", err)
	}
	return value, nil
}

func LoadClient(path string) (Client, error) {
	var value Client
	if err := load(path, &value); err != nil {
		return Client{}, err
	}
	if err := value.Validate(); err != nil {
		return Client{}, fmt.Errorf("config: invalid client configuration: %w", err)
	}
	return value, nil
}

// ParseClient is the in-memory counterpart to LoadClient for immutable
// generation directories selected by target-local lifecycle state.
func ParseClient(encoded []byte) (Client, error) {
	var value Client
	if err := parse(encoded, &value); err != nil {
		return Client{}, err
	}
	if err := value.Validate(); err != nil {
		return Client{}, fmt.Errorf("config: invalid client configuration: %w", err)
	}
	return value, nil
}

func load(path string, destination any) error {
	if path == "" {
		return errors.New("config: path is empty")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("config: open %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("config: inspect opened %q: %w", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxConfigSize {
		return fmt.Errorf("config: %q must be a bounded regular non-symlink file", path)
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return fmt.Errorf("config: read %q: %w", path, err)
	}
	if len(encoded) < 1 || len(encoded) > maxConfigSize {
		return fmt.Errorf("config: %q changed size while being read", path)
	}
	if err := parse(encoded, destination); err != nil {
		return fmt.Errorf("config: decode %q: %w", path, err)
	}
	return nil
}

func parse(encoded []byte, destination any) error {
	if len(encoded) == 0 || len(encoded) > maxConfigSize {
		return fmt.Errorf("config: encoded configuration size must be within 1..%d bytes", maxConfigSize)
	}
	return strictjson.Decode(encoded, destination)
}

func (value Relay) Validate() error {
	if value.Path != RelayPath {
		return fmt.Errorf("path must be exactly %q", RelayPath)
	}
	if err := validateListen(value.Listen); err != nil {
		return err
	}
	if value.EnrollmentAllocationCapabilitySHA256 != "" && !validCanonicalSHA256(value.EnrollmentAllocationCapabilitySHA256) {
		return errors.New("enrollment allocation capability hash must be canonical SHA-256")
	}
	if err := validateServerTLS(value.OuterTLS); err != nil {
		return fmt.Errorf("outer TLS: %w", err)
	}
	if value.OuterTLS.LocalDNSName != "" && value.OuterTLS.LocalDNSName != RelayDNSName {
		return fmt.Errorf("outer TLS local DNS name must be %q", RelayDNSName)
	}
	if len(value.Clients) == 0 {
		return errors.New("client admission allowlist is empty")
	}
	if len(value.Clients) > MaxRelayClients {
		return fmt.Errorf("client admission allowlist exceeds %d identities", MaxRelayClients)
	}
	if len(value.Routes) == 0 {
		return errors.New("route allowlist is empty")
	}
	peerNames := make(map[string]struct{}, len(value.Clients))
	for index, peer := range value.Clients {
		if err := validatePeer(peer); err != nil {
			return fmt.Errorf("client %d: %w", index, err)
		}
		if _, duplicate := peerNames[peer.DNSName]; duplicate {
			return fmt.Errorf("duplicate client DNS name %q", peer.DNSName)
		}
		peerNames[peer.DNSName] = struct{}{}
	}
	routes := make(map[protocol.RouteID]struct{}, len(value.Routes))
	for index, route := range value.Routes {
		parsed, err := protocol.ParseRouteID(route.RouteID)
		if err != nil {
			return fmt.Errorf("route %d: %w", index, err)
		}
		if _, duplicate := routes[parsed]; duplicate {
			return fmt.Errorf("duplicate route ID at index %d", index)
		}
		routes[parsed] = struct{}{}
		if route.DNSName != OuterConnectorDNSName(parsed) {
			return fmt.Errorf("route %d connector DNS name must be %q", index, OuterConnectorDNSName(parsed))
		}
		if _, duplicate := peerNames[route.DNSName]; duplicate {
			return fmt.Errorf("route %d duplicates client DNS name %q", index, route.DNSName)
		}
		if _, err := identity.ParsePinAllowlist(route.SPKIPins); err != nil {
			return fmt.Errorf("route %d connector pins: %w", index, err)
		}
	}
	if err := value.Limits.validate(); err != nil {
		return err
	}
	if value.Limits.CarrierGlobal() < value.Limits.minimumCarriers(len(value.Routes)) {
		return errors.New("carrier global limit is below configured total connection capacity")
	}
	return nil
}

func validCanonicalSHA256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for index := range value {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func (value Connector) Validate() error {
	route, err := protocol.ParseRouteID(value.RouteID)
	if err != nil || route == (protocol.RouteID{}) {
		return errors.New("route_id must be a nonzero canonical route ID")
	}
	if err := validateRelayURL(value.RelayURL, value.AllowInsecureCarrier); err != nil {
		return err
	}
	if err := validateClientTLS(value.OuterTLS); err != nil {
		return fmt.Errorf("outer TLS: %w", err)
	}

	outerStrict := value.OuterTLS.LocalDNSName != ""
	if outerStrict && value.OuterTLS.LocalDNSName != OuterConnectorDNSName(route) {
		return fmt.Errorf("outer TLS local DNS name must be %q", OuterConnectorDNSName(route))
	}
	switch value.InnerProfile {
	case InnerProfileRouteCapability:
		if err := value.validateCapabilityProfile(route); err != nil {
			return err
		}
	case InnerProfileLegacyExactPins:
		if err := value.validateLegacyExactPinProfile(route, outerStrict); err != nil {
			return err
		}
	default:
		return fmt.Errorf("inner_profile must be exactly %q or explicit migration profile %q", InnerProfileRouteCapability, InnerProfileLegacyExactPins)
	}
	if value.SSHTarget != ConnectorSSHTarget {
		return fmt.Errorf("ssh_target must be exactly the build-bound endpoint %s", ConnectorSSHTarget)
	}
	target, err := netip.ParseAddrPort(value.SSHTarget)
	if err != nil || target.Addr() != netip.MustParseAddr("127.0.0.1") {
		return errors.New("ssh_target is not the fixed numeric loopback endpoint")
	}
	return value.Limits.validate()
}

func (value Connector) validateCapabilityProfile(route protocol.RouteID) error {
	installationID, err := parseNonzeroInstallationID(value.InstallationID)
	if err != nil {
		return fmt.Errorf("installation_id: %w", err)
	}
	if value.OuterTLS.LocalDNSName == "" || value.OuterTLS.IssuerCAFile == "" {
		return errors.New("capability profile requires strict outer local identity fields")
	}
	if value.Limits.Active > 1 && value.Limits.ActivePerClientValue() >= value.Limits.Active {
		return errors.New("capability active_per_client must leave one connector slot for another client")
	}
	expectedName := CapabilityConnectorDNSName(installationID, route)
	if value.InnerTLS.CertFile == "" || value.InnerTLS.KeyFile == "" || value.InnerTLS.IssuerCAFile == "" {
		return errors.New("capability inner TLS requires certificate, key, and local issuer paths")
	}
	if value.InnerTLS.LocalDNSName != expectedName || value.InnerTLS.ServerName != expectedName {
		return fmt.Errorf("capability connector inner identity and server name must both be %q", expectedName)
	}
	if value.InnerTLS.ClientCAFile != "" {
		return errors.New("capability profile forbids legacy client_ca_file")
	}
	if len(value.InnerTLS.ClientCAFiles) == 0 || len(value.InnerTLS.ClientCAFiles) > MaxCapabilityClientCAs {
		return fmt.Errorf("capability client_ca_files must contain 1..%d route roots", MaxCapabilityClientCAs)
	}
	if value.InnerTLS.ClientCARotation != (len(value.InnerTLS.ClientCAFiles) == 2) {
		return errors.New("client_ca_rotation must be true exactly while two route roots overlap")
	}
	seenPaths := make(map[string]struct{}, len(value.InnerTLS.ClientCAFiles))
	for index, root := range value.InnerTLS.ClientCAFiles {
		if root == "" {
			return fmt.Errorf("capability client CA %d path is empty", index)
		}
		if _, duplicate := seenPaths[root]; duplicate {
			return fmt.Errorf("capability client CA %d duplicates an earlier path", index)
		}
		seenPaths[root] = struct{}{}
	}
	if len(value.InnerTLS.Clients) != 0 {
		return errors.New("capability profile forbids a positive client allowlist")
	}
	return validateCapabilityRevocations(value.InnerTLS.RevokedClientIDs, value.InnerTLS.RevokedClientSPKIs)
}

func (value Connector) validateLegacyExactPinProfile(route protocol.RouteID, outerStrict bool) error {
	if value.InstallationID != "" {
		return errors.New("legacy exact-pin migration profile forbids capability installation_id")
	}
	if len(value.InnerTLS.ClientCAFiles) != 0 || value.InnerTLS.ClientCARotation || len(value.InnerTLS.RevokedClientIDs) != 0 || len(value.InnerTLS.RevokedClientSPKIs) != 0 {
		return errors.New("legacy exact-pin migration profile contains capability-only state")
	}
	innerServerTLS := ServerTLS{
		CertFile:     value.InnerTLS.CertFile,
		KeyFile:      value.InnerTLS.KeyFile,
		ClientCAFile: value.InnerTLS.ClientCAFile,
		IssuerCAFile: value.InnerTLS.IssuerCAFile,
		LocalDNSName: value.InnerTLS.LocalDNSName,
	}
	if err := validateServerTLS(innerServerTLS); err != nil {
		return fmt.Errorf("inner TLS: %w", err)
	}
	innerStrict := value.InnerTLS.LocalDNSName != ""
	if outerStrict != innerStrict {
		return errors.New("outer and inner TLS must both use strict local identity fields or both use legacy compatibility")
	}
	if innerStrict && value.InnerTLS.LocalDNSName != ConnectorDNSName(route) {
		return fmt.Errorf("inner TLS local DNS name must be %q", ConnectorDNSName(route))
	}
	if value.InnerTLS.ServerName != ConnectorDNSName(route) {
		return fmt.Errorf("inner server name must be %q", ConnectorDNSName(route))
	}
	if len(value.InnerTLS.Clients) == 0 {
		return errors.New("legacy inner client allowlist is empty")
	}
	seen := make(map[string]struct{}, len(value.InnerTLS.Clients))
	for index, peer := range value.InnerTLS.Clients {
		if err := validatePeer(peer); err != nil {
			return fmt.Errorf("inner client %d: %w", index, err)
		}
		if _, duplicate := seen[peer.DNSName]; duplicate {
			return fmt.Errorf("duplicate inner client DNS name %q", peer.DNSName)
		}
		seen[peer.DNSName] = struct{}{}
	}
	return nil
}

func (value Client) Validate() error {
	route, err := protocol.ParseRouteID(value.RouteID)
	if err != nil || route == (protocol.RouteID{}) {
		return errors.New("route_id must be a nonzero canonical route ID")
	}
	if err := validateRelayURL(value.RelayURL, value.AllowInsecureCarrier); err != nil {
		return err
	}
	if err := validateClientTLS(value.OuterTLS); err != nil {
		return fmt.Errorf("outer TLS: %w", err)
	}
	if err := validateClientTLS(value.InnerTLS); err != nil {
		return fmt.Errorf("inner TLS: %w", err)
	}
	switch value.InnerProfile {
	case InnerProfileRouteCapability:
		if err := value.validateCapabilityProfile(route); err != nil {
			return err
		}
	case InnerProfileLegacyExactPins:
		if err := value.validateLegacyExactPinProfile(route); err != nil {
			return err
		}
	default:
		return fmt.Errorf("inner_profile must be exactly %q or explicit migration profile %q", InnerProfileRouteCapability, InnerProfileLegacyExactPins)
	}
	for name, duration := range map[string]Duration{
		"connect_timeout":   value.ConnectTimeout,
		"handshake_timeout": value.HandshakeTimeout,
		"ready_timeout":     value.ReadyTimeout,
		"drain_timeout":     value.DrainTimeout,
	} {
		if duration <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	return nil
}

func (value Client) validateCapabilityProfile(route protocol.RouteID) error {
	installationID, err := parseNonzeroInstallationID(value.InstallationID)
	if err != nil {
		return fmt.Errorf("installation_id: %w", err)
	}
	connectorID, err := parseNonzeroInstallationID(value.ConnectorInstallationID)
	if err != nil {
		return fmt.Errorf("connector_installation_id: %w", err)
	}
	if installationID == connectorID {
		return errors.New("client and connector installation IDs must be distinct")
	}
	if value.CredentialEpoch == 0 {
		return errors.New("credential_epoch must be nonzero")
	}
	if value.OuterTLS.LocalDNSName == "" || value.OuterTLS.IssuerCAFile == "" || value.InnerTLS.LocalDNSName == "" || value.InnerTLS.IssuerCAFile == "" {
		return errors.New("capability profile requires strict local identity fields")
	}
	if value.OuterTLS.LocalDNSName != OuterClientDNSName(installationID) {
		return fmt.Errorf("outer TLS local DNS name must be %q", OuterClientDNSName(installationID))
	}
	wantClient := ClientCapabilityDNSName(installationID, connectorID, route, value.CredentialEpoch)
	if value.InnerTLS.LocalDNSName != wantClient {
		return fmt.Errorf("inner TLS local DNS name must be %q", wantClient)
	}
	wantConnector := CapabilityConnectorDNSName(connectorID, route)
	if value.InnerTLS.ServerName != wantConnector {
		return fmt.Errorf("inner TLS server name must be %q", wantConnector)
	}
	return nil
}

func (value Client) validateLegacyExactPinProfile(route protocol.RouteID) error {
	if value.ConnectorInstallationID != "" || value.CredentialEpoch != 0 {
		return errors.New("legacy exact-pin migration profile contains capability-only binding")
	}
	outerStrict := value.OuterTLS.LocalDNSName != ""
	innerStrict := value.InnerTLS.LocalDNSName != ""
	if outerStrict != innerStrict {
		return errors.New("outer and inner TLS must both use strict local identity fields or both use legacy compatibility")
	}
	if value.InstallationID == "" {
		if outerStrict {
			return errors.New("installation_id is required with strict local TLS identity fields")
		}
	} else {
		installationID, err := protocol.ParseID(value.InstallationID)
		if err != nil || installationID == (protocol.ID{}) {
			return errors.New("installation_id must be a nonzero canonical ID")
		}
		if !outerStrict {
			return errors.New("installation_id requires issuer_ca_file and local_dns_name on both TLS profiles")
		}
		if value.OuterTLS.LocalDNSName != OuterClientDNSName(installationID) {
			return fmt.Errorf("outer TLS local DNS name must be %q", OuterClientDNSName(installationID))
		}
		if value.InnerTLS.LocalDNSName != ClientDNSName(installationID) {
			return fmt.Errorf("inner TLS local DNS name must be %q", ClientDNSName(installationID))
		}
	}
	if value.InnerTLS.ServerName != ConnectorDNSName(route) {
		return fmt.Errorf("inner TLS server name must be %q", ConnectorDNSName(route))
	}
	return nil
}

func validateListen(address string) error {
	host, port, err := net.SplitHostPort(address)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("listen must contain an explicit nonzero numeric port")
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("listen host must be a numeric IP address")
	}
	if !parsed.IsLoopback() && !parsed.IsUnspecified() {
		return errors.New("listen address must be loopback or unspecified inside an isolated container")
	}
	return nil
}

// ValidateRelayListen applies the relay's runtime listener policy to tooling
// before that tooling creates credentials or configuration on disk.
func ValidateRelayListen(address string) error {
	return validateListen(address)
}

func validateRelayURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid relay_url: %w", err)
	}
	if parsed.Scheme != "wss" && !(parsed.Scheme == "ws" && allowInsecure) {
		return errors.New("relay_url must use wss, or ws with allow_insecure_carrier explicitly enabled")
	}
	if parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("relay_url must contain only scheme, authority, and exact path")
	}
	if parsed.Path != RelayPath || parsed.RawPath != "" {
		return fmt.Errorf("relay_url path must be exactly %q", RelayPath)
	}
	return nil
}

func validateServerTLS(value ServerTLS) error {
	if value.CertFile == "" || value.KeyFile == "" || value.ClientCAFile == "" {
		return errors.New("certificate, key, and client CA paths are required")
	}
	return validateLocalTLSIdentity(value.IssuerCAFile, value.LocalDNSName)
}

func validateClientTLS(value ClientTLS) error {
	if value.CertFile == "" || value.KeyFile == "" || value.CAFile == "" || value.ServerName == "" {
		return errors.New("certificate, key, CA, and server_name are required")
	}
	if _, err := identity.ParsePinAllowlist(value.SPKIPins); err != nil {
		return fmt.Errorf("server pins: %w", err)
	}
	return validateLocalTLSIdentity(value.IssuerCAFile, value.LocalDNSName)
}

// validateLocalTLSIdentity preserves one deliberately narrow compatibility
// mode for pre-v1 POC configurations: both new fields may be absent. Newly
// rendered configurations set both fields, and partial upgrades fail closed.
func validateLocalTLSIdentity(issuerCAFile, localDNSName string) error {
	if (issuerCAFile == "") != (localDNSName == "") {
		return errors.New("issuer_ca_file and local_dns_name must be set together")
	}
	if localDNSName != "" {
		if err := validateDNSName(localDNSName); err != nil {
			return fmt.Errorf("local_dns_name: %w", err)
		}
	}
	return nil
}

func validatePeer(value AuthorizedPeer) error {
	if err := validateDNSName(value.DNSName); err != nil {
		return err
	}
	if _, err := identity.ParsePinAllowlist(value.SPKIPins); err != nil {
		return fmt.Errorf("pins: %w", err)
	}
	return nil
}

func validateCapabilityRevocations(clientIDs, spkiPins []string) error {
	if len(clientIDs)+len(spkiPins) > MaxCapabilityRevocations {
		return fmt.Errorf("capability revocations exceed combined limit %d", MaxCapabilityRevocations)
	}
	seenIDs := make(map[protocol.ID]struct{}, len(clientIDs))
	for index, encoded := range clientIDs {
		id, err := parseNonzeroInstallationID(encoded)
		if err != nil {
			return fmt.Errorf("revoked client ID %d: %w", index, err)
		}
		if _, duplicate := seenIDs[id]; duplicate {
			return fmt.Errorf("revoked client ID %d is duplicated", index)
		}
		seenIDs[id] = struct{}{}
	}
	if len(spkiPins) != 0 {
		if _, err := identity.ParsePinAllowlist(spkiPins); err != nil {
			return fmt.Errorf("revoked client SPKIs: %w", err)
		}
	}
	return nil
}

func parseNonzeroInstallationID(encoded string) (protocol.ID, error) {
	id, err := protocol.ParseID(encoded)
	if err != nil || id == (protocol.ID{}) {
		return protocol.ID{}, errors.New("must be a nonzero canonical ID")
	}
	return id, nil
}

func validateDNSName(name string) error {
	if name == "" || len(name) > 253 || strings.ToLower(name) != name || strings.HasSuffix(name, ".") {
		return errors.New("DNS name must be a nonempty canonical lowercase literal")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS name contains an invalid label")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return errors.New("DNS name contains a non-canonical character")
			}
		}
	}
	return nil
}

func (limits RelayLimits) validate() error {
	integers := map[string]int{
		"carriers_global":    limits.CarrierGlobal(),
		"outer_handshakes":   limits.OuterHandshakes,
		"pending_global":     limits.PendingGlobal,
		"pending_per_route":  limits.PendingPerRoute,
		"pending_per_client": limits.PendingPerClientValue(),
		"active_global":      limits.ActiveGlobal,
		"active_per_route":   limits.ActivePerRoute,
		"active_per_client":  limits.ActivePerClientValue(),
	}
	for name, value := range integers {
		if value <= 0 || value > 1024 {
			return fmt.Errorf("limit %s must be within 1..1024", name)
		}
	}
	if limits.PendingPerRoute > limits.PendingGlobal || limits.ActivePerRoute > limits.ActiveGlobal {
		return errors.New("per-route limits cannot exceed global limits")
	}
	if limits.PendingPerClientValue() > limits.PendingGlobal || limits.PendingPerClientValue() > limits.PendingPerRoute ||
		limits.ActivePerClientValue() > limits.ActiveGlobal || limits.ActivePerClientValue() > limits.ActivePerRoute {
		return errors.New("per-client limits cannot exceed corresponding global or per-route limits")
	}
	// This is an intentional capacity-reservation policy: when more than one
	// slot exists, no single authenticated client may consume the final slot at
	// either the global or route boundary. Capacity-one legacy configurations
	// remain valid because no positive quota could reserve a slot there.
	if (limits.PendingGlobal > 1 && limits.PendingPerClientValue() >= limits.PendingGlobal) ||
		(limits.PendingPerRoute > 1 && limits.PendingPerClientValue() >= limits.PendingPerRoute) ||
		(limits.ActiveGlobal > 1 && limits.ActivePerClientValue() >= limits.ActiveGlobal) ||
		(limits.ActivePerRoute > 1 && limits.ActivePerClientValue() >= limits.ActivePerRoute) {
		return errors.New("per-client limits must leave a slot when corresponding capacity exceeds one")
	}
	if limits.CarrierGlobal() < limits.minimumCarriers(0) {
		return errors.New("carrier global limit is below configured handshake/session capacity")
	}
	for name, duration := range map[string]Duration{"handshake": limits.Handshake, "preface": limits.Preface, "join": limits.Join, "drain": limits.Drain} {
		if duration <= 0 {
			return fmt.Errorf("limit %s duration must be positive", name)
		}
	}
	if limits.SessionIdleValue() <= 0 || limits.SessionLifetimeValue() <= 0 {
		return errors.New("session idle and lifetime limits must be positive")
	}
	if limits.SessionIdleValue() > limits.SessionLifetimeValue() {
		return errors.New("session idle limit cannot exceed absolute lifetime")
	}
	return nil
}

// minimumCarriers accounts for every WebSocket that may legitimately coexist:
// one current control per route, in-progress outer handshakes, pending clients,
// and both halves of every active pair.
func (limits RelayLimits) minimumCarriers(routes int) int {
	return routes + limits.OuterHandshakes + limits.PendingGlobal + 2*limits.ActiveGlobal
}

func (limits ConnectorLimits) validate() error {
	if limits.Pending <= 0 || limits.Pending > 64 || limits.Active <= 0 || limits.Active > 64 {
		return errors.New("connector pending and active limits must be within 1..64")
	}
	if limits.ActivePerClientValue() <= 0 || limits.ActivePerClientValue() > limits.Active {
		return errors.New("connector active_per_client must be positive and within active")
	}
	for name, duration := range map[string]Duration{
		"connect":       limits.ConnectTimeout,
		"handshake":     limits.Handshake,
		"local_dial":    limits.LocalDial,
		"drain":         limits.Drain,
		"reconnect_min": limits.ReconnectMin,
		"reconnect_max": limits.ReconnectMax,
	} {
		if duration <= 0 {
			return fmt.Errorf("connector %s duration must be positive", name)
		}
	}
	if limits.ReconnectMin > limits.ReconnectMax {
		return errors.New("reconnect_min cannot exceed reconnect_max")
	}
	if limits.SessionIdleValue() <= 0 || limits.SessionLifetimeValue() <= 0 {
		return errors.New("connector session idle and lifetime limits must be positive")
	}
	if limits.SessionIdleValue() > limits.SessionLifetimeValue() {
		return errors.New("connector session idle limit cannot exceed absolute lifetime")
	}
	return nil
}

func ConnectorDNSName(route protocol.RouteID) string {
	return wireprofile.LegacyV1IdentityPrefix + route.String() + wireprofile.LegacyV1ConnectorSuffix
}

// CapabilityConnectorDNSName binds a connector's inner server identity to one
// physical connector installation and one exact route.
func CapabilityConnectorDNSName(connectorID protocol.ID, route protocol.RouteID) string {
	return "i-" + connectorID.String() + ".r-" + route.String() + ".connector.v1.owntransit.invalid"
}

// ClientCapabilityDNSName binds a client credential to one client, connector,
// route, and fixed-width credential epoch. Each identifier occupies its own
// DNS label so the representation remains unambiguous and parseable.
func ClientCapabilityDNSName(clientID, connectorID protocol.ID, route protocol.RouteID, epoch uint64) string {
	return "i-" + clientID.String() + ".r-" + route.String() + ".c-" + connectorID.String() + ".e-" + fmt.Sprintf("%016x", epoch) + ".client-cap.v1.owntransit.invalid"
}

// ParseClientCapabilityDNSName accepts only the canonical capability identity
// emitted by ClientCapabilityDNSName.
func ParseClientCapabilityDNSName(name string) (clientID, connectorID protocol.ID, route protocol.RouteID, epoch uint64, err error) {
	labels := strings.Split(name, ".")
	if len(labels) != 8 || labels[4] != "client-cap" || labels[5] != "v1" || labels[6] != "owntransit" || labels[7] != "invalid" {
		err = errors.New("capability DNS identity has the wrong exact suffix")
		return
	}
	clientID, err = parseCapabilityIDLabel(labels[0], "i-")
	if err != nil {
		err = fmt.Errorf("capability client ID: %w", err)
		return
	}
	route, err = parseCapabilityRouteLabel(labels[1])
	if err != nil {
		err = fmt.Errorf("capability route ID: %w", err)
		return
	}
	connectorID, err = parseCapabilityIDLabel(labels[2], "c-")
	if err != nil {
		err = fmt.Errorf("capability connector ID: %w", err)
		return
	}
	encodedEpoch, ok := strings.CutPrefix(labels[3], "e-")
	if !ok || len(encodedEpoch) != 16 {
		err = errors.New("capability epoch must be fixed-width lowercase hexadecimal")
		return
	}
	epoch, err = strconv.ParseUint(encodedEpoch, 16, 64)
	if err != nil || epoch == 0 || fmt.Sprintf("%016x", epoch) != encodedEpoch {
		err = errors.New("capability epoch must be nonzero fixed-width lowercase hexadecimal")
		return
	}
	if ClientCapabilityDNSName(clientID, connectorID, route, epoch) != name {
		err = errors.New("capability DNS identity is not canonical")
	}
	return
}

func parseCapabilityIDLabel(label, prefix string) (protocol.ID, error) {
	encoded, ok := strings.CutPrefix(label, prefix)
	if !ok {
		return protocol.ID{}, errors.New("identity label has the wrong prefix")
	}
	return parseNonzeroInstallationID(encoded)
}

func parseCapabilityRouteLabel(label string) (protocol.RouteID, error) {
	encoded, ok := strings.CutPrefix(label, "r-")
	if !ok {
		return protocol.RouteID{}, errors.New("route label has the wrong prefix")
	}
	route, err := protocol.ParseRouteID(encoded)
	if err != nil || route == (protocol.RouteID{}) {
		return protocol.RouteID{}, errors.New("route label contains an invalid route ID")
	}
	return route, nil
}

func OuterConnectorDNSName(route protocol.RouteID) string {
	return wireprofile.LegacyV1IdentityPrefix + route.String() + wireprofile.LegacyV1OuterConnectorSuffix
}

func ClientDNSName(id protocol.ID) string {
	return wireprofile.LegacyV1IdentityPrefix + id.String() + wireprofile.LegacyV1ClientSuffix
}

func OuterClientDNSName(id protocol.ID) string {
	return wireprofile.LegacyV1IdentityPrefix + id.String() + wireprofile.LegacyV1OuterClientSuffix
}

// ParseClientInstallationID binds the two authenticated client-role names to
// one physical installation. It accepts only the canonical v1 name formats.
func ParseClientInstallationID(outerDNSName, innerDNSName string) (protocol.ID, error) {
	outer, err := parseClientDNSName(outerDNSName, wireprofile.LegacyV1OuterClientSuffix)
	if err != nil {
		return protocol.ID{}, fmt.Errorf("outer client identity: %w", err)
	}
	inner, err := parseClientDNSName(innerDNSName, wireprofile.LegacyV1ClientSuffix)
	if err != nil {
		return protocol.ID{}, fmt.Errorf("inner client identity: %w", err)
	}
	if outer != inner {
		return protocol.ID{}, errors.New("outer and inner client identities belong to different installations")
	}
	return outer, nil
}

func parseClientDNSName(name, suffix string) (protocol.ID, error) {
	encoded, ok := strings.CutPrefix(name, wireprofile.LegacyV1IdentityPrefix)
	if !ok {
		return protocol.ID{}, errors.New("DNS identity has no canonical client prefix")
	}
	encoded, ok = strings.CutSuffix(encoded, suffix)
	if !ok {
		return protocol.ID{}, errors.New("DNS identity has the wrong client role suffix")
	}
	id, err := protocol.ParseID(encoded)
	if err != nil || id == (protocol.ID{}) {
		return protocol.ID{}, errors.New("DNS identity contains an invalid installation ID")
	}
	return id, nil
}
