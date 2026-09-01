package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/enrollment"
	"github.com/sentrybottale/owntransit/internal/enrollmentexchange"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

const (
	invitationFile         = "invitation.otinvite"
	operatorReceiptFile    = "operator-receipt.otopr"
	courierRegistrationOut = "courier-registration.otreg"
	exchangeSummaryFile    = "summary.json"
	boundResponseFile      = "bound-response.otb"
	operatorRequestFile    = "signed-request.otr"
	invitationStateFile    = ".invitation-state.v1"
	invitationLockFile     = ".invitation.lock"
	boundResponseLockFile  = ".bound-response.lock"
	maxRecipientRecordSize = 4 << 10
	maxInvitationStateSize = 4 << 20
	invitationValidity     = time.Hour
)

type issueInvitationOptions struct {
	authorityDir            string
	role                    string
	connectorInstallationID string
	releaseID               string
	releaseSequence         uint64
	artifactSHA256          string
	goos                    string
	goarch                  string
	exchangeEndpoint        string
	recipientRecord         string
	outputDir               string
	now                     time.Time
}

type operatorOpenOptions struct {
	receiptPath string
	requestPath string
	sessionRoot string
	now         time.Time
}

type operatorConfirmOptions struct {
	sessionRoot string
	now         time.Time
}

type operatorBindOptions struct {
	sessionRoot         string
	responsePath        string
	relayRequest        string
	connectorRequest    string
	clientRequest       string
	deploymentSignerKey string
	outputDir           string
	now                 time.Time
}

type recipientRecord struct {
	Schema                   string `json:"schema"`
	IntendedRecipient        string `json:"intended_recipient"`
	IdentityContactReference string `json:"identity_contact_reference"`
}

type exchangeFileSummary struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

type invitationSummary struct {
	Schema      string                `json:"schema"`
	Role        enrollment.Role       `json:"role"`
	CreatedUnix int64                 `json:"created_unix"`
	ExpiresUnix int64                 `json:"expires_unix"`
	Files       []exchangeFileSummary `json:"files"`
}

type invitationInput struct {
	Schema                  string                    `json:"schema"`
	RouteID                 string                    `json:"route_id"`
	Role                    enrollment.Role           `json:"role"`
	ConnectorInstallationID string                    `json:"connector_installation_id,omitempty"`
	Runtime                 enrollment.RuntimeBinding `json:"runtime"`
	ExchangeEndpoint        string                    `json:"exchange_endpoint"`
	RecipientRecordSHA256   string                    `json:"recipient_record_sha256"`
	RelayCASHA256           string                    `json:"relay_ca_sha256"`
	InnerConnectorCASHA256  string                    `json:"inner_connector_ca_sha256"`
	InnerClientCASHA256     string                    `json:"inner_client_ca_sha256"`
	DeploymentSignerKeyID   string                    `json:"deployment_signer_key_id"`
}

type invitationResumeState struct {
	Schema              string `json:"schema"`
	InputSHA256         string `json:"input_sha256"`
	Invitation          string `json:"invitation"`
	OperatorReceipt     string `json:"operator_receipt"`
	CourierRegistration string `json:"courier_registration"`
	Summary             string `json:"summary"`
}

type operatorSessionSummary struct {
	Schema                   string                          `json:"schema"`
	Phase                    enrollmentexchange.SessionPhase `json:"phase"`
	Generation               uint64                          `json:"generation"`
	Role                     enrollment.Role                 `json:"role"`
	InstallationID           string                          `json:"installation_id"`
	RouteID                  string                          `json:"route_id,omitempty"`
	ConnectorInstallationID  string                          `json:"connector_installation_id,omitempty"`
	IntendedRecipient        string                          `json:"intended_recipient"`
	IdentityContactReference string                          `json:"identity_contact_reference"`
	Request                  exchangeFileSummary             `json:"request"`
}

type boundResponseSummary struct {
	Schema string              `json:"schema"`
	File   exchangeFileSummary `json:"file"`
}

func issueInvitationBundle(options issueInvitationOptions) ([]byte, error) {
	now := options.now.UTC().Truncate(time.Second)
	role := enrollment.Role(options.role)
	if now.IsZero() || role != enrollment.RoleRelay && role != enrollment.RoleConnector && role != enrollment.RoleClient {
		return nil, errors.New("current time and exact target role are required")
	}
	authority, err := loadAuthoritySummary(options.authorityDir)
	if err != nil {
		return nil, err
	}
	readAuthority := func(name string, private bool) ([]byte, error) {
		return readRegularFile(filepath.Join(options.authorityDir, name), maxOfflineKeyFileSize, private)
	}
	relayCA, err := readAuthority(outerIssuerCertFile, false)
	if err != nil {
		return nil, err
	}
	innerConnectorCA, err := readAuthority(innerConnectorCertFile, false)
	if err != nil {
		return nil, err
	}
	innerClientCA, err := readAuthority(innerClientIssuerCertFile, false)
	if err != nil {
		return nil, err
	}
	signerBytes, err := readAuthority(deploymentSignerKeyFile, true)
	if err != nil {
		return nil, err
	}
	signer, err := signing.ParsePrivate(signerBytes)
	if err != nil {
		return nil, err
	}
	recordBytes, err := readRegularFile(options.recipientRecord, maxRecipientRecordSize, true)
	if err != nil {
		return nil, err
	}
	record, err := parseRecipientRecord(recordBytes)
	if err != nil {
		return nil, err
	}
	runtime := enrollment.RuntimeBinding{
		ReleaseID: options.releaseID, ReleaseSequence: options.releaseSequence, ArtifactSHA256: options.artifactSHA256,
		OS: options.goos, Arch: options.goarch, Role: role, Protocol: enrollment.DeploymentProtocol,
		LifecycleGeneration: enrollment.CurrentLifecycleGeneration,
	}
	if role == enrollment.RoleConnector {
		runtime.ConnectorTarget = "tcp4/" + config.ConnectorSSHTarget
	}
	routeID := authority.RouteID
	if role == enrollment.RoleRelay {
		routeID = ""
	}
	inputDigest, err := invitationInputDigest(invitationInput{
		Schema: "owntransit.provision.invitation-input.v1", RouteID: authority.RouteID, Role: role,
		ConnectorInstallationID: options.connectorInstallationID, Runtime: runtime, ExchangeEndpoint: options.exchangeEndpoint,
		RecipientRecordSHA256: digestHex(recordBytes), RelayCASHA256: digestHex(relayCA),
		InnerConnectorCASHA256: digestHex(innerConnectorCA), InnerClientCASHA256: digestHex(innerClientCA),
		DeploymentSignerKeyID: signing.KeyID(signer.Public().(ed25519.PublicKey)),
	})
	if err != nil {
		return nil, err
	}
	root, err := createOrOpenExchangeRoot(options.outputDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := root.TryLock(invitationLockFile)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	var issued enrollmentexchange.IssuedInvitation
	var summaryBytes []byte
	stateBytes, stateErr := root.ReadFile(invitationStateFile, maxInvitationStateSize)
	if stateErr == nil {
		issued, summaryBytes, err = parseInvitationResumeState(stateBytes, inputDigest, role, now)
		if err != nil {
			return nil, err
		}
	} else {
		if !errors.Is(stateErr, os.ErrNotExist) {
			return nil, stateErr
		}
		issued, err = enrollmentexchange.IssueInvitation(enrollmentexchange.InvitationOptions{
			Role: role, RouteID: routeID, ConnectorInstallationID: options.connectorInstallationID,
			Runtime:          runtime,
			Trust:            enrollment.Trust{RelayAdmissionCA: string(relayCA), InnerClientCA: string(innerClientCA), InnerConnectorCA: string(innerConnectorCA)},
			ExchangeEndpoint: options.exchangeEndpoint, Validity: invitationValidity,
			IntendedRecipient: record.IntendedRecipient, IdentityContactReference: record.IdentityContactReference,
		}, signer, now)
		if err != nil {
			return nil, err
		}
		summaryBytes, err = invitationBundleSummary(role, now, issued)
		if err != nil {
			return nil, err
		}
		stateBytes, err = encodeInvitationResumeState(inputDigest, issued, summaryBytes)
		if err != nil {
			return nil, err
		}
		if err := root.EnsureFile(invitationStateFile, stateBytes, 0o600); err != nil {
			return nil, err
		}
	}
	files := []struct {
		name string
		data []byte
		mode fs.FileMode
	}{
		{invitationFile, issued.Invitation, 0o644},
		{operatorReceiptFile, issued.OperatorReceipt, 0o600},
		{courierRegistrationOut, issued.CourierRegistration, 0o600},
	}
	for _, file := range files {
		if err := root.EnsureFile(file.name, file.data, file.mode); err != nil {
			return nil, err
		}
	}
	if err := root.EnsureFile(exchangeSummaryFile, summaryBytes, 0o644); err != nil {
		return nil, err
	}
	return summaryBytes, nil
}

func invitationBundleSummary(role enrollment.Role, now time.Time, issued enrollmentexchange.IssuedInvitation) ([]byte, error) {
	files := []struct {
		name string
		data []byte
	}{
		{invitationFile, issued.Invitation}, {operatorReceiptFile, issued.OperatorReceipt}, {courierRegistrationOut, issued.CourierRegistration},
	}
	summary := invitationSummary{Schema: "owntransit.provision.invitation-bundle.v1", Role: role, CreatedUnix: now.Unix(), ExpiresUnix: now.Add(invitationValidity).Unix()}
	for _, file := range files {
		summary.Files = append(summary.Files, exchangeFileSummary{File: file.name, SHA256: digestHex(file.data), Size: len(file.data)})
	}
	return encodeSummary(summary)
}

func invitationInputDigest(input invitationInput) (string, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	return digestHex(encoded), nil
}

func encodeInvitationResumeState(inputDigest string, issued enrollmentexchange.IssuedInvitation, summary []byte) ([]byte, error) {
	state := invitationResumeState{
		Schema: "owntransit.provision.invitation-state.v1", InputSHA256: inputDigest,
		Invitation: base64.StdEncoding.EncodeToString(issued.Invitation), OperatorReceipt: base64.StdEncoding.EncodeToString(issued.OperatorReceipt),
		CourierRegistration: base64.StdEncoding.EncodeToString(issued.CourierRegistration), Summary: base64.StdEncoding.EncodeToString(summary),
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxInvitationStateSize {
		return nil, errors.New("invitation resume state exceeds its bound")
	}
	return encoded, nil
}

func parseInvitationResumeState(encoded []byte, inputDigest string, expectedRole enrollment.Role, now time.Time) (enrollmentexchange.IssuedInvitation, []byte, error) {
	var state invitationResumeState
	if len(encoded) == 0 || len(encoded) > maxInvitationStateSize || strictjson.Decode(encoded, &state) != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, errors.New("invitation resume state is invalid")
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, encoded) || state.Schema != "owntransit.provision.invitation-state.v1" || state.InputSHA256 != inputDigest {
		return enrollmentexchange.IssuedInvitation{}, nil, errors.New("invitation resume state belongs to another exact operation")
	}
	decode := func(value string, limit int) ([]byte, error) {
		decoded, decodeErr := base64.StdEncoding.DecodeString(value)
		if decodeErr != nil || base64.StdEncoding.EncodeToString(decoded) != value || len(decoded) == 0 || len(decoded) > limit {
			return nil, errors.New("invitation resume artifact is invalid")
		}
		return decoded, nil
	}
	invitation, err := decode(state.Invitation, enrollmentexchange.MaxInvitationSize)
	if err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	receipt, err := decode(state.OperatorReceipt, enrollmentexchange.MaxOperatorReceiptSize)
	if err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	registration, err := decode(state.CourierRegistration, enrollmentexchange.MaxCourierRegistrationSize)
	if err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	summaryBytes, err := decode(state.Summary, 64<<10)
	if err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	if _, err := enrollmentexchange.ParseCourierRegistration(registration, now); err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	var summary invitationSummary
	if err := strictjson.Decode(summaryBytes, &summary); err != nil {
		return enrollmentexchange.IssuedInvitation{}, nil, err
	}
	canonicalSummary, err := encodeSummary(summary)
	if err != nil || !bytes.Equal(canonicalSummary, summaryBytes) || summary.Schema != "owntransit.provision.invitation-bundle.v1" || summary.Role != expectedRole || len(summary.Files) != 3 {
		return enrollmentexchange.IssuedInvitation{}, nil, errors.New("invitation resume summary is invalid")
	}
	created := time.Unix(summary.CreatedUnix, 0).UTC()
	expires := time.Unix(summary.ExpiresUnix, 0).UTC()
	if summary.CreatedUnix <= 0 || summary.ExpiresUnix-summary.CreatedUnix != int64(invitationValidity/time.Second) ||
		now.Before(created.Add(-5*time.Minute)) || !now.Before(expires) {
		return enrollmentexchange.IssuedInvitation{}, nil, errors.New("invitation resume summary is expired or inconsistent")
	}
	issued := enrollmentexchange.IssuedInvitation{Invitation: invitation, OperatorReceipt: receipt, CourierRegistration: registration}
	wantSummary, err := invitationBundleSummary(summary.Role, created, issued)
	if err != nil || !bytes.Equal(wantSummary, summaryBytes) || summary.ExpiresUnix != summary.CreatedUnix+int64(invitationValidity/time.Second) {
		return enrollmentexchange.IssuedInvitation{}, nil, errors.New("invitation resume artifacts differ from their summary")
	}
	return issued, summaryBytes, nil
}

func createOrOpenExchangeRoot(path string) (*securefs.Root, error) {
	root, err := createOutputRoot(path)
	if err == nil {
		return root, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	absolute, absoluteErr := filepath.Abs(path)
	if absoluteErr != nil || filepath.Clean(absolute) == string(filepath.Separator) {
		return nil, errors.New("invitation output directory is invalid")
	}
	parent, resolveErr := filepath.EvalSymlinks(filepath.Dir(filepath.Clean(absolute)))
	if resolveErr != nil {
		return nil, resolveErr
	}
	return securefs.OpenRoot(filepath.Join(parent, filepath.Base(absolute)))
}

func digestHex(encoded []byte) string {
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func openOperatorSession(options operatorOpenOptions) ([]byte, error) {
	receipt, err := readRegularFile(options.receiptPath, enrollmentexchange.MaxOperatorReceiptSize, true)
	if err != nil {
		return nil, err
	}
	request, err := readRegularFile(options.requestPath, enrollmentexchange.MaxEncryptedRequestSize, true)
	if err != nil {
		return nil, err
	}
	session, err := enrollmentexchange.OpenOperatorStore(options.sessionRoot, receipt, request, options.now)
	if err != nil {
		return nil, err
	}
	signedRequest, err := session.SignedRequest()
	if err != nil {
		return nil, err
	}
	root, err := securefs.OpenRoot(options.sessionRoot)
	if err != nil {
		return nil, err
	}
	if err := root.EnsureFile(operatorRequestFile, signedRequest, 0o600); err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	review, err := session.Review()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(signedRequest)
	return encodeSummary(operatorSessionSummary{
		Schema: "owntransit.provision.operator-session.v1", Phase: session.Phase(), Generation: session.Generation(),
		Role: review.Role, InstallationID: review.InstallationID, RouteID: review.RouteID,
		ConnectorInstallationID: review.ConnectorInstallationID,
		IntendedRecipient:       review.IntendedRecipient, IdentityContactReference: review.IdentityContactReference,
		Request: exchangeFileSummary{File: operatorRequestFile, SHA256: hex.EncodeToString(digest[:]), Size: len(signedRequest)},
	})
}

func confirmOperatorSession(options operatorConfirmOptions, input io.Reader) ([]byte, error) {
	session, err := enrollmentexchange.LoadOperatorStore(options.sessionRoot, options.now)
	if err != nil {
		return nil, err
	}
	if session.Phase() == enrollmentexchange.PhaseTranscriptConfirmed {
		words, err := session.ProvisionerWords()
		if err != nil {
			return nil, err
		}
		return encodeReverseWords(words), nil
	}
	words, err := readComparisonWords(input)
	if err != nil {
		return nil, err
	}
	generation := session.Generation()
	outcome, err := session.ConfirmTargetWords(words)
	if err != nil {
		return nil, err
	}
	if outcome == enrollmentexchange.OutcomeDeferred {
		return nil, errors.New("three locally typed target words are required")
	}
	if err := enrollmentexchange.ReplaceOperatorStore(options.sessionRoot, generation, session, options.now); err != nil {
		return nil, err
	}
	if outcome != enrollmentexchange.OutcomeConfirmed {
		return nil, errors.New("comparison failed; operator session is cancelled")
	}
	reverse, err := session.ProvisionerWords()
	if err != nil {
		return nil, err
	}
	return encodeReverseWords(reverse), nil
}

func bindOperatorResponse(options operatorBindOptions) ([]byte, error) {
	session, err := enrollmentexchange.LoadOperatorStore(options.sessionRoot, options.now)
	if err != nil {
		return nil, err
	}
	response, err := readRegularFile(options.responsePath, enrollment.MaxEnvelopeSize, true)
	if err != nil {
		return nil, err
	}
	relayRequest, err := readRegularFile(options.relayRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, err
	}
	connectorRequest, err := readRegularFile(options.connectorRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, err
	}
	clientRequest, err := readRegularFile(options.clientRequest, enrollment.MaxRequestSize, false)
	if err != nil {
		return nil, err
	}
	sessionRequest, err := session.SignedRequest()
	if err != nil {
		return nil, err
	}
	review, err := session.Review()
	if err != nil {
		return nil, err
	}
	var approvedTargetRequest []byte
	switch review.Role {
	case enrollment.RoleRelay:
		approvedTargetRequest = relayRequest
	case enrollment.RoleConnector:
		approvedTargetRequest = connectorRequest
	case enrollment.RoleClient:
		approvedTargetRequest = clientRequest
	default:
		return nil, errors.New("operator session has an invalid target role")
	}
	if !bytes.Equal(sessionRequest, approvedTargetRequest) {
		return nil, errors.New("operator session request is absent from the exact approved request set")
	}
	approvedSet, err := enrollmentexchange.ApprovedRequestSetSHA256(relayRequest, connectorRequest, clientRequest, options.now)
	if err != nil {
		return nil, err
	}
	signerBytes, err := readRegularFile(options.deploymentSignerKey, maxOfflineKeyFileSize, true)
	if err != nil {
		return nil, err
	}
	signer, err := signing.ParsePrivate(signerBytes)
	if err != nil {
		return nil, err
	}
	bound, err := session.BindResponse(response, approvedSet, ed25519.PrivateKey(signer))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(bound)
	summary := boundResponseSummary{Schema: "owntransit.provision.bound-response.v1", File: exchangeFileSummary{File: boundResponseFile, SHA256: hex.EncodeToString(digest[:]), Size: len(bound)}}
	summaryBytes, err := encodeSummary(summary)
	if err != nil {
		return nil, err
	}
	root, err := createOrOpenExchangeRoot(options.outputDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lock, err := root.TryLock(boundResponseLockFile)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := root.EnsureFile(boundResponseFile, bound, 0o600); err != nil {
		return nil, err
	}
	if err := root.EnsureFile(exchangeSummaryFile, summaryBytes, 0o644); err != nil {
		return nil, err
	}
	return summaryBytes, nil
}

func loadAuthoritySummary(authorityDir string) (authoritySummary, error) {
	encoded, err := readRegularFile(filepath.Join(authorityDir, authoritySummaryFile), 64<<10, false)
	if err != nil {
		return authoritySummary{}, err
	}
	var value authoritySummary
	if err := strictjson.Decode(encoded, &value); err != nil {
		return authoritySummary{}, err
	}
	canonical, err := encodeSummary(value)
	if err != nil || !bytes.Equal(canonical, encoded) || value.Schema != "owntransit.provision.authority.v1" || value.RouteID == "" {
		return authoritySummary{}, errors.New("authority summary is noncanonical or unsupported")
	}
	return value, nil
}

func parseRecipientRecord(encoded []byte) (recipientRecord, error) {
	var value recipientRecord
	if err := strictjson.Decode(encoded, &value); err != nil {
		return recipientRecord{}, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return recipientRecord{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) || value.Schema != "owntransit.recipient-record.v1" {
		return recipientRecord{}, errors.New("recipient record is noncanonical or unsupported")
	}
	return value, nil
}

func readComparisonWords(input io.Reader) ([3]string, error) {
	var result [3]string
	if input == nil {
		return result, errors.New("comparison input is unavailable")
	}
	encoded, err := io.ReadAll(io.LimitReader(input, 257))
	if err != nil || len(encoded) == 0 || len(encoded) > 256 {
		return result, errors.New("comparison input must contain exactly three bounded words")
	}
	fields := strings.Fields(string(encoded))
	if len(fields) != len(result) {
		return result, errors.New("comparison input must contain exactly three bounded words")
	}
	copy(result[:], fields)
	return result, nil
}

func encodeReverseWords(words [3]string) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n", words[0], words[1], words[2]))
}
