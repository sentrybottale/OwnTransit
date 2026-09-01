package enrollmentexchange

import (
	"errors"
	"time"

	"github.com/sentrybottale/owntransit/internal/enrollment"
)

// ClientBootstrap is the narrow tentative invitation view needed to create a
// client request. It deliberately omits mailbox capabilities. These values do
// not become trusted until the durable two-way transcript ceremony completes.
type ClientBootstrap struct {
	InvitationSHA256          string
	ExpiresUnix               int64
	Runtime                   enrollment.RuntimeBinding
	Trust                     enrollment.Trust
	DeploymentSignerPublicPEM []byte
	RouteID                   string
	ConnectorInstallationID   string
}

// PrepareClientBootstrap verifies the canonical self-signed invitation and
// requires an exact match with the independently authenticated installed
// client artifact. It does not authenticate the human administrator.
func PrepareClientBootstrap(encoded []byte, expectedRuntime enrollment.RuntimeBinding, now time.Time) (ClientBootstrap, error) {
	tentative, err := parseTentativeInvitation(encoded, now)
	if err != nil {
		return ClientBootstrap{}, err
	}
	if tentative.Invitation.Role != enrollment.RoleClient || tentative.Invitation.Runtime != expectedRuntime {
		return ClientBootstrap{}, errors.New("enrollmentexchange: invitation does not target the authenticated installed client runtime")
	}
	return ClientBootstrap{
		InvitationSHA256:          tentative.SHA256,
		ExpiresUnix:               tentative.Invitation.ExpiresUnix,
		Runtime:                   tentative.Invitation.Runtime,
		Trust:                     tentative.Invitation.Trust,
		DeploymentSignerPublicPEM: []byte(tentative.Invitation.DeploymentSignerPublicPEM),
		RouteID:                   tentative.Invitation.RouteID,
		ConnectorInstallationID:   tentative.Invitation.ConnectorInstallationID,
	}, nil
}

// InvitationSHA256 and RequestSHA256 are immutable session bindings used by
// the privileged coordinator to reject cross-wired durable state.
func (session *TargetSession) InvitationSHA256() string {
	if session == nil {
		return ""
	}
	return digestText(session.invitationSHA256)
}

func (session *TargetSession) RequestSHA256() string {
	if session == nil {
		return ""
	}
	return digestText(session.requestSHA256)
}

func digestText(value [32]byte) string {
	const alphabet = "0123456789abcdef"
	encoded := make([]byte, len(value)*2)
	for index, item := range value {
		encoded[index*2] = alphabet[item>>4]
		encoded[index*2+1] = alphabet[item&0x0f]
	}
	return string(encoded)
}
