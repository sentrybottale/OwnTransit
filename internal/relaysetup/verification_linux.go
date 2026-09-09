//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/identity"
	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/pairrelaycmd"
	"golang.org/x/sys/unix"
)

var errProbeIdentityMismatch = errors.New("public or local relay identity does not match the retained relay")

type verificationEvidence struct {
	URL, Engine, DataRootDigest, RouteDigest, Required string
	Port                                               int
	Identity                                           pairrelay.ServerInfo
	Digests                                            map[string]string
}
type verificationEvidenceKey struct{}

func (source migrationSource) evidence(publicURL string) verificationEvidence {
	return verificationEvidence{URL: publicURL, Engine: source.Engine, Port: source.Port, DataRootDigest: planDigest(legacyRoot(source.Label) + "/data"), RouteDigest: source.RouteDigest, Required: source.Verification, Identity: source.Identity, Digests: source.Digests}
}
func withVerificationEvidence(ctx context.Context, e verificationEvidence) context.Context {
	return context.WithValue(ctx, verificationEvidenceKey{}, e)
}

func routeDigest(route *routeChange, after bool) string {
	data := route.edit.Before
	if after {
		data = route.edit.After
	}
	return planDigest(struct {
		Path string
		Data []byte
	}{route.path, data})
}
func (s instanceSpec) captureVerificationEvidence(ctx context.Context, engine string, route *routeChange) (verificationEvidence, error) {
	plannedRoute := route != nil
	e := verificationEvidence{URL: s.url, Engine: engine, Port: s.port, DataRootDigest: planDigest(s.dataRoot()), Required: VerificationPublic}
	var err error
	e.Digests, err = identityDigests(s)
	if err != nil {
		return e, err
	}
	e.Identity, err = readPublicIdentity(s)
	if err != nil {
		return e, err
	}
	if err := checkIdentityDigests(s, e.Digests); err != nil {
		return e, err
	}
	if route == nil {
		parsed, _ := url.Parse(s.url)
		route, err = prepareRouteForPort(ctx, parsed.Hostname(), s.port)
		if err != nil {
			return e, err
		}
	}
	if route == nil {
		return e, ErrRoute
	}
	e.RouteDigest = routeDigest(route, plannedRoute)
	remote, probeErr := probeServer(ctx, s.url)
	if errors.Is(probeErr, errProbeForbidden) {
		if !plannedRoute && !route.edit.Reused {
			return e, errors.New("HTTP 403 cannot authorize upgrade without an existing exact local route")
		}
		e.Required = VerificationLocal403
	} else if probeErr == nil && !sameIdentity(remote, e.Identity) {
		return e, errProbeIdentityMismatch
	}
	return e, nil
}
func (s instanceSpec) validVerificationEvidence(e verificationEvidence) bool {
	if e.URL != s.url || e.Port != s.port || e.DataRootDigest != planDigest(s.dataRoot()) || !validEngine(e.Engine) || !validImage("sha256:"+e.RouteDigest) || (e.Required != VerificationPublic && e.Required != VerificationLocal403) || len(e.Digests) != 5 || e.Identity.ServerName != pairrelaycmd.RelayServerName || len(e.Identity.CAPEM) == 0 || len(e.Identity.CAPEM) > pairrelay.MaxAdmissionCABytes {
		return false
	}
	if _, err := identity.ParseSPKIPin(e.Identity.LeafSPKISHA256); err != nil {
		return false
	}
	for _, name := range relayIdentityFiles {
		if !validImage("sha256:" + e.Digests[name]) {
			return false
		}
	}
	return true
}
func (s instanceSpec) checkVerificationEvidence(ctx context.Context, e verificationEvidence, local pairrelay.ServerInfo, engine string, localOnly bool) error {
	if !s.validVerificationEvidence(e) || e.Engine != engine || !sameIdentity(e.Identity, local) {
		return errProbeIdentityMismatch
	}
	if err := checkIdentityDigests(s, e.Digests); err != nil {
		return errors.Join(errProbeIdentityMismatch, err)
	}
	if localOnly {
		if e.Required != VerificationLocal403 {
			return errors.New("public verification changed to HTTP 403 after preparation")
		}
		parsed, _ := url.Parse(s.url)
		route, err := prepareRouteForPort(ctx, parsed.Hostname(), s.port)
		if err != nil {
			return err
		}
		if route == nil || !route.edit.Reused || routeDigest(route, false) != e.RouteDigest {
			return errors.New("HTTP 403 cannot verify an absent or changed local website route")
		}
		c, err := inspect(ctx, engine, s.container)
		if err != nil || !c.State.Running || !confined(c) {
			return errors.New("local relay confinement could not be verified")
		}
	}
	return nil
}
func reportVerification(out io.Writer, level string) {
	if level == VerificationLocal403 {
		fmt.Fprintln(out, "Local relay service and exact website route verified. HTTP 403 blocked this VPS's verified HTTPS probe; public reachability was not proved here. Continue receiver/client setup from an allowed network to verify its own public connection.")
	} else {
		fmt.Fprintln(out, "Relay public WebSocket route and retained identity verified from this VPS.")
	}
}

// Read only the public certificates through an opened, non-followed state
// directory. The private key bytes are never parsed or copied by this helper.
func readPublicIdentity(s instanceSpec) (pairrelay.ServerInfo, error) {
	if err := s.validateData(); err != nil {
		return pairrelay.ServerInfo{}, err
	}
	fd, err := unix.Open(s.dataRoot()+"/relay", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	defer unix.Close(fd)
	read := func(name string) ([]byte, error) {
		fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		file := os.NewFile(uintptr(fileFD), "relay-public-certificate")
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 || st.Uid != 65532 || st.Gid != 65532 || st.Nlink != 1 || info.Size() > 32768 {
			return nil, errors.New("unsafe public relay certificate")
		}
		b, err := io.ReadAll(io.LimitReader(file, 32769))
		if err != nil || int64(len(b)) != info.Size() {
			return nil, errors.New("public relay certificate changed")
		}
		return b, nil
	}
	ca, err := read("relay-ca-cert.pem")
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	encoded, err := read("relay-cert.pem")
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return pairrelay.ServerInfo{}, errors.New("invalid public relay leaf")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != pairrelaycmd.RelayServerName {
		return pairrelay.ServerInfo{}, errors.New("unexpected public relay certificate identity")
	}
	pin, err := identity.SPKIPin(leaf)
	if err != nil {
		return pairrelay.ServerInfo{}, err
	}
	if strings.TrimSpace(string(ca)) == "" {
		return pairrelay.ServerInfo{}, errors.New("missing public relay CA")
	}
	return pairrelay.ServerInfo{ServerName: pairrelaycmd.RelayServerName, CAPEM: ca, LeafSPKISHA256: pin}, nil
}
