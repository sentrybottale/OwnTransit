//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentrybottale/owntransit/internal/securefs"
)

// Journals retain only a bounded reference to an exact root-protected backup.
// Reconstructing the planned edit binds recovery to the selected URL/port and
// current adapter, rather than accepting arbitrary replacement bytes.
type routeRecovery struct {
	Path, Program, Kind, Backup, BeforeDigest, AfterDigest string
	Mode                                                   uint32
}

func routeBackupName(path string, before []byte) string {
	hash := sha256.Sum256(append([]byte(path+"\x00"), before...))
	return "site-" + hex.EncodeToString(hash[:8]) + ".backup"
}

func validRouteRecovery(r *routeRecovery) bool {
	if r == nil || !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || r.Mode&^uint32(0755) != 0 || r.Mode&0022 != 0 || !validImage("sha256:"+r.BeforeDigest) || !validImage("sha256:"+r.AfterDigest) || r.BeforeDigest == r.AfterDigest || len(r.Backup) != len("site-")+16+len(".backup") {
		return false
	}
	if !strings.HasPrefix(r.Backup, "site-") || !strings.HasSuffix(r.Backup, ".backup") {
		return false
	}
	if _, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(r.Backup, "site-"), ".backup")); err != nil {
		return false
	}
	switch r.Kind {
	case "nginx":
		return r.Program == "/usr/sbin/nginx"
	case "caddy":
		return r.Program == "/usr/bin/caddy"
	case "apache":
		return r.Program == "/usr/sbin/apache2ctl" || r.Program == "/usr/sbin/apachectl"
	}
	return false
}

func (r *routeChange) recovery(root *securefs.Root) (*routeRecovery, error) {
	if r.edit.Reused {
		return nil, nil
	}
	j := &routeRecovery{Path: r.path, Program: r.program, Kind: r.kind, Backup: routeBackupName(r.path, r.edit.Before), BeforeDigest: routeDigest(r, false), AfterDigest: routeDigest(r, true), Mode: uint32(r.mode)}
	if !validRouteRecovery(j) {
		return nil, errors.New("invalid website route recovery selection")
	}
	if err := root.EnsureFile(j.Backup, r.edit.Before, 0600); err != nil {
		return nil, err
	}
	return j, nil
}

func (s instanceSpec) recordedRoute(root *securefs.Root, j *routeRecovery) (*routeChange, error) {
	if !validRouteRecovery(j) {
		return nil, errors.New("invalid website route recovery journal")
	}
	before, err := root.ReadPrivateFile(j.Backup, maxConfigBytes)
	if err != nil || routeBackupName(j.Path, before) != j.Backup {
		return nil, errors.New("website route backup is missing or changed")
	}
	parsed, err := url.Parse(s.url)
	if err != nil {
		return nil, ErrRoute
	}
	var edit RouteEdit
	switch j.Kind {
	case "nginx":
		edit, err = NginxRouteForPort(before, parsed.Hostname(), s.port)
	case "caddy":
		edit, err = CaddyRouteForPort(before, parsed.Hostname(), s.port)
	case "apache":
		edit, err = ApacheRouteForPort(before, parsed.Hostname(), s.port)
	}
	if err != nil || edit.Reused {
		return nil, errors.New("website route backup no longer identifies the planned edit")
	}
	r := &routeChange{path: j.Path, program: j.Program, kind: j.Kind, mode: os.FileMode(j.Mode), edit: edit}
	if routeDigest(r, false) != j.BeforeDigest || routeDigest(r, true) != j.AfterDigest {
		return nil, errors.New("website route recovery digests do not match")
	}
	current, mode, err := protectedFile(r.path)
	if err != nil || mode != r.mode || !bytes.Equal(current, edit.Before) && !bytes.Equal(current, edit.After) {
		return nil, errors.New("website route changed outside setup; recovery refused")
	}
	return r, nil
}

func restoreRecordedRoute(ctx context.Context, r *routeChange) error {
	if r == nil {
		return nil
	}
	return r.rollback(ctx)
}
