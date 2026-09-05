//go:build linux

package relaysetup

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

func (r *routeChange) validate(ctx context.Context) error {
	args := []string{"-t"}
	if r.kind == "caddy" {
		args = []string{"validate", "--config", r.path, "--adapter", "caddyfile"}
	}
	_, err := command(ctx, r.program, args...)
	return err
}
func (r *routeChange) reload(ctx context.Context) error {
	args := []string{"-s", "reload"}
	if r.kind == "caddy" {
		args = []string{"reload", "--config", r.path, "--adapter", "caddyfile"}
	} else if r.kind == "apache" {
		args = []string{"graceful"}
	}
	_, err := command(ctx, r.program, args...)
	return err
}

var apacheFile = regexp.MustCompile(`\((/[^()]+):[0-9]+\)`)

func prepareOtherRoute(ctx context.Context, hostname string) (*routeChange, error) {
	for _, candidate := range []struct{ program, service string }{{"/usr/sbin/apache2ctl", "apache2.service"}, {"/usr/sbin/apachectl", "httpd.service"}} {
		if _, err := os.Stat(candidate.program); err != nil {
			continue
		}
		if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", candidate.service); err != nil {
			continue
		}
		dump, err := combined(ctx, candidate.program, "-S")
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		var chosen *routeChange
		for _, m := range apacheFile.FindAllSubmatch(dump, -1) {
			path, err := filepath.EvalSymlinks(string(m[1]))
			if err != nil || seen[path] {
				continue
			}
			seen[path] = true
			data, mode, err := protectedFile(path)
			if err != nil {
				return nil, err
			}
			edit, err := ApacheRoute(data, hostname)
			if errors.Is(err, ErrNoSite) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if chosen != nil {
				return nil, ErrRoute
			}
			chosen = &routeChange{path: path, program: candidate.program, edit: edit, mode: mode, kind: "apache"}
		}
		if chosen != nil {
			return chosen, nil
		}
	}
	if _, err := os.Stat("/usr/bin/caddy"); err == nil {
		if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "caddy.service"); err == nil {
			path, err := filepath.EvalSymlinks("/etc/caddy/Caddyfile")
			if err != nil {
				return nil, err
			}
			data, mode, err := protectedFile(path)
			if err != nil {
				return nil, err
			}
			edit, err := CaddyRoute(data, hostname)
			if err != nil {
				return nil, err
			}
			return &routeChange{path: path, program: "/usr/bin/caddy", edit: edit, mode: mode, kind: "caddy"}, nil
		}
	}
	return nil, errors.New("no matching local HTTPS site was found; the public URL must be served by this VPS or routed to its loopback relay by your existing proxy")
}

func combined(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	var out boundedBuffer
	out.limit = maxConfigBytes
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil, errors.New("webserver inspection failed")
	}
	return out.Bytes(), nil
}

func adoptState(c containerInfo, dataDir string) error {
	var source string
	for _, m := range c.Mounts {
		if m.Type == "bind" && m.Destination == "/state" {
			if source != "" {
				return errors.New("ambiguous relay state mounts")
			}
			source = filepath.Join(m.Source, "relay")
		}
	}
	if source == "" {
		return errors.New("the previous paired relay uses an unsupported state mount; its identity was preserved")
	}
	fd, err := untrustedDirectory(source)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var directoryStat unix.Stat_t
	if unix.Fstat(fd, &directoryStat) != nil || directoryStat.Mode&0777 != 0700 {
		return errors.New("previous relay state is not private")
	}
	// Stage under the root-owned parent, never in a directory writable by a
	// potentially compromised old relay. Final publication is no-replace.
	target, err := os.MkdirTemp(managedRoot, "adopt-")
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			os.RemoveAll(target)
		}
	}()
	for _, name := range []string{"token-hmac.key", "relay-ca-cert.pem", "relay-ca-key.pem", "relay-cert.pem", "relay-key.pem", "service.lock"} {
		mode := os.FileMode(0600)
		if name == "relay-ca-cert.pem" || name == "relay-cert.pem" {
			mode = 0644
		}
		member, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			return errors.New("unsafe previous relay state member")
		}
		var st unix.Stat_t
		if unix.Fstat(member, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != directoryStat.Uid || st.Mode&0777 != uint32(mode) || st.Size < 0 || st.Size > 65536 {
			unix.Close(member)
			return errors.New("invalid previous relay state member")
		}
		fileReader := os.NewFile(uintptr(member), name)
		data, err := io.ReadAll(io.LimitReader(fileReader, 65537))
		fileReader.Close()
		if err != nil || len(data) > 65536 {
			return errors.New("previous relay state exceeds its bound")
		}
		if name == "service.lock" {
			data = nil
		}
		file := filepath.Join(target, name)
		if err := os.WriteFile(file, data, mode); err != nil {
			return err
		}
		if err := os.Chown(file, 65532, 65532); err != nil {
			return err
		}
	}
	if err := os.Chown(target, 65532, 65532); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, target, unix.AT_FDCWD, filepath.Join(dataDir, "relay"), unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	complete = true
	return nil
}

func untrustedDirectory(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, errors.New("invalid previous state path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return -1, errors.New("symlinked or unavailable previous state path")
		}
		fd = next
	}
	return fd, nil
}
