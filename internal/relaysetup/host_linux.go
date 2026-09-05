//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const managedRoot = "/var/lib/owntransit-relay-setup"
const managedContainer = "owntransit-relay-managed"
const managedUnit = "owntransit-relay-managed.service"
const unitPath = "/etc/systemd/system/" + managedUnit
const imageTag = "owntransit-relay-pair:0.1.3"

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, errors.New("command output exceeded its bound")
	}
	return b.Buffer.Write(p)
}

var command = runCommand
var firstProbeTimeout = 5 * time.Second
var routeProbeTimeout = 30 * time.Second
var probeServer = func(ctx context.Context, rawURL string) (pairrelay.ServerInfo, error) {
	c, e := pairrelay.NewPublicClient(rawURL, nil)
	if e != nil {
		return pairrelay.ServerInfo{}, e
	}
	return c.FetchServerInfo(ctx)
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", "HOME=/root"}
	var output boundedBuffer
	output.limit = maxConfigBytes
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s operation failed", filepath.Base(name))
	}
	return output.Bytes(), nil
}

func protectedMetadata(path string, maximum int64) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrRoute
	}
	for item := path; ; item = filepath.Dir(item) {
		info, err := os.Lstat(item)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("configuration path is not protected")
		}
		if item == path && (!info.Mode().IsRegular() || st.Nlink != 1 || info.Size() > maximum) {
			return nil, ErrRoute
		}
		if item == "/" {
			break
		}
	}
	return os.Stat(path)
}
func protectedFile(path string) ([]byte, os.FileMode, error) {
	info, err := protectedMetadata(path, maxConfigBytes)
	if err != nil {
		return nil, 0, err
	}
	data, err := os.ReadFile(path)
	return data, info.Mode().Perm(), err
}

type savedConfig struct {
	Schema string `json:"schema"`
	URL    string `json:"url"`
	Engine string `json:"engine"`
	Image  string `json:"image"`
}

func stateRoot() (*securefs.Root, error) {
	root, err := securefs.OpenRoot(managedRoot)
	if errors.Is(err, os.ErrNotExist) {
		return securefs.CreateRoot(managedRoot)
	}
	return root, err
}

func loadConfig() (savedConfig, error) {
	r, err := securefs.OpenRoot(managedRoot)
	if err != nil {
		return savedConfig{}, err
	}
	defer r.Close()
	b, err := r.ReadFile("setup.json", 8192)
	if err != nil {
		return savedConfig{}, err
	}
	var c savedConfig
	if strictjson.Decode(b, &c) != nil || c.Schema != "owntransit.relay-setup.v1" {
		return c, errors.New("invalid relay setup state")
	}
	if _, err := PublicURL(c.URL); err != nil {
		return c, err
	}
	if !validEngine(c.Engine) || !validImage(c.Image) {
		return c, errors.New("invalid relay setup engine/image")
	}
	return c, nil
}

var enginePaths = []string{"/usr/bin/podman", "/usr/local/bin/podman", "/usr/bin/docker", "/usr/local/bin/docker"}

func validEngine(path string) bool {
	for _, p := range enginePaths {
		if path == p {
			return true
		}
	}
	return false
}
func validImage(id string) bool {
	if !strings.HasPrefix(id, "sha256:") || len(id) != 71 {
		return false
	}
	_, e := hex.DecodeString(id[7:])
	return e == nil && id == strings.ToLower(id)
}

func engine(ctx context.Context) (string, error) {
	for _, name := range enginePaths {
		if _, err := protectedMetadata(name, 256<<20); err == nil {
			if _, err := command(ctx, name, "info", "--format", "{{.Host.Arch}}"); err == nil {
				return name, nil
			}
			if filepath.Base(name) == "docker" {
				if _, err := command(ctx, name, "info", "--format", "{{.Architecture}}"); err == nil {
					return name, nil
				}
			}
		}
	}
	return "", errors.New("Docker or Podman must be installed and working on this VPS")
}

func ensureEngine(ctx context.Context, output io.Writer) (string, error) {
	if e, err := engine(ctx); err == nil {
		return e, nil
	}
	fmt.Fprintln(output, "Installing the container runtime needed by OwnTransit...")
	for _, p := range []struct {
		name string
		args []string
	}{
		{"/usr/bin/apt-get", []string{"-y", "--no-remove", "--no-install-recommends", "install", "podman"}},
		{"/usr/bin/dnf", []string{"-y", "install", "podman"}},
		{"/usr/bin/yum", []string{"-y", "install", "podman"}},
		{"/usr/bin/zypper", []string{"--non-interactive", "install", "podman"}},
	} {
		if _, err := os.Stat(p.name); err != nil {
			continue
		}
		if p.name == "/usr/bin/apt-get" {
			if _, err := command(ctx, p.name, "-qq", "update"); err != nil {
				return "", err
			}
		}
		if _, err := command(ctx, p.name, p.args...); err != nil {
			return "", err
		}
		return engine(ctx)
	}
	return "", errors.New("this Linux distribution needs Docker or Podman installed before setup")
}

type containerInfo struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Config struct {
		Entrypoint []string
		Cmd        []string
		Labels     map[string]string
	} `json:"Config"`
	State      struct{ Running bool } `json:"State"`
	HostConfig struct {
		PortBindings map[string][]struct{ HostIP, HostPort string }
	} `json:"HostConfig"`
	Mounts []struct{ Type, Source, Destination string } `json:"Mounts"`
}

func inspect(ctx context.Context, engine, name string) (containerInfo, error) {
	data, err := command(ctx, engine, "container", "inspect", name)
	if err != nil {
		return containerInfo{}, err
	}
	var list []containerInfo
	if json.Unmarshal(data, &list) != nil || len(list) != 1 {
		return containerInfo{}, errors.New("invalid container inspection")
	}
	return list[0], nil
}
func ownsPort(c containerInfo) bool {
	for _, bindings := range c.HostConfig.PortBindings {
		for _, p := range bindings {
			if p.HostPort == "9087" && (p.HostIP == "127.0.0.1" || p.HostIP == "0.0.0.0" || p.HostIP == "") {
				return true
			}
		}
	}
	return false
}
func ownRelay(c containerInfo) bool {
	name := strings.TrimPrefix(c.Name, "/")
	if name != managedContainer && name != "owntransit-relay-pair" && name != "owntransit-relay" && name != wireprofile.LegacyV1RelayArtifactName && c.Config.Labels["org.opencontainers.image.title"] != "OwnTransit Relay" {
		return false
	}
	if len(c.Config.Entrypoint) != 1 {
		return false
	}
	entry := filepath.Base(c.Config.Entrypoint[0])
	return entry == "owntransit-relay" || entry == wireprofile.LegacyV1RelayArtifactName
}

type previousRelay struct {
	Engine     string
	Container  containerInfo
	WasEnabled bool
	Unit       bool
}

func previous(ctx context.Context) (*previousRelay, error) {
	var found *previousRelay
	for _, e := range enginePaths {
		if _, err := protectedMetadata(e, 256<<20); err != nil {
			continue
		}
		out, err := command(ctx, e, "ps", "-q")
		if err != nil {
			continue
		}
		for _, id := range strings.Fields(string(out)) {
			if len(id) < 12 || len(id) > 64 {
				continue
			}
			c, err := inspect(ctx, e, id)
			if err != nil {
				return nil, err
			}
			if c.State.Running && ownsPort(c) {
				if found != nil && found.Container.ID == c.ID {
					continue
				}
				if !ownRelay(c) || found != nil {
					return nil, errors.New("port 9087 belongs to another service; setup will not replace it")
				}
				found = &previousRelay{Engine: e, Container: c}
			}
		}
	}
	if found == nil {
		listener, err := net.Listen("tcp4", "127.0.0.1:9087")
		if err != nil {
			return nil, errors.New("port 9087 is occupied by a service that is not an identified OwnTransit relay")
		}
		listener.Close()
	}
	return found, nil
}

func unit(image, engine string) []byte {
	return []byte(fmt.Sprintf(`[Unit]
Description=OwnTransit managed relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s run --rm --name=%s --pull=never --user=65532:65532 --read-only --cap-drop=all --security-opt=no-new-privileges --memory=256m --pids-limit=128 --cpus=1 --publish=127.0.0.1:9087:9087/tcp --volume=%s/data:/state:rw %s pair serve --state /state/relay
ExecStop=%s stop --time=10 %s
Restart=on-failure
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=20s
LimitCORE=0
StandardOutput=null
StandardError=journal
PrivateTmp=yes
ProtectSystem=full
ProtectHome=yes
Delegate=yes

[Install]
WantedBy=multi-user.target
`, engine, managedContainer, managedRoot, image, engine, managedContainer))
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".owntransit-setup-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Setup is entered only by the explicit local setup command. It selects one
// public URL, pins a locally installed image and verifies the real protocol
// through that URL. Other website locations are not rewrite targets.
func Setup(ctx context.Context, inputURL string, output io.Writer) (returnErr error) {
	if os.Geteuid() != 0 {
		return errors.New("run relay setup with sudo")
	}
	publicURL, err := PublicURL(inputURL)
	if err != nil {
		return err
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return errors.New("this managed setup requires systemd")
	}
	root, err := stateRoot()
	if err != nil {
		return err
	}
	defer root.Close()
	lock, err := root.TryLock("setup.lock")
	if err != nil {
		return err
	}
	defer lock.Close()
	old, err := previous(ctx)
	if err != nil {
		return err
	}
	var e string
	if old != nil {
		e = old.Engine
	} else {
		e, err = ensureEngine(ctx, output)
		if err != nil {
			return err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	archive := filepath.Join(filepath.Dir(executable), "owntransit-relay.oci.tar")
	if _, err := protectedMetadata(archive, 128<<20); err != nil {
		return errors.New("the authenticated relay image is missing beside the installed executable")
	}
	fmt.Fprintf(output, "Selected endpoint: %s\nContainer engine: %s\n", publicURL, filepath.Base(e))
	loadArchive := archive
	if filepath.Base(e) == "docker" {
		input, err := os.Open(archive)
		if err != nil {
			return err
		}
		converted, err := os.CreateTemp(managedRoot, "docker-load-*.tar")
		if err != nil {
			input.Close()
			return err
		}
		defer os.Remove(converted.Name())
		err = DockerArchive(input, converted, imageTag)
		input.Close()
		closed := converted.Close()
		if err != nil {
			return err
		}
		if closed != nil {
			return closed
		}
		loadArchive = converted.Name()
	}
	if _, err := command(ctx, e, "load", "--input", loadArchive); err != nil {
		return err
	}
	// Do not alter state or the listener if a pre-existing same-name container
	// is not an identified OwnTransit relay.
	if c, err := inspect(ctx, e, managedContainer); err == nil && !ownRelay(c) {
		return errors.New("the managed container name is already used by another application")
	}
	imageBytes, err := command(ctx, e, "image", "inspect", "--format", "{{.Id}}", imageTag)
	if err != nil {
		return err
	}
	image := strings.TrimSpace(string(imageBytes))
	if len(image) == 64 {
		image = "sha256:" + image
	}
	if !validImage(image) {
		return errors.New("image did not resolve to an immutable ID")
	}
	user, err := command(ctx, e, "image", "inspect", "--format", "{{.Config.User}}", image)
	if err != nil || strings.TrimSpace(string(user)) != "65532:65532" {
		return errors.New("relay image does not select the required unprivileged identity")
	}
	dataDir := filepath.Join(managedRoot, "data")
	if info, err := os.Lstat(dataDir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(dataDir, 0700); err != nil {
			return err
		}
		if err := os.Chown(dataDir, 65532, 65532); err != nil {
			return err
		}
	} else if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Uid != 65532 {
		return errors.New("unsafe relay data directory")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "relay")); errors.Is(err, os.ErrNotExist) {
		if old != nil && len(old.Container.Config.Cmd) > 0 && old.Container.Config.Cmd[0] == "pair" {
			if err := adoptState(old.Container, dataDir); err != nil {
				return err
			}
		} else if _, err := command(ctx, e, "run", "--rm", "--network=none", "--user=65532:65532", "--cap-drop=all", "--security-opt=no-new-privileges", "--read-only", "--volume="+dataDir+":/state:rw", image, "pair", "init", "--state", "/state/relay"); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	var route *routeChange
	changedRoute := false
	newStarted := false
	oldStopped := false
	alreadyManaged := old != nil && strings.TrimPrefix(old.Container.Name, "/") == managedContainer
	defer func() {
		if returnErr != nil {
			if newStarted {
				_, e := command(context.Background(), "/usr/bin/systemctl", "disable", "--now", managedUnit)
				returnErr = errors.Join(returnErr, e)
			}
			if changedRoute {
				returnErr = errors.Join(returnErr, route.rollback(context.Background()))
			}
			if oldStopped {
				if old.Unit {
					if old.WasEnabled {
						_, _ = command(context.Background(), "/usr/bin/systemctl", "enable", "owntransit-relay.service")
					}
					_, e := command(context.Background(), "/usr/bin/systemctl", "start", "owntransit-relay.service")
					returnErr = errors.Join(returnErr, e)
				} else {
					_, e := command(context.Background(), old.Engine, "start", old.Container.ID)
					returnErr = errors.Join(returnErr, e)
				}
			}
		}
	}()
	contents := unit(image, e)
	if existing, _, err := protectedFile(unitPath); err == nil && !bytes.Equal(existing, contents) {
		return errors.New("an existing managed service differs; explicit upgrade is required")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := writeAtomic(unitPath, contents, 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if old != nil && strings.TrimPrefix(old.Container.Name, "/") != managedContainer {
		if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", "owntransit-relay.service"); err == nil {
			start, err := command(ctx, "/usr/bin/systemctl", "show", "owntransit-relay.service", "--property=ExecStart", "--value")
			if err != nil || !bytes.Contains(start, []byte(strings.TrimPrefix(old.Container.Name, "/"))) {
				return errors.New("the old relay has an unexpected service manager; no unrelated service was stopped")
			}
			old.Unit = true
			_, enabledErr := command(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", "owntransit-relay.service")
			old.WasEnabled = enabledErr == nil
			oldStopped = true
			if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", "owntransit-relay.service"); err != nil {
				return err
			}
		} else {
			oldStopped = true
			if _, err := command(ctx, old.Engine, "stop", "--time=10", old.Container.ID); err != nil {
				return err
			}
		}
	}
	newStarted = !alreadyManaged
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", "--now", managedUnit); err != nil {
		return err
	}
	var localBytes []byte
	for attempt := 0; attempt < 20; attempt++ {
		localBytes, err = command(ctx, e, "exec", managedContainer, "/owntransit-relay", "pair", "info", "--state", "/state/relay")
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	if err != nil {
		return err
	}
	var local pairrelay.ServerInfo
	if strictjson.Decode(localBytes, &local) != nil {
		return errors.New("local relay identity could not be verified")
	}
	verify := func(timeout time.Duration) bool {
		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		for probeCtx.Err() == nil {
			remote, err := probeServer(probeCtx, publicURL)
			if err == nil && remote.LeafSPKISHA256 == local.LeafSPKISHA256 && bytes.Equal(remote.CAPEM, local.CAPEM) {
				return true
			}
			select {
			case <-probeCtx.Done():
			case <-time.After(time.Second):
			}
		}
		return false
	}
	verified := verify(firstProbeTimeout)
	if !verified {
		u, _ := url.Parse(publicURL)
		route, err = prepareRoute(ctx, u.Hostname())
		if err != nil {
			return err
		}
		if route != nil {
			if err := route.apply(ctx, root); err != nil {
				return err
			}
			changedRoute = !route.edit.Reused
			verified = verify(routeProbeTimeout)
		}
	}
	if !verified {
		return errors.New("the selected website did not reach this relay; setup is rolling back its changes")
	}
	configBytes, _ := json.Marshal(savedConfig{"owntransit.relay-setup.v1", publicURL, e, image})
	if err := root.ReplaceFile("setup.json", configBytes, 0600); err != nil {
		return err
	}
	fmt.Fprintf(output, "Relay is ready at %s and enabled for reboot.\nNEXT — on your private SSH server:\n  sudo owntransit-connector-preview pair setup\nUse the relay URL above. Receiver setup prints the exact command to run here next:\n  sudo owntransit-relay-preview register RECEIVER_ID\n", publicURL)
	return nil
}

func RegisterManaged(ctx context.Context, id string) (string, error) {
	if os.Geteuid() != 0 {
		return "", errors.New("run relay registration with sudo")
	}
	c, err := loadConfig()
	if err != nil {
		return "", err
	}
	result, err := command(ctx, c.Engine, "exec", managedContainer, "/owntransit-relay", "pair", "register", "--state", "/state/relay", id)
	if err != nil {
		return "", errors.New("receiver is not advertising yet; start its setup and try again")
	}
	return strings.TrimSpace(string(result)), nil
}

type routeChange struct {
	path, program string
	edit          RouteEdit
	mode          os.FileMode
	kind          string
}

func prepareRoute(ctx context.Context, hostname string) (*routeChange, error) {
	nginx := "/usr/sbin/nginx"
	if _, err := os.Stat(nginx); err != nil {
		return prepareOtherRoute(ctx, hostname)
	}
	dump, err := command(ctx, nginx, "-T")
	if err != nil {
		return nil, errors.New("existing nginx configuration does not pass validation")
	}
	var chosen *routeChange
	for _, line := range strings.Split(string(dump), "\n") {
		if !strings.HasPrefix(line, "# configuration file ") || !strings.HasSuffix(line, ":") {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(line, "# configuration file "), ":")
		path, err := filepath.EvalSymlinks(name)
		if err != nil {
			continue
		}
		data, mode, err := protectedFile(path)
		if err != nil {
			continue
		}
		edit, err := NginxRoute(data, hostname)
		if err != nil {
			if errors.Is(err, ErrNoSite) {
				continue
			}
			return nil, err
		}
		if chosen != nil && chosen.path != path {
			return nil, ErrRoute
		}
		chosen = &routeChange{path: path, program: nginx, edit: edit, mode: mode, kind: "nginx"}
	}
	if chosen == nil {
		return prepareOtherRoute(ctx, hostname)
	}
	return chosen, nil
}
func (r *routeChange) apply(ctx context.Context, root *securefs.Root) error {
	if r.edit.Reused {
		return nil
	}
	current, _, err := protectedFile(r.path)
	if err != nil || !bytes.Equal(current, r.edit.Before) {
		return errors.New("site configuration changed during setup")
	}
	hash := sha256.Sum256([]byte(r.path))
	backup := "site-" + hex.EncodeToString(hash[:8]) + ".backup"
	if err := root.EnsureFile(backup, r.edit.Before, 0600); err != nil {
		return err
	}
	if err := writeAtomic(r.path, r.edit.After, r.mode); err != nil {
		return err
	}
	if err := r.validate(ctx); err != nil {
		return errors.Join(errors.New("route validation failed"), r.rollback(context.Background()))
	}
	if err := r.reload(ctx); err != nil {
		return errors.Join(errors.New("route reload failed"), r.rollback(context.Background()))
	}
	return nil
}
func (r *routeChange) rollback(ctx context.Context) error {
	current, _, err := protectedFile(r.path)
	if err != nil || !bytes.Equal(current, r.edit.After) {
		return errors.New("site changed outside setup; refusing to overwrite it during rollback")
	}
	if err := writeAtomic(r.path, r.edit.Before, r.mode); err != nil {
		return err
	}
	if err := r.validate(ctx); err != nil {
		return err
	}
	return r.reload(ctx)
}
