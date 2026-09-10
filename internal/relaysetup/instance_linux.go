//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const firstInstancePort, lastInstancePort = 9088, 9151
const maxInstances = lastInstancePort - firstInstancePort + 2

// A spec is constructed only from a validated selector and protected binding.
// No operation changes package-global paths or names to select an instance.
type instanceSpec struct {
	name, root, container, unitName, unitPath, url string
	port                                           int
	legacyDataLabel                                string
}

type instanceBinding struct {
	Schema          string `json:"schema"`
	Name            string `json:"name"`
	URL             string `json:"url"`
	Port            int    `json:"port"`
	LegacyDataLabel string `json:"legacy_data_label,omitempty"`
}

func defaultInstance() instanceSpec {
	return instanceSpec{name: "default", root: managedRoot, container: managedContainer, unitName: managedUnit, unitPath: unitPath, port: 9087}
}

func instanceFromBinding(b instanceBinding) (instanceSpec, error) {
	name, err := normalizedInstanceName(b.Name)
	u, ue := PublicURL(b.URL)
	legacy := b.Schema == "owntransit.relay-instance.v2" && name != "default" && validLegacyLabel(b.LegacyDataLabel)
	if err != nil || name != b.Name || ue != nil || u != b.URL || (!legacy && (b.Schema != "owntransit.relay-instance.v1" || b.LegacyDataLabel != "")) {
		return instanceSpec{}, errors.New("invalid relay instance binding")
	}
	s := defaultInstance()
	if name != "default" {
		if b.Port < firstInstancePort || b.Port > lastInstancePort {
			return instanceSpec{}, errors.New("invalid relay instance port")
		}
		s.name = name
		s.root = managedRoot + "/instances/" + name
		s.container = managedContainer + "-" + name
		s.unitName = s.container + ".service"
		s.unitPath = "/etc/systemd/system/" + s.unitName
	} else if b.Port != 9087 {
		return instanceSpec{}, errors.New("invalid default relay port")
	}
	s.url, s.port = b.URL, b.Port
	s.legacyDataLabel = b.LegacyDataLabel
	return s, nil
}

func (s instanceSpec) named() bool { return s.name != "default" }
func (s instanceSpec) dataRoot() string {
	if s.legacyDataLabel != "" {
		return legacyRoot(s.legacyDataLabel) + "/data"
	}
	return s.root + "/data"
}
func (s instanceSpec) openRoot() (*securefs.Root, error) {
	if err := protectedDirectoryChain(s.root); err != nil {
		return nil, err
	}
	paths := []string{managedRoot}
	if s.named() {
		paths = append(paths, managedRoot+"/instances", s.root)
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != 0 || st.Gid != 0 {
			return nil, errors.New("unsafe relay instance root")
		}
	}
	return securefs.OpenRoot(s.root)
}

func protectedDirectoryChain(path string) error {
	for item := path; ; item = filepath.Dir(item) {
		info, err := os.Lstat(item)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || st.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("relay configuration ancestor is not protected")
		}
		if item == "/" {
			return nil
		}
	}
}

func (s instanceSpec) readRecord(root *securefs.Root, name string, limit int64) ([]byte, error) {
	info, err := protectedMetadata(s.root+"/"+name, limit)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm() != 0600 {
		return nil, errors.New("relay record must be private")
	}
	return root.ReadFile(name, limit)
}

func (s instanceSpec) validateData() error {
	if !s.named() {
		return nil
	}
	if s.legacyDataLabel != "" {
		if err := protectedDirectoryChain(legacyRoot(s.legacyDataLabel)); err != nil {
			return err
		}
		info, err := os.Lstat(legacyRoot(s.legacyDataLabel))
		if err != nil || info.Mode().Perm() != 0700 || info.Sys().(*syscall.Stat_t).Gid != 0 {
			return errors.New("unsafe retained relay state root")
		}
	}
	for _, path := range []string{s.dataRoot(), s.dataRoot() + "/relay"} {
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != 65532 || st.Gid != 65532 {
			return errors.New("unsafe relay identity directory")
		}
	}
	return nil
}
func (s instanceSpec) config(url, engine, image string) savedConfig {
	c := savedConfig{Schema: "owntransit.relay-setup.v1", URL: url, Engine: engine, Image: image}
	if s.named() {
		c.Schema, c.Instance, c.Port = "owntransit.relay-setup.v2", s.name, s.port
	}
	return c
}

func (s instanceSpec) validSaved(c savedConfig) bool {
	if !validSaved(c) || (s.url != "" && c.URL != s.url) {
		return false
	}
	if s.named() {
		return c.Schema == "owntransit.relay-setup.v2" && c.Instance == s.name && c.Port == s.port
	}
	return c.Schema == "owntransit.relay-setup.v1" && c.Instance == "" && c.Port == 0
}

func (s instanceSpec) ownsContainer(c containerInfo, image string) bool {
	if s.legacyDataLabel != "" && !confined(c) {
		return false
	}
	if strings.TrimPrefix(c.Name, "/") != s.container || c.Image != image {
		return false
	}
	if !s.named() {
		return ownRelay(c)
	} // Retain recognition of the authenticated legacy default profile.
	if len(c.Config.Entrypoint) != 1 || c.Config.Entrypoint[0] != "/owntransit-relay" || (!equalStrings(c.Config.Cmd, []string{"pair", "serve", "--state", "/state/relay"}) && !equalStrings(c.Config.Cmd, []string{"serve", "--state", "/state/relay"})) {
		return false
	}
	if len(c.Mounts) != 1 || c.Mounts[0].Type != "bind" || c.Mounts[0].Source != s.dataRoot() || c.Mounts[0].Destination != "/state" {
		return false
	}
	if len(c.HostConfig.PortBindings) != 1 {
		return false
	}
	p := c.HostConfig.PortBindings["9087/tcp"]
	return len(p) == 1 && p[0].HostIP == "127.0.0.1" && p[0].HostPort == strconv.Itoa(s.port)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// managerRoot serializes every manager operation across all instances. Hooks
// intentionally do not take this lock, because systemctl waits for the hooks.
func managerRoot(create bool) (*securefs.Root, io.Closer, error) {
	if os.Geteuid() != 0 {
		return nil, nil, errors.New("relay administration requires root")
	}
	if err := protectedDirectoryChain(filepath.Dir(managedRoot)); err != nil {
		return nil, nil, err
	}
	root, err := defaultInstance().openRoot()
	if errors.Is(err, os.ErrNotExist) && create {
		root, err = securefs.CreateRoot(managedRoot)
	}
	if err != nil {
		return nil, nil, err
	}
	var lock io.Closer
	if create {
		lock, err = root.TryLock("setup.lock")
	} else {
		// Listing must never create state or a lock file.
		var fd int
		fd, err = unix.Open(managedRoot+"/setup.lock", unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err == nil {
			var st unix.Stat_t
			err = unix.Fstat(fd, &st)
			if err == nil && (st.Uid != 0 || st.Mode != unix.S_IFREG|0600 || st.Nlink != 1 || st.Size != 0) {
				err = errors.New("unsafe setup lock")
			}
			if err == nil {
				err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
			}
			if err != nil {
				unix.Close(fd)
			} else {
				lock = os.NewFile(uintptr(fd), "setup.lock")
			}
		}
	}
	if err != nil {
		root.Close()
		if !create && errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("existing relay state has no setup lock")
		}
		return nil, nil, err
	}
	return root, lock, nil
}

func readBinding(root *securefs.Root, name string) (instanceSpec, error) {
	if ValidateInstanceName(name) != nil || name == "" {
		return instanceSpec{}, errors.New("invalid relay binding selector")
	}
	s := defaultInstance()
	if name != "default" {
		s.root = managedRoot + "/instances/" + name
	}
	b, err := s.readRecord(root, "instance.json", 8192)
	if err != nil {
		return instanceSpec{}, err
	}
	var binding instanceBinding
	if strictjson.Decode(b, &binding) != nil || binding.Name != name {
		return instanceSpec{}, errors.New("cross-instance or invalid relay binding")
	}
	return instanceFromBinding(binding)
}

func boundedNames(path string, maximum int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(maximum + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > maximum {
		return nil, errors.New("relay directory exceeds its bound")
	}
	sort.Strings(names)
	return names, nil
}

// scanInstances includes stopped, removed and incomplete reservations. A URL
// or port is never released by a failed setup or ordinary uninstall.
func scanInstances(root *securefs.Root) ([]instanceSpec, error) {
	if err := noMigration(root); err != nil {
		return nil, err
	}
	var specs []instanceSpec
	d, err := readBinding(root, "default")
	if errors.Is(err, os.ErrNotExist) {
		d = defaultInstance()
		c, e := d.loadConfig()
		if e == nil {
			d.url = c.URL
			specs = append(specs, d)
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
	} else if err != nil {
		return nil, err
	} else {
		specs = append(specs, d)
	}
	instances, err := root.OpenDir("instances")
	if errors.Is(err, os.ErrNotExist) {
		return specs, nil
	}
	if err != nil {
		return nil, err
	}
	defer instances.Close()
	names, err := boundedNames(managedRoot+"/instances", maxInstances-1)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		if ValidateInstanceName(name) != nil || name == "default" {
			return nil, errors.New("invalid relay instance directory")
		}
		r, err := instances.OpenDir(name)
		if err != nil {
			return nil, err
		}
		s, err := readBinding(r, name)
		r.Close()
		if errors.Is(err, os.ErrNotExist) {
			// A crash may leave the private directory before its reservation.
			names, e := boundedNames(managedRoot+"/instances/"+name, 1)
			if e != nil || len(names) != 0 {
				return nil, errors.New("unbound relay instance state")
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	seenURL, seenPort := map[string]bool{}, map[int]bool{}
	seenData := map[string]bool{}
	for i, s := range specs {
		if seenURL[s.url] || seenPort[s.port] || seenData[s.dataRoot()] {
			return nil, errors.New("conflicting relay URL or port reservations")
		}
		for _, other := range specs[:i] {
			if overlapsPath(s.dataRoot(), other.dataRoot()) {
				return nil, errors.New("conflicting relay state directories")
			}
		}
		seenURL[s.url], seenPort[s.port] = true, true
		seenData[s.dataRoot()] = true
		if _, err := s.loadConfig(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return specs, nil
}

func reserveInstance(root *securefs.Root, name, url string) (instanceSpec, error) {
	specs, err := scanInstances(root)
	if err != nil {
		return instanceSpec{}, err
	}
	ports := map[int]bool{}
	for _, s := range specs {
		if s.name == name {
			if s.url != url {
				return instanceSpec{}, errors.New("use this relay instance's existing public URL")
			}
			return s, nil
		}
		if s.url == url {
			return instanceSpec{}, errors.New("public URL is reserved by another relay instance")
		}
		ports[s.port] = true
	}
	port := 9087
	if name != "default" {
		port = 0
		for p := firstInstancePort; p <= lastInstancePort; p++ {
			if ports[p] {
				continue
			}
			listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(p))
			if err != nil {
				continue
			}
			listener.Close()
			port = p
			break
		}
		if port == 0 {
			return instanceSpec{}, errors.New("no free managed relay instance port")
		}
	}
	binding := instanceBinding{Schema: "owntransit.relay-instance.v1", Name: name, URL: url, Port: port}
	s, err := instanceFromBinding(binding)
	if err != nil {
		return s, err
	}
	r := root
	if s.named() {
		instances, err := root.OpenDir("instances")
		if errors.Is(err, os.ErrNotExist) {
			if err := root.MkdirExclusive("instances", 0700); err != nil {
				return s, err
			}
			instances, err = root.OpenDir("instances")
		}
		if err != nil {
			return s, err
		}
		defer instances.Close()
		names, err := boundedNames(managedRoot+"/instances", maxInstances-1)
		if err != nil {
			return s, err
		}
		present := false
		for _, existing := range names {
			if existing == name {
				present = true
			}
		}
		if len(names) == maxInstances-1 && !present {
			return s, errors.New("relay instance directory limit reached")
		}
		if err := instances.MkdirExclusive(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return s, err
		}
		r, err = instances.OpenDir(name)
		if err != nil {
			return s, err
		}
		defer r.Close()
	}
	b, _ := json.Marshal(binding)
	return s, r.CreateExclusive("instance.json", b, 0600)
}

func selectedInstance(root *securefs.Root, name string) (instanceSpec, error) {
	specs, err := scanInstances(root)
	if err != nil {
		return instanceSpec{}, err
	}
	for _, s := range specs {
		if s.name == name {
			return s, nil
		}
	}
	if name == "default" {
		return defaultInstance(), nil
	}
	return instanceSpec{}, os.ErrNotExist
}

func Setup(ctx context.Context, url string, out io.Writer) error {
	return SetupInstance(ctx, "default", url, out)
}
func SetupInstance(ctx context.Context, name, rawURL string, out io.Writer) error {
	name, err := normalizedInstanceName(name)
	if err != nil {
		return err
	}
	url, err := PublicURL(rawURL)
	if err != nil {
		return err
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	if err := noMigration(root); err != nil {
		return err
	}
	s, err := reserveInstance(root, name, url)
	if err != nil {
		return err
	}
	return s.setup(ctx, url, out)
}

func RegisterManaged(ctx context.Context, id string) (string, error) {
	return RegisterInstance(ctx, "default", id)
}
func RegisterInstance(ctx context.Context, name, id string) (string, error) {
	name, err := normalizedInstanceName(name)
	if err != nil {
		return "", err
	}
	if err := validatePublicReceiverID(id); err != nil {
		return "", err
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return "", err
	}
	defer root.Close()
	defer lock.Close()
	s, err := selectedInstance(root, name)
	if err != nil {
		return "", err
	}
	return s.register(ctx, id)
}

// RegisterURL selects exactly one retained local relay by its explicit public
// URL. It performs no network discovery and never retries another instance.
func RegisterURL(ctx context.Context, rawURL, id string) (string, error) {
	url, err := PublicURL(rawURL)
	if err != nil {
		return "", err
	}
	if err := validatePublicReceiverID(id); err != nil {
		return "", err
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return "", err
	}
	defer root.Close()
	defer lock.Close()
	specs, err := scanInstances(root)
	if err != nil {
		return "", err
	}
	var selected instanceSpec
	found := false
	for _, s := range specs {
		if s.url != url {
			continue
		}
		if found {
			return "", errors.New("public URL matches conflicting relay instances")
		}
		selected, found = s, true
	}
	if !found {
		return "", errors.New("no saved relay instance matches that public URL")
	}
	return selected.register(ctx, id)
}

func validatePublicReceiverID(id string) error {
	// Receiver IDs are fixed public values, never an option or pairing secret.
	parsed, err := protocol.ParseID(id)
	if err != nil || parsed == (protocol.ID{}) {
		return errors.New("invalid public receiver ID")
	}
	return nil
}

func (s instanceSpec) register(ctx context.Context, id string) (string, error) {
	c, err := s.loadConfig()
	if err != nil {
		return "", err
	}
	if err := s.validateData(); err != nil {
		return "", err
	}
	r, err := s.openRoot()
	if err != nil {
		return "", err
	}
	defer r.Close()
	if err := noPendingOperation(r); err != nil {
		return "", err
	}
	if _, err := s.managedIdentity(ctx, c.Engine, c.Image); err != nil {
		return "", err
	}
	result, err := command(ctx, c.Engine, "exec", s.container, "/owntransit-relay", "approve-admission", "--state", "/state/relay", id)
	if err != nil {
		return "", errors.New("receiver is not advertising yet; start its setup and try again")
	}
	return strings.TrimSpace(string(result)), nil
}

func ListInstances(ctx context.Context, out io.Writer) error {
	root, lock, err := managerRoot(false)
	if errors.Is(err, os.ErrNotExist) {
		_, e := fmt.Fprintln(out, "No managed relay instances.")
		return e
	}
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	specs, err := scanInstances(root)
	if err != nil {
		return err
	}
	var result bytes.Buffer
	for _, s := range specs {
		if err := ctx.Err(); err != nil {
			return err
		}
		status := "reserved"
		if _, err := s.loadConfig(); err == nil {
			status = "stopped"
			if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", s.unitName); err == nil {
				status = "active"
			}
		}
		fmt.Fprintf(&result, "%s\t%s\t127.0.0.1:%d\t%s\n", s.name, s.url, s.port, status)
	}
	if len(specs) == 0 {
		result.WriteString("No managed relay instances.\n")
	}
	_, err = out.Write(result.Bytes())
	return err
}

// Preserve internal legacy entry points used by the default-profile fixtures.
func loadConfig() (savedConfig, error)          { return defaultInstance().loadConfig() }
func unit(image, engine string) []byte          { return defaultInstance().unit(image, engine) }
func legacyUnit(image, engine string) []byte    { return defaultInstance().legacyUnit(image, engine) }
func knownUnit(data []byte, c savedConfig) bool { return defaultInstance().knownUnit(data, c) }

func noPendingOperation(root *securefs.Root) error {
	for _, name := range []string{"upgrade.json", "pending-setup.json", "migration.json"} {
		if _, err := root.ReadFile(name, 8192); !errors.Is(err, os.ErrNotExist) {
			return errors.New("finish or recover this relay setup before continuing")
		}
	}
	return nil
}

func (s instanceSpec) preflightFresh(ctx context.Context, engine, image string) error {
	if !s.named() {
		return nil
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("relay service overrides present; setup refused")
	}
	ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+s.container)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(ids)) {
		c, err := inspect(ctx, engine, id)
		if err != nil {
			return err
		}
		if strings.TrimPrefix(c.Name, "/") == s.container {
			return errors.New("named container exists without a recoverable setup record")
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(s.port))
	if err != nil {
		return errors.New("this relay instance's reserved port is occupied")
	}
	return listener.Close()
}

func (s instanceSpec) recoverFresh(ctx context.Context, root *securefs.Root) error {
	b, err := s.readRecord(root, "pending-setup.json", 8192)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var c savedConfig
	if !s.named() || strictjson.Decode(b, &c) != nil || !s.validSaved(c) {
		return errors.New("invalid pending relay setup")
	}
	if err := s.validateData(); err != nil {
		return err
	}
	if saved, err := s.loadConfig(); err == nil {
		if saved != c {
			return errors.New("pending setup conflicts with selected relay")
		}
		return root.UnlinkFile("pending-setup.json")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	u, _, err := protectedFile(s.unitPath)
	if errors.Is(err, os.ErrNotExist) {
		if err := s.cleanupStopped(ctx, c.Engine, []string{c.Image}); err != nil {
			return err
		}
		return nil
	}
	if err != nil || !s.knownUnit(u, c) {
		return errors.New("pending relay unit changed; recovery refused")
	}
	drops, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(drops)) != 0 {
		return errors.New("relay service overrides present; recovery refused")
	}
	if err := s.prevalidateContainer(ctx, c, true); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", s.unitName); err != nil {
		return err
	}
	if err := s.cleanupStopped(ctx, c.Engine, []string{c.Image}); err != nil {
		return err
	}
	// Remove only this exact incomplete unit before changing the pending image.
	// A crash may then leave an absent unit with either journal generation;
	// both are recoverable without guessing which template was selected.
	current, _, err := protectedFile(s.unitPath)
	if err != nil || !bytes.Equal(current, u) {
		return errors.New("pending relay unit changed during recovery")
	}
	if err := os.Remove(s.unitPath); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(s.unitPath))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (s instanceSpec) prevalidateContainer(ctx context.Context, c savedConfig, allowRunning bool) error {
	ids, err := command(ctx, c.Engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+s.container)
	if err != nil {
		return err
	}
	for _, id := range strings.Fields(string(ids)) {
		if len(id) != 64 || !validImage("sha256:"+id) {
			return errors.New("invalid managed container ID")
		}
		container, err := inspect(ctx, c.Engine, id)
		if err != nil {
			return err
		}
		if strings.TrimPrefix(container.Name, "/") != s.container {
			continue
		}
		if container.ID != id || !s.ownsContainer(container, c.Image) {
			return errors.New("relay container ownership mismatch")
		}
		if !allowRunning && container.State.Running {
			return errors.New("running relay has no matching managed unit")
		}
	}
	return nil
}
