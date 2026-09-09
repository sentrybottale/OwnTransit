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
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/sentrybottale/owntransit/internal/pairrelay"
	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"golang.org/x/sys/unix"
)

const migrationFile = "migration.json"
const migrationLimit = 64 << 10

func validLegacyLabel(label string) bool {
	return label != "" && ValidateInstanceName(label) == nil && label != "default" && label != "setup" && label != "pair" && label != "managed" && !strings.HasPrefix(label, "managed-") && !strings.HasPrefix(label, "setup-")
}
func legacyRoot(label string) string { return "/var/lib/owntransit-relay-" + label }
func legacySpec(label, publicURL string, port int) instanceSpec {
	name := "owntransit-relay-" + label
	return instanceSpec{name: label, root: legacyRoot(label), container: name, unitName: name + ".service", unitPath: "/etc/systemd/system/" + name + ".service", url: publicURL, port: port, legacyDataLabel: label}
}

// No other manager operation may allocate a port or change ownership while a
// migration holds its old and new reservations. Cleanup hooks still work.
func noMigration(root *securefs.Root) error {
	if _, err := root.ReadFile(migrationFile, migrationLimit); !errors.Is(err, os.ErrNotExist) {
		return errors.New("an interrupted relay migration needs the same setup command before other relay management")
	}
	return nil
}

type migrationSource struct {
	Label, Engine, Image, ContainerID string
	Port                              int
	Unit                              []byte
	Identity                          pairrelay.ServerInfo
	Digests                           map[string]string
}
type migrationIntent struct {
	Schema, Phase                 string
	Source                        migrationSource
	PreviousBinding               instanceBinding
	NextBinding                   instanceBinding
	PreviousPending, PreviousUnit []byte
	Next                          savedConfig
}

func planDigest(value any) string {
	b, _ := json.Marshal(value)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func readMigration(root *securefs.Root) (migrationIntent, error) {
	b, err := defaultInstance().readRecord(root, migrationFile, migrationLimit)
	if err != nil {
		return migrationIntent{}, err
	}
	var j migrationIntent
	if strictjson.Decode(b, &j) != nil || validateMigration(j) != nil {
		return j, errors.New("invalid relay migration journal")
	}
	return j, nil
}
func validateMigration(j migrationIntent) error {
	p, pe := instanceFromBinding(j.PreviousBinding)
	n, ne := instanceFromBinding(j.NextBinding)
	s := j.Source
	if pe != nil || ne != nil || !p.named() || p.name != n.name || p.url != n.url || p.legacyDataLabel != "" || n.legacyDataLabel != s.Label || n.port != s.Port || !validLegacyLabel(s.Label) || !validEngine(s.Engine) || !validImage(s.Image) || !validImage("sha256:"+s.ContainerID) || !n.validSaved(j.Next) || j.Next.Engine != s.Engine || j.Schema != "owntransit.relay-migration.v1" || (j.Phase != "prepared" && j.Phase != "committed") {
		return errors.New("migration journal ownership mismatch")
	}
	if !knownManualUnit(s.Unit, legacySpec(s.Label, n.url, s.Port), s.Engine, s.Image) || len(s.Digests) != 5 {
		return errors.New("invalid retained legacy ownership")
	}
	for _, name := range relayIdentityFiles {
		if !validImage("sha256:" + s.Digests[name]) {
			return errors.New("invalid retained identity digest")
		}
	}
	if len(j.PreviousPending) != 0 {
		var c savedConfig
		if strictjson.Decode(j.PreviousPending, &c) != nil || !p.validSaved(c) || (len(j.PreviousUnit) != 0 && !p.knownUnit(j.PreviousUnit, c)) {
			return errors.New("invalid incomplete reservation backup")
		}
	} else if len(j.PreviousUnit) != 0 {
		return errors.New("unowned incomplete unit")
	}
	return nil
}

func PrepareSetup(ctx context.Context, name, rawURL string) (SetupPlan, error) {
	if err := ValidateInstanceName(name); err != nil {
		return SetupPlan{}, err
	}
	u, err := PublicURL(rawURL)
	if err != nil {
		return SetupPlan{}, err
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return SetupPlan{}, err
	}
	defer root.Close()
	defer lock.Close()
	p, _, err := prepareSetupLocked(ctx, root, name, u)
	return p, err
}
func prepareSetupLocked(ctx context.Context, root *securefs.Root, name, u string) (SetupPlan, *migrationSource, error) {
	explicit := name != ""
	if j, err := readMigration(root); err == nil {
		if j.Next.URL != u || (name != "" && name != j.Next.Instance) {
			return SetupPlan{}, nil, errors.New("finish the existing relay migration using its original URL and instance")
		}
		p := migrationPlan(j.Next.Instance, u, j.Source)
		p.evidence = planDigest(j)
		return p, &j.Source, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return SetupPlan{}, nil, err
	}
	specs, err := scanInstances(root)
	if err != nil {
		return SetupPlan{}, nil, err
	}
	var selected *instanceSpec
	for i := range specs {
		s := &specs[i]
		if s.url == u {
			if name != "" && name != s.name {
				return SetupPlan{}, nil, errors.New("public URL is reserved by another relay instance")
			}
			selected, name = s, s.name
		}
	}
	if selected == nil {
		if name == "" {
			name = "default"
			if len(specs) != 0 {
				name = "relay-" + planDigest(u)[:12]
			}
		}
		for _, s := range specs {
			if s.name == name {
				return SetupPlan{}, nil, errors.New("use this relay instance's existing public URL")
			}
		}
	}
	p := SetupPlan{Instance: name, URL: u, Kind: "new", Port: 9087}
	if name != "default" {
		p.Port = 0
	}
	if selected != nil {
		p.Port, p.Kind = selected.port, "reserved"
		if _, err := selected.loadConfig(); err == nil {
			p.Kind = "managed"
		} else if !errors.Is(err, os.ErrNotExist) {
			return p, nil, err
		}
	}
	var source *migrationSource
	var reservation string
	if p.Kind != "managed" {
		source, err = discoverManual(ctx, u, specs)
		if err != nil {
			return p, nil, err
		}
		if source != nil {
			if name == "default" {
				if selected != nil || explicit {
					return p, nil, errors.New("a legacy named relay cannot replace default")
				}
				name = "relay-" + planDigest(u)[:12]
			}
			p = migrationPlan(name, u, *source)
			if selected != nil {
				pending, unit, err := incompleteReservation(ctx, *selected)
				if err != nil {
					return p, nil, err
				}
				reservation = planDigest(struct{ Pending, Unit []byte }{pending, unit})
			}
		}
	}
	if source == nil && p.Kind == "reserved" {
		parsed, _ := url.Parse(u)
		route, routeErr := prepareRouteForPort(ctx, parsed.Hostname(), p.Port)
		if routeErr != nil {
			return p, nil, routeErr
		}
		if route == nil {
			return p, nil, ErrRoute
		}
	}
	// The token binds the read-only source and the protected local inventory.
	p.evidence = planDigest(struct {
		Plan        SetupPlan
		Specs       []instanceBinding
		Source      *migrationSource
		Reservation string
	}{p, bindings(specs), source, reservation})
	return p, source, nil
}
func bindings(specs []instanceSpec) []instanceBinding {
	var out []instanceBinding
	for _, s := range specs {
		out = append(out, s.binding())
	}
	return out
}
func (s instanceSpec) binding() instanceBinding {
	b := instanceBinding{Schema: "owntransit.relay-instance.v1", Name: s.name, URL: s.url, Port: s.port}
	if s.legacyDataLabel != "" {
		b.Schema, b.LegacyDataLabel = "owntransit.relay-instance.v2", s.legacyDataLabel
	}
	return b
}
func migrationPlan(name, u string, source migrationSource) SetupPlan {
	s := legacySpec(source.Label, u, source.Port)
	return SetupPlan{Instance: name, URL: u, Kind: "migration", Port: source.Port, LegacyUnit: s.unitName, LegacyContainer: s.container, LegacyState: s.dataRoot()}
}
func ApplySetup(ctx context.Context, plan SetupPlan, migrationConfirmed bool, out io.Writer) error {
	if plan.evidence == "" || ValidateInstanceName(plan.Instance) != nil || plan.Instance == "" {
		return errors.New("prepare relay setup before applying it")
	}
	if u, err := PublicURL(plan.URL); err != nil || u != plan.URL {
		return errors.New("invalid setup URL")
	}
	root, lock, err := managerRoot(true)
	if err != nil {
		return err
	}
	defer root.Close()
	defer lock.Close()
	fresh, source, err := prepareSetupLocked(ctx, root, plan.Instance, plan.URL)
	if err != nil {
		return err
	}
	if fresh != plan {
		return errors.New("relay setup changed since preparation; prepare the same setup again")
	}
	if plan.Kind == "migration" && !migrationConfirmed {
		return errors.New("confirm the displayed legacy relay migration before applying it")
	}
	if j, err := readMigration(root); err == nil {
		if j.Phase == "committed" {
			return finishMigration(ctx, root, j)
		}
		if err := restoreMigration(ctx, root, j); err != nil {
			return err
		}
		// One bounded recovery/reprepare cycle continues the already confirmed
		// operation. A recreated auto-remove container may have a new ID, but
		// every identity byte, image, unit and displayed resource must match.
		reprepared, recovered, e := prepareSetupLocked(ctx, root, plan.Instance, plan.URL)
		if e != nil {
			return e
		}
		if recovered == nil {
			return errors.New("previous relay recovered but its migration source is no longer recognized")
		}
		before, after := j.Source, *recovered
		before.ContainerID, after.ContainerID = "", ""
		expected := migrationPlan(plan.Instance, plan.URL, j.Source)
		expected.evidence = reprepared.evidence
		if reprepared != expected || planDigest(before) != planDigest(after) {
			return errors.New("previous relay recovered but migration ownership changed; prepare the same setup again")
		}
		plan, source = reprepared, recovered
		fmt.Fprintln(out, "Previous relay recovered. Continuing the confirmed migration with the same identity and website route.")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	s, err := reserveInstance(root, plan.Instance, plan.URL)
	if err != nil {
		return err
	}
	if source != nil {
		return s.migrate(ctx, root, *source, out)
	}
	return s.setup(ctx, plan.URL, out)
}

// The supported manual unit has the fixed packaged launch contract, with an
// inert printable description and an optional exact stopped-container hook.
func knownManualUnit(data []byte, s instanceSpec, engine, image string) bool {
	if len(data) > 8192 || bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	lines := strings.Split(string(data), "\n")
	seenDescription := false
	for i, line := range lines {
		if strings.HasPrefix(line, "Description=") {
			if seenDescription || len(line) > 256 {
				return false
			}
			for _, c := range strings.TrimPrefix(line, "Description=") {
				if c < 32 || c > 126 || c == '%' {
					return false
				}
			}
			seenDescription = true
			lines[i] = "Description=OwnTransit managed relay"
		}
	}
	if !seenDescription {
		return false
	}
	normal := strings.Join(lines, "\n")
	hook := "ExecStopPost=-" + engine + " rm --ignore " + s.container + "\n"
	if filepath.Base(engine) == "podman" {
		normal = strings.Replace(normal, hook, "", 1)
	}
	return bytes.Equal([]byte(normal), s.legacyUnit(image, engine))
}
func noOverrides(ctx context.Context, s instanceSpec) error {
	if err := noDropIns(ctx, s); err != nil {
		return err
	}
	fragment, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=FragmentPath", "--value")
	if err != nil || strings.TrimSpace(string(fragment)) != s.unitPath {
		return errors.New("relay unit is not the expected local systemd file")
	}
	return nil
}
func noDropIns(ctx context.Context, s instanceSpec) error {
	for _, base := range []string{"/etc/systemd/system/", "/run/systemd/system/"} {
		if _, err := os.Lstat(base + s.unitName + ".d"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("relay service override directory prevents migration")
		}
	}
	b, err := command(ctx, "/usr/bin/systemctl", "show", s.unitName, "--property=DropInPaths", "--value")
	if err != nil || len(bytes.TrimSpace(b)) != 0 {
		return errors.New("relay service overrides prevent migration")
	}
	return nil
}
func confined(c containerInfo) bool {
	h := c.HostConfig
	cpu := (h.NanoCpus == 1000000000 && h.CpuPeriod == 0 && h.CpuQuota == 0) || (h.NanoCpus == 0 && h.CpuPeriod == 100000 && h.CpuQuota == 100000)
	nnp := equalStrings(h.SecurityOpt, []string{"no-new-privileges"}) || equalStrings(h.SecurityOpt, []string{"no-new-privileges:true"})
	restart := (h.RestartPolicy.Name == "" || h.RestartPolicy.Name == "no") && h.RestartPolicy.MaximumRetryCount == 0
	return c.Config.User == "65532:65532" && len(c.Mounts) == 1 && c.Mounts[0].RW && h.ReadonlyRootfs && !h.Privileged && h.AutoRemove && len(h.CapAdd) == 0 && droppedAllCapabilities(c) && nnp && restart && h.Memory == 268435456 && h.PidsLimit == 128 && cpu
}

func droppedAllCapabilities(c containerInfo) bool {
	if len(c.EffectiveCaps) != 0 || len(c.BoundingCaps) != 0 {
		return false
	}
	drops := c.HostConfig.CapDrop
	if equalStrings(drops, []string{"ALL"}) || equalStrings(drops, []string{"all"}) {
		return true
	}
	// Podman expands the fixed --cap-drop=all unit argument into its default
	// bounding set. Accept only that complete known set, never a partial list.
	want := []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FOWNER", "CAP_FSETID", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SETFCAP", "CAP_SETGID", "CAP_SETPCAP", "CAP_SETUID", "CAP_SYS_CHROOT"}
	got := append([]string(nil), drops...)
	sort.Strings(got)
	return equalStrings(got, want)
}

func discoverManual(ctx context.Context, u string, specs []instanceSpec) (*migrationSource, error) {
	var found *migrationSource
	var all []containerInfo
	for _, engine := range enginePaths {
		if _, err := os.Lstat(engine); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if _, err := protectedMetadata(engine, 256<<20); err != nil {
			return nil, errors.New("an installed container engine has unsafe or unreadable metadata; migration inventory cannot be completed")
		}
		ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc")
		if err != nil {
			return nil, errors.New("an installed container engine's inventory is unavailable; restore local engine access before retrying migration")
		}
		values := strings.Fields(string(ids))
		if len(values) > 256 {
			return nil, errors.New("container inventory exceeds migration bound")
		}
		for _, id := range values {
			if !validImage("sha256:" + id) {
				return nil, errors.New("invalid container inventory")
			}
			c, err := inspect(ctx, engine, id)
			if err != nil || c.ID != id {
				return nil, errors.New("container inventory changed")
			}
			all = append(all, c)
			name := strings.TrimPrefix(c.Name, "/")
			label := strings.TrimPrefix(name, "owntransit-relay-")
			if name == label || !validLegacyLabel(label) {
				continue
			}
			ports := c.HostConfig.PortBindings["9087/tcp"]
			if len(ports) != 1 {
				continue
			}
			port, err := strconv.Atoi(ports[0].HostPort)
			if err != nil || port < firstInstancePort || port > lastInstancePort {
				continue
			}
			parsed, _ := url.Parse(u)
			route, err := prepareRouteForPort(ctx, parsed.Hostname(), port)
			if errors.Is(err, ErrRoutePortConflict) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if route == nil {
				return nil, ErrRoute
			}
			if !route.edit.Reused {
				continue
			}
			s := legacySpec(label, u, port)
			unit, mode, err := protectedFile(s.unitPath)
			if err != nil || mode != 0644 || !knownManualUnit(unit, s, engine, c.Image) || !c.State.Running || !s.ownsContainer(c, c.Image) || !confined(c) {
				return nil, errors.New("selected site's legacy relay does not match the supported manual deployment")
			}
			if err := noOverrides(ctx, s); err != nil {
				return nil, err
			}
			if _, err := command(ctx, "/usr/bin/systemctl", "is-active", "--quiet", s.unitName); err != nil {
				return nil, errors.New("legacy relay is not active under its expected unit")
			}
			if _, err := command(ctx, "/usr/bin/systemctl", "is-enabled", "--quiet", s.unitName); err != nil {
				return nil, errors.New("legacy relay must have its expected enabled service before migration")
			}
			if err := protectedDirectoryChain(s.root); err != nil {
				return nil, err
			}
			if err := s.validateData(); err != nil {
				return nil, err
			}
			if err := separateData(s, specs); err != nil {
				return nil, err
			}
			for _, other := range specs {
				if other.port == port && other.url != u {
					return nil, errors.New("legacy publication port is reserved by another relay")
				}
			}
			digests, err := identityDigests(s)
			if err != nil {
				return nil, err
			}
			local, err := s.managedIdentity(ctx, engine, c.Image)
			if err != nil {
				return nil, err
			}
			probeCtx, cancel := context.WithTimeout(ctx, firstProbeTimeout)
			remote, err := probeServer(probeCtx, u)
			cancel()
			if err != nil || !sameIdentity(local, remote) {
				return nil, errors.New("the selected public URL did not verify the existing relay identity")
			}
			if found != nil && (found.ContainerID != id || found.Engine != engine) {
				return nil, errors.New("selected URL has conflicting legacy relay owners")
			}
			found = &migrationSource{Label: label, Engine: engine, Image: c.Image, ContainerID: id, Port: port, Unit: unit, Identity: local, Digests: digests}
		}
	}
	if found != nil {
		source := legacySpec(found.Label, u, found.Port)
		for _, c := range all {
			if c.ID == found.ContainerID {
				continue
			}
			for _, m := range c.Mounts {
				if overlapsPath(m.Source, source.dataRoot()) {
					return nil, errors.New("another container shares the legacy relay state")
				}
			}
		}
	}
	return found, nil
}
func sameIdentity(a, b pairrelay.ServerInfo) bool {
	return a.ServerName == b.ServerName && a.LeafSPKISHA256 == b.LeafSPKISHA256 && bytes.Equal(a.CAPEM, b.CAPEM)
}
func overlapsPath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if resolved, err := filepath.EvalSymlinks(a); err == nil {
		a = resolved
	}
	if resolved, err := filepath.EvalSymlinks(b); err == nil {
		b = resolved
	}
	if a == "/" || b == "/" {
		return true
	}
	if a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
		return true
	}
	x, xe := os.Stat(a)
	y, ye := os.Stat(b)
	return xe == nil && ye == nil && os.SameFile(x, y)
}
func separateData(s instanceSpec, specs []instanceSpec) error {
	for _, other := range append(specs, defaultInstance()) {
		if overlapsPath(s.dataRoot(), other.dataRoot()) {
			return errors.New("legacy relay data overlaps an existing instance")
		}
	}
	return nil
}

var relayIdentityFiles = []string{"relay-ca-cert.pem", "relay-ca-key.pem", "relay-cert.pem", "relay-key.pem", "token-hmac.key"}

func identityDigests(s instanceSpec) (map[string]string, error) {
	if err := s.validateData(); err != nil {
		return nil, err
	}
	if err := protectedDirectoryChain(filepath.Dir(s.dataRoot())); err != nil {
		return nil, err
	}
	dataFD, err := unix.Open(s.dataRoot(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	data := os.NewFile(uintptr(dataFD), "relay-data")
	defer data.Close()
	if err := checkIdentityDirectory(data); err != nil {
		return nil, err
	}
	dataNames, err := data.Readdirnames(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(dataNames) != 1 || dataNames[0] != "relay" {
		return nil, errors.New("relay data directory has unexpected members")
	}
	relayFD, err := unix.Openat(dataFD, "relay", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	relay := os.NewFile(uintptr(relayFD), "relay-state")
	defer relay.Close()
	if err := checkIdentityDirectory(relay); err != nil {
		return nil, err
	}
	names, err := relay.Readdirnames(9)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(names) > 7 {
		return nil, errors.New("relay state inventory exceeds its bound")
	}
	allowed := map[string]bool{"service.lock": true, "control.sock": true}
	for _, name := range relayIdentityFiles {
		allowed[name] = true
	}
	for _, name := range names {
		if !allowed[name] {
			return nil, errors.New("unrecognized relay state member")
		}
		if name == "service.lock" || name == "control.sock" {
			var st unix.Stat_t
			if err := unix.Fstatat(relayFD, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return nil, err
			}
			kind := uint32(unix.S_IFREG)
			if name == "control.sock" {
				kind = unix.S_IFSOCK
			}
			if st.Uid != 65532 || st.Gid != 65532 || st.Nlink != 1 || st.Mode != kind|0600 || (name == "service.lock" && st.Size != 0) {
				return nil, errors.New("unsafe relay service state")
			}
		}
	}
	if len(names) < 6 {
		return nil, errors.New("relay state inventory is incomplete")
	}
	lockFound := false
	for _, name := range names {
		lockFound = lockFound || name == "service.lock"
	}
	if !lockFound {
		return nil, errors.New("relay service lock is missing")
	}
	out := map[string]string{}
	for _, name := range relayIdentityFiles {
		digest, err := hashIdentityMember(relayFD, name)
		if err != nil {
			return nil, err
		}
		out[name] = digest
	}
	return out, nil
}

func checkIdentityDirectory(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm() != 0700 || st.Uid != 65532 || st.Gid != 65532 {
		return errors.New("unsafe opened relay identity directory")
	}
	return nil
}

func hashIdentityMember(relayFD int, name string) (string, error) {
	// Nonblocking open prevents an unprivileged file-to-FIFO replacement from
	// hanging the privileged manager before it can inspect the opened inode.
	fd, err := unix.Openat(relayFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), "relay-identity")
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0600)
	if strings.HasSuffix(name, "cert.pem") {
		mode = 0644
	}
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != mode || st.Uid != 65532 || st.Gid != 65532 || st.Nlink != 1 || info.Size() > 32768 {
		return "", errors.New("unsafe opened relay identity file")
	}
	h := sha256.New()
	count, err := io.Copy(h, io.LimitReader(f, 32769))
	if err != nil {
		return "", err
	}
	final, err := f.Stat()
	if err != nil {
		return "", err
	}
	if count != info.Size() || final.Size() != info.Size() || !final.ModTime().Equal(info.ModTime()) {
		return "", errors.New("relay identity changed during inspection")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
