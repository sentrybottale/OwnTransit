//go:build linux

package relaysetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentrybottale/owntransit/internal/securefs"
	"github.com/sentrybottale/owntransit/internal/strictjson"
)

func incompleteReservation(ctx context.Context, s instanceSpec) ([]byte, []byte, error) {
	if !s.named() || s.legacyDataLabel != "" {
		return nil, nil, errors.New("migration needs an unused named reservation")
	}
	r, err := s.openRoot()
	if err != nil {
		return nil, nil, err
	}
	defer r.Close()
	for _, name := range []string{"setup.json", "upgrade.json", "data", "last-upgrade.json"} {
		if _, err := os.Lstat(s.root + "/" + name); !errors.Is(err, os.ErrNotExist) {
			return nil, nil, errors.New("migration destination already owns relay state")
		}
	}
	pending, err := s.readRecord(r, "pending-setup.json", 8192)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	unit, _, err := protectedFile(s.unitPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	var c savedConfig
	if len(pending) > 0 {
		if strictjson.Decode(pending, &c) != nil || !s.validSaved(c) {
			return nil, nil, errors.New("invalid unused reservation")
		}
		if len(unit) > 0 && !s.knownUnit(unit, c) {
			return nil, nil, errors.New("unused relay unit was modified")
		}
	} else if len(unit) > 0 {
		return nil, nil, errors.New("unused unit lacks a matching pending record")
	}
	for _, engine := range enginePaths {
		if _, err := os.Lstat(engine); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if _, err := protectedMetadata(engine, 256<<20); err != nil {
			return nil, nil, errors.New("container engine metadata prevents complete reservation inspection")
		}
		ids, err := command(ctx, engine, "ps", "--all", "--quiet", "--no-trunc", "--filter", "name="+s.container)
		if err != nil {
			return nil, nil, errors.New("container inventory is unavailable for the unused reservation")
		}
		values := strings.Fields(string(ids))
		if len(values) > 256 {
			return nil, nil, errors.New("reservation container inventory exceeds bound")
		}
		for _, id := range values {
			if !validImage("sha256:" + id) {
				return nil, nil, errors.New("invalid reservation container identity")
			}
			container, err := inspect(ctx, engine, id)
			if err != nil || container.ID != id {
				return nil, nil, errors.New("reservation container inspection changed")
			}
			if strings.TrimPrefix(container.Name, "/") == s.container {
				return nil, nil, errors.New("migration reservation already has a container; local ownership needs inspection")
			}
		}
	}
	if len(unit) > 0 {
		if err := noOverrides(ctx, s); err != nil {
			return nil, nil, err
		}
	} else if err := noDropIns(ctx, s); err != nil {
		return nil, nil, err
	}
	for _, op := range []string{"is-active", "is-enabled"} {
		if _, err := command(ctx, "/usr/bin/systemctl", op, "--quiet", s.unitName); err == nil {
			return nil, nil, errors.New("migration destination service is active or enabled")
		}
	}
	return pending, unit, nil
}

func (s instanceSpec) loadMigrationImage(ctx context.Context, engine string) (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return "", err
	}
	archive := filepath.Join(filepath.Dir(executable), "owntransit-relay.oci.tar")
	if _, err := protectedMetadata(archive, 128<<20); err != nil {
		return "", errors.New("authenticated relay image is missing beside installed executable")
	}
	if filepath.Base(engine) == "docker" {
		input, err := os.Open(archive)
		if err != nil {
			return "", err
		}
		defer input.Close()
		converted, err := os.CreateTemp(s.root, "docker-load-*.tar")
		if err != nil {
			return "", err
		}
		defer os.Remove(converted.Name())
		err = DockerArchive(input, converted, imageTag)
		closeErr := converted.Close()
		if err != nil || closeErr != nil {
			return "", errors.Join(err, closeErr)
		}
		archive = converted.Name()
	}
	if _, err := command(ctx, engine, "load", "--input", archive); err != nil {
		return "", err
	}
	b, err := command(ctx, engine, "image", "inspect", "--format", "{{.Id}}", imageTag)
	if err != nil {
		return "", err
	}
	image := strings.TrimSpace(string(b))
	if len(image) == 64 {
		image = "sha256:" + image
	}
	if !validImage(image) {
		return "", errors.New("new relay image is not immutable")
	}
	user, err := command(ctx, engine, "image", "inspect", "--format", "{{.Config.User}}", image)
	if err != nil || strings.TrimSpace(string(user)) != "65532:65532" {
		return "", errors.New("new relay image has an unexpected runtime identity")
	}
	return image, nil
}
func migrationGuard(j migrationIntent) []byte {
	return bytes.Replace(j.Source.Unit, []byte("[Unit]\n"), []byte("[Unit]\nConditionPathExists=!"+managedRoot+"/"+migrationFile+"\n"), 1)
}
func saveMigration(root *securefs.Root, j migrationIntent, create bool) error {
	if err := validateMigration(j); err != nil {
		return err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(b) > migrationLimit {
		return errors.New("migration journal exceeds bound")
	}
	if create {
		if _, err := root.ReadFile(migrationFile, migrationLimit); !errors.Is(err, os.ErrNotExist) {
			return errors.New("a relay migration already has a journal")
		}
	}
	// The manager lock excludes another publisher. Atomic replacement also
	// publishes the initial intent whole; a crash cannot leave partial JSON.
	return root.ReplaceFile(migrationFile, b, 0600)
}

var publishMigration = saveMigration

func (s instanceSpec) migrate(ctx context.Context, manager *securefs.Root, source migrationSource, out io.Writer) (returnErr error) {
	pending, oldUnit, err := incompleteReservation(ctx, s)
	if err != nil {
		return err
	}
	image, err := s.loadMigrationImage(ctx, source.Engine)
	if err != nil {
		return err
	}
	oldImage, err := command(ctx, source.Engine, "image", "inspect", "--format", "{{.Id}}", source.Image)
	resolvedOld := strings.TrimSpace(string(oldImage))
	if len(resolvedOld) == 64 {
		resolvedOld = "sha256:" + resolvedOld
	}
	if err != nil || resolvedOld != source.Image {
		return errors.New("old relay image is missing; migration cannot roll back")
	}
	nextBinding := s.binding()
	nextBinding.Schema = "owntransit.relay-instance.v2"
	nextBinding.LegacyDataLabel = source.Label
	nextBinding.Port = source.Port
	next, err := instanceFromBinding(nextBinding)
	if err != nil {
		return err
	}
	j := migrationIntent{Schema: "owntransit.relay-migration.v2", Phase: "prepared", Source: source, PreviousBinding: s.binding(), NextBinding: nextBinding, PreviousPending: pending, PreviousUnit: oldUnit, Next: next.config(s.url, source.Engine, image)}
	// Inspect once more after image loading; the prepared public identity and
	// exact source ID/unit/state must still be the current deployment.
	specs, err := scanInstances(manager)
	if err != nil {
		return err
	}
	current, err := discoverManual(ctx, s.url, specs)
	if err != nil {
		return err
	}
	if current == nil || planDigest(current) != planDigest(source) {
		return errors.New("legacy relay changed before migration")
	}
	if err := publishMigration(manager, j, true); err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			recoverCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if j.Phase == "committed" {
				returnErr = errors.Join(returnErr, errors.New("verified migration cleanup is pending; rerun the same setup"))
			} else if e := restoreMigration(recoverCtx, manager, j); e != nil {
				returnErr = errors.Join(returnErr, errors.New("migration recovery is pending; rerun the same setup"), e)
			} else {
				fmt.Fprintln(out, "Migration failed; the previous relay and unused reservation were restored.")
			}
		}
	}()
	old := legacySpec(source.Label, s.url, source.Port)
	if err := writeAtomic(old.unitPath, migrationGuard(j), 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", old.unitName); err != nil {
		return err
	}
	if err := old.prevalidateContainer(ctx, old.config(old.url, source.Engine, source.Image), false); err != nil {
		return err
	}
	if err := checkIdentityDigests(next, source.Digests); err != nil {
		return err
	}
	r, err := s.openRoot()
	if err != nil {
		return err
	}
	defer r.Close()
	binding, _ := json.Marshal(nextBinding)
	if err := r.ReplaceFile("instance.json", binding, 0600); err != nil {
		return err
	}
	if err := writeAtomic(next.unitPath, next.unit(image, source.Engine), 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", "--now", next.unitName); err != nil {
		return err
	}
	if err := verifyMigration(ctx, next, j); err != nil {
		return err
	}
	config, _ := json.Marshal(j.Next)
	if err := r.ReplaceFile("setup.json", config, 0600); err != nil {
		return err
	}
	if len(pending) > 0 {
		if err := r.UnlinkFile("pending-setup.json"); err != nil {
			return err
		}
	}
	j.Phase = "committed"
	if err := publishMigration(manager, j, false); err != nil {
		// Rename may already have published the committed decision before its
		// directory sync failed. Never roll back against that possible decision;
		// the next invocation reads the actual journal and recovers accordingly.
		return err
	}
	if err := finishMigration(ctx, manager, j); err != nil {
		return err
	}
	reportVerification(out, currentVerification(ctx))
	fmt.Fprintf(out, "Local relay migration completed for %s. The old unit and container were retired; the existing relay keys and website route are retained.\n", s.url)
	return nil
}
func checkIdentityDigests(s instanceSpec, want map[string]string) error {
	got, err := identityDigests(s)
	if err != nil {
		return err
	}
	if planDigest(got) != planDigest(want) {
		return errors.New("relay identity files changed; recovery requires local inspection")
	}
	return nil
}
func verifyMigration(ctx context.Context, s instanceSpec, j migrationIntent) error {
	if j.Schema == "owntransit.relay-migration.v2" {
		ctx = withVerificationEvidence(ctx, j.Source.evidence(s.url))
	}
	if err := s.verifyRunningRelay(ctx, j.Next, routeProbeTimeout); err != nil {
		return err
	}
	c, err := inspect(ctx, j.Next.Engine, s.container)
	if err != nil || !confined(c) {
		return errors.New("managed relay confinement could not be verified")
	}
	local, err := s.managedIdentity(ctx, j.Next.Engine, j.Next.Image)
	if err != nil || !sameIdentity(local, j.Source.Identity) {
		return errors.New("managed relay did not retain the original identity")
	}
	for _, op := range []string{"is-active", "is-enabled"} {
		if _, err := command(ctx, "/usr/bin/systemctl", op, "--quiet", s.unitName); err != nil {
			return errors.New("managed relay service is not active and enabled")
		}
	}
	return checkIdentityDigests(s, j.Source.Digests)
}

// validateMigrationState accepts only the two recorded metadata generations.
// It runs before any recovery stop, unlink, or ownership publication.
func validateMigrationState(ctx context.Context, j migrationIntent) (instanceSpec, *securefs.Root, error) {
	if err := validateMigration(j); err != nil {
		return instanceSpec{}, nil, err
	}
	next, _ := instanceFromBinding(j.NextBinding)
	previous, _ := instanceFromBinding(j.PreviousBinding)
	r, err := next.openRoot()
	if err != nil {
		return next, nil, err
	}
	fail := func(err error) (instanceSpec, *securefs.Root, error) { r.Close(); return next, nil, err }
	b, err := next.readRecord(r, "instance.json", 8192)
	if err != nil {
		return fail(err)
	}
	var binding instanceBinding
	if strictjson.Decode(b, &binding) != nil || (binding != j.PreviousBinding && binding != j.NextBinding) {
		return fail(errors.New("relay binding changed outside migration"))
	}
	if j.Phase == "committed" && binding != j.NextBinding {
		return fail(errors.New("committed migration binding is not selected"))
	}
	old := legacySpec(j.Source.Label, next.url, j.Source.Port)
	u, _, err := protectedFile(old.unitPath)
	if errors.Is(err, os.ErrNotExist) && j.Phase == "committed" {
	} else if err != nil || (!bytes.Equal(u, j.Source.Unit) && !bytes.Equal(u, migrationGuard(j))) {
		return fail(errors.New("legacy unit changed outside migration"))
	}
	if len(u) > 0 {
		if err := noOverrides(ctx, old); err != nil {
			return fail(err)
		}
	}
	u, _, err = protectedFile(next.unitPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if len(u) > 0 && !bytes.Equal(u, j.PreviousUnit) && !bytes.Equal(u, next.unit(j.Next.Image, j.Next.Engine)) {
		return fail(errors.New("managed unit changed outside migration"))
	}
	if j.Phase == "committed" && !bytes.Equal(u, next.unit(j.Next.Image, j.Next.Engine)) {
		return fail(errors.New("committed managed unit is not selected"))
	}
	if len(u) > 0 {
		if err := noOverrides(ctx, next); err != nil {
			return fail(err)
		}
	}
	config, err := next.readRecord(r, "setup.json", 8192)
	if err == nil {
		var c savedConfig
		if strictjson.Decode(config, &c) != nil || c != j.Next {
			return fail(errors.New("relay setup changed outside migration"))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if j.Phase == "committed" && len(config) == 0 {
		return fail(errors.New("committed setup record is missing"))
	}
	pending, err := next.readRecord(r, "pending-setup.json", 8192)
	if err == nil && !bytes.Equal(pending, j.PreviousPending) {
		return fail(errors.New("pending setup changed outside migration"))
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fail(err)
	}
	if j.Phase == "committed" && len(pending) != 0 {
		return fail(errors.New("committed migration retains a conflicting pending setup"))
	}
	if err := checkIdentityDigests(next, j.Source.Digests); err != nil {
		return fail(err)
	}
	// A stopped unrelated same-name container is not an absence certificate.
	if err := next.prevalidateContainer(ctx, j.Next, true); err != nil {
		return fail(err)
	}
	if err := old.prevalidateContainer(ctx, old.config(old.url, j.Source.Engine, j.Source.Image), true); err != nil {
		return fail(err)
	}
	if _, err := os.Lstat(previous.root + "/data"); !errors.Is(err, os.ErrNotExist) {
		return fail(errors.New("migration destination acquired independent identity state"))
	}
	return next, r, nil
}

func restoreMigration(ctx context.Context, manager *securefs.Root, j migrationIntent) error {
	if j.Phase != "prepared" {
		return errors.New("committed relay migration must finish cleanup")
	}
	next, r, err := validateMigrationState(ctx, j)
	if err != nil {
		return err
	}
	defer r.Close()
	old := legacySpec(j.Source.Label, next.url, j.Source.Port)
	u, _, ue := protectedFile(next.unitPath)
	if ue == nil && bytes.Equal(u, next.unit(j.Next.Image, j.Next.Engine)) {
		if _, err := command(ctx, "/usr/bin/systemctl", "disable", "--now", next.unitName); err != nil {
			return err
		}
	}
	if err := next.cleanupStopped(ctx, j.Next.Engine, []string{j.Next.Image}); err != nil {
		return err
	}
	if len(j.PreviousUnit) > 0 {
		if err := writeAtomic(next.unitPath, j.PreviousUnit, 0644); err != nil {
			return err
		}
	} else if ue == nil {
		if err := removeExactUnit(next.unitPath, next.unit(j.Next.Image, j.Next.Engine)); err != nil {
			return err
		}
	}
	if err := restoreOptionalRecord(r, "setup.json", nil); err != nil {
		return err
	}
	if err := restoreOptionalRecord(r, "pending-setup.json", j.PreviousPending); err != nil {
		return err
	}
	b, _ := json.Marshal(j.PreviousBinding)
	if err := r.ReplaceFile("instance.json", b, 0600); err != nil {
		return err
	}
	if err := writeAtomic(old.unitPath, j.Source.Unit, 0644); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Stopping the auto-remove source may have left a known stopped container.
	c, e := inspect(ctx, j.Source.Engine, old.container)
	if e == nil && !c.State.Running {
		if err := old.cleanupStopped(ctx, j.Source.Engine, []string{j.Source.Image}); err != nil {
			return err
		}
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "enable", "--now", old.unitName); err != nil {
		return err
	}
	verifyCtx := ctx
	if j.Schema == "owntransit.relay-migration.v2" {
		verifyCtx = withVerificationEvidence(ctx, j.Source.evidence(old.url))
	}
	if err := old.verifyRunningRelay(verifyCtx, old.config(old.url, j.Source.Engine, j.Source.Image), routeProbeTimeout); err != nil {
		return err
	}
	if err := checkIdentityDigests(next, j.Source.Digests); err != nil {
		return err
	}
	return manager.UnlinkFile(migrationFile)
}
func restoreOptionalRecord(root *securefs.Root, name string, data []byte) error {
	if len(data) > 0 {
		return root.ReplaceFile(name, data, 0600)
	}
	if err := root.UnlinkFile(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
func removeExactUnit(path string, want []byte) error {
	got, _, err := protectedFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !bytes.Equal(got, want) {
		return errors.New("unit changed; exact removal refused")
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func finishMigration(ctx context.Context, manager *securefs.Root, j migrationIntent) error {
	if j.Phase != "committed" {
		return errors.New("migration is not verified")
	}
	next, r, err := validateMigrationState(ctx, j)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := verifyMigration(ctx, next, j); err != nil {
		return err
	}
	old := legacySpec(j.Source.Label, next.url, j.Source.Port)
	if err := old.cleanupStopped(ctx, j.Source.Engine, []string{j.Source.Image}); err != nil {
		return err
	}
	if err := removeExactUnit(old.unitPath, migrationGuard(j)); err != nil {
		return err
	}
	if _, err := command(ctx, "/usr/bin/systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Retain public rollback evidence and the original image; no key material
	// is copied and the retained data directory has one active managed owner.
	b, _ := json.Marshal(j)
	if err := r.ReplaceFile("last-migration.json", b, 0600); err != nil {
		return err
	}
	return manager.UnlinkFile(migrationFile)
}
