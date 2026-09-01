//go:build darwin || linux

package packagetxn

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"golang.org/x/sys/unix"
)

var errInterrupted = errors.New("test interruption")

type transactionHarness struct {
	base    string
	root    string
	manager *Manager
	uid     uint32
	gid     uint32
}

func newTransactionHarness(t *testing.T, role string) *transactionHarness {
	t.Helper()
	temporary, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	root := filepath.Join(temporary, "package-root")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("create package root: %v", err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatalf("protect package root: %v", err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	manager, err := openManager(root, role, uid, gid, false, func(int, bool) error { return nil })
	if err != nil {
		t.Fatalf("open test package manager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Errorf("close test package manager: %v", err)
		}
	})
	return &transactionHarness{base: temporary, root: root, manager: manager, uid: uid, gid: gid}
}

func (harness *transactionHarness) decision(t *testing.T, label, role string, sequence uint64) decision {
	t.Helper()
	bundle := filepath.Join(harness.base, "bundle-"+label)
	artifacts := filepath.Join(bundle, "artifacts")
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	if err := os.Chmod(bundle, 0o700); err != nil {
		t.Fatalf("protect bundle: %v", err)
	}
	if err := os.Chmod(artifacts, 0o700); err != nil {
		t.Fatalf("protect artifacts: %v", err)
	}

	primaryName := "owntransit"
	if role == "connector" {
		primaryName = "owntransit-connector"
	} else if role == "relay" {
		primaryName = "owntransit-relay.oci.tar"
	} else if role == "provisioner" {
		primaryName = "owntransit-provision"
	}
	primaryMode := fs.FileMode(0o755)
	if role == "relay" {
		primaryMode = 0o600
	} else if role == "provisioner" {
		primaryMode = 0o700
	}

	type fixtureFile struct {
		artifact string
		source   string
		install  string
		mode     fs.FileMode
		contents []byte
	}
	fixtures := []fixtureFile{{
		artifact: role + "-artifact", source: "artifacts/primary", install: primaryName,
		mode: primaryMode, contents: []byte("primary-" + label + "\n"),
	}}
	if role != "provisioner" {
		fixtures = append(fixtures, fixtureFile{
			artifact: "lifecycle-artifact", source: "artifacts/lifecycle", install: "owntransitctl",
			mode: 0o700, contents: []byte("lifecycle-" + label + "\n"),
		})
	}
	files := make([]decisionFile, len(fixtures))
	for index, fixture := range fixtures {
		path := filepath.Join(bundle, filepath.FromSlash(fixture.source))
		if err := os.WriteFile(path, fixture.contents, 0o600); err != nil {
			t.Fatalf("write bundle artifact: %v", err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatalf("protect bundle artifact: %v", err)
		}
		files[index] = decisionFile{
			ArtifactName: fixture.artifact,
			SourcePath:   fixture.source,
			InstallName:  fixture.install,
			SHA256:       digestBytes(fixture.contents),
			Size:         int64(len(fixture.contents)),
			Mode:         fixture.mode,
			GID:          harness.gid,
		}
	}
	if len(files) == 2 && files[0].InstallName > files[1].InstallName {
		files[0], files[1] = files[1], files[0]
	}
	digest := sha256.Sum256([]byte("release-" + label))
	releaseID := protocol.ID(digest).String()
	return decision{
		seal: decisionSeal, operation: operationInstall, bundleRoot: bundle, releaseID: releaseID, sequence: sequence,
		manifestSHA256: digestBytes([]byte("manifest-" + label)), role: role,
		os: runtime.GOOS, arch: runtime.GOARCH, files: files,
	}
}

func TestInstallResumesAfterEveryDurableTransition(t *testing.T) {
	points := []failurePoint{
		pointJournalPlanned,
		pointReleaseStaged,
		pointJournalStaged,
		pointSelectorCommit,
		pointJournalSelected,
		pointJournalComplete,
	}
	for _, point := range points {
		t.Run(string(point), func(t *testing.T) {
			harness := newTransactionHarness(t, "client")
			decision := harness.decision(t, string(point), "client", 1)
			failed := false
			_, err := harness.manager.install(decision, func(observed failurePoint) error {
				if !failed && observed == point {
					failed = true
					return errInterrupted
				}
				return nil
			}, nil)
			if !failed || err == nil || !errors.Is(err, errInterrupted) {
				t.Fatalf("interrupted Install error = %v, hook fired = %v", err, failed)
			}

			result, err := harness.manager.installVerified(decision)
			if err != nil {
				t.Fatalf("resume Install: %v", err)
			}
			if result.Current != decision.releaseID || result.Previous != "" || result.Generation != 1 {
				t.Fatalf("resume result = %+v", result)
			}
			if point == pointJournalComplete {
				if !result.Idempotent || result.Installed || result.Resumed {
					t.Fatalf("post-complete replay result = %+v", result)
				}
			} else if !result.Installed || !result.Resumed || result.Idempotent {
				t.Fatalf("resumed result = %+v", result)
			}
			assertNoStageFiles(t, harness.root)
			assertReleaseFiles(t, harness, decision)
		})
	}
}

func TestInstallAThenBThenCRetiresAAndRejectsReplay(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	releaseA := harness.decision(t, "release-a", "client", 7)
	releaseB := harness.decision(t, "release-b", "client", 8)
	releaseC := harness.decision(t, "release-c", "client", 9)

	first, err := harness.manager.installVerified(releaseA)
	if err != nil {
		t.Fatalf("install A: %v", err)
	}
	if !first.Installed || first.Resumed || first.Idempotent || first.Generation != 1 {
		t.Fatalf("install A result = %+v", first)
	}
	second, err := harness.manager.installVerified(releaseB)
	if err != nil {
		t.Fatalf("install B: %v", err)
	}
	if second.Current != releaseB.releaseID || second.Previous != releaseA.releaseID || second.Generation != 2 {
		t.Fatalf("install B result = %+v", second)
	}
	selector := readSelectorFromDisk(t, harness, "client")
	if selector.Current != releaseB.releaseID || selector.Previous != releaseA.releaseID || selector.Generation != 2 {
		t.Fatalf("selector after B = %+v", selector)
	}

	idempotent, err := harness.manager.installVerified(releaseB)
	if err != nil || !idempotent.Idempotent || idempotent.Installed {
		t.Fatalf("same release result = %+v, error = %v", idempotent, err)
	}
	if _, err := harness.manager.installVerified(releaseA); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay A error = %v, want %v", err, ErrReplay)
	}
	third, err := harness.manager.installVerified(releaseC)
	if err != nil {
		t.Fatalf("install C: %v", err)
	}
	if third.Current != releaseC.releaseID || third.Previous != releaseB.releaseID || third.Generation != 3 {
		t.Fatalf("install C result = %+v", third)
	}
	if _, err := os.Stat(filepath.Join(harness.root, "client", releasesDirectory, releaseA.releaseID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired release A still exists: %v", err)
	}
	assertReleaseFiles(t, harness, releaseB)
	assertReleaseFiles(t, harness, releaseC)
}

func TestConcurrentInstallUsesExactDescriptorLock(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	decision := harness.decision(t, "concurrent", "client", 1)
	started := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	var once sync.Once
	go func() {
		_, err := harness.manager.install(decision, func(point failurePoint) error {
			if point == pointJournalPlanned {
				once.Do(func() { close(started) })
				<-release
			}
			return nil
		}, nil)
		firstDone <- err
	}()
	select {
	case <-started:
	case err := <-firstDone:
		t.Fatalf("first Install ended before acquiring the descriptor lock: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first Install did not reach the descriptor-lock test point")
	}
	if _, err := harness.manager.installVerified(decision); !errors.Is(err, ErrLocked) {
		close(release)
		t.Fatalf("concurrent Install error = %v, want %v", err, ErrLocked)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first Install: %v", err)
	}
}

func TestInterruptedOwnedStagesAreRecoveredButCompletedResidueIsRejected(t *testing.T) {
	t.Run("partial-payload", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "partial-payload", "client", 1)
		_, err := harness.manager.install(decision, interruptAt(pointJournalPlanned), nil)
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("interrupt planned transaction: %v", err)
		}
		releasePath := filepath.Join(harness.root, "client", releasesDirectory, decision.releaseID)
		if err := os.Mkdir(releasePath, 0o750); err != nil {
			t.Fatalf("create interrupted release directory: %v", err)
		}
		stage := filepath.Join(releasePath, payloadStageName(decision.files[0].InstallName))
		if err := os.WriteFile(stage, []byte("partial"), 0o600); err != nil {
			t.Fatalf("create interrupted payload stage: %v", err)
		}
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("resume partial payload: %v", err)
		}
		assertNoStageFiles(t, harness.root)
	})

	t.Run("metadata-stage", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "metadata-stage", "client", 1)
		_, err := harness.manager.install(decision, interruptAt(pointJournalStaged), nil)
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("interrupt staged transaction: %v", err)
		}
		stage := filepath.Join(harness.root, "client", selectorStageName)
		if err := os.WriteFile(stage, []byte("interrupted metadata"), 0o600); err != nil {
			t.Fatalf("create interrupted selector stage: %v", err)
		}
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("resume metadata stage: %v", err)
		}
		assertNoStageFiles(t, harness.root)
	})

	t.Run("receipt-hardlink-publication", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "receipt-hardlink-publication", "client", 1)
		_, err := harness.manager.install(decision, interruptAt(pointJournalPlanned), nil)
		if !errors.Is(err, errInterrupted) {
			t.Fatalf("interrupt planned transaction: %v", err)
		}

		releasePath := filepath.Join(harness.root, "client", releasesDirectory, decision.releaseID)
		if err := os.Mkdir(releasePath, 0o750); err != nil {
			t.Fatalf("create interrupted release directory: %v", err)
		}
		for _, file := range decision.files {
			contents, err := os.ReadFile(filepath.Join(decision.bundleRoot, filepath.FromSlash(file.SourcePath)))
			if err != nil {
				t.Fatalf("read fixture payload: %v", err)
			}
			writeTestFile(t, filepath.Join(releasePath, file.InstallName), contents, file.Mode)
		}
		_, receiptBytes, _, err := receiptForDecision(decision)
		if err != nil {
			t.Fatalf("encode receipt: %v", err)
		}
		stagePath := filepath.Join(releasePath, receiptStageName)
		writeTestFile(t, stagePath, receiptBytes, 0o600)
		if err := os.Link(stagePath, filepath.Join(releasePath, receiptFileName)); err != nil {
			t.Fatalf("publish interrupted receipt hardlink: %v", err)
		}

		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("resume receipt publication: %v", err)
		}
		assertNoStageFiles(t, harness.root)
		assertReleaseFiles(t, harness, decision)
	})

	t.Run("complete-uncommitted-stage-is-discarded", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "completed-stage", "client", 1)
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("install: %v", err)
		}
		stage := filepath.Join(harness.root, "client", selectorStageName)
		if err := os.WriteFile(stage, []byte("unexplained"), 0o600); err != nil {
			t.Fatalf("create unexplained selector stage: %v", err)
		}
		if result, err := harness.manager.installVerified(decision); err != nil || !result.Idempotent {
			t.Fatalf("completed transaction with uncommitted stage result = %+v, error = %v", result, err)
		}
		assertNoStageFiles(t, harness.root)
	})

	t.Run("initial-partial-journal-stage-is-discarded", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "initial-journal-stage", "client", 1)
		rolePath := filepath.Join(harness.root, "client")
		if err := os.Mkdir(rolePath, 0o750); err != nil {
			t.Fatalf("create role directory: %v", err)
		}
		if err := os.Mkdir(filepath.Join(rolePath, releasesDirectory), 0o750); err != nil {
			t.Fatalf("create releases directory: %v", err)
		}
		stage := filepath.Join(rolePath, journalStageName)
		writeTestFile(t, stage, []byte("partial"), 0o600)
		if err := os.Chmod(stage, 0o200); err != nil {
			t.Fatalf("simulate pre-fchmod journal stage: %v", err)
		}
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("install after partial initial journal stage: %v", err)
		}
		assertNoStageFiles(t, harness.root)
	})
}

func TestManagerCopyAndFilesystemMismatchFailClosed(t *testing.T) {
	t.Run("copied-handle", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "copied-manager", "client", 1)
		copiedValue := reflect.New(reflect.TypeOf(harness.manager).Elem())
		copiedValue.Elem().Set(reflect.ValueOf(harness.manager).Elem())
		copied := copiedValue.Interface().(*Manager)
		if _, err := copied.installVerified(decision); err == nil || !strings.Contains(err.Error(), "copied") {
			t.Fatalf("copied manager Install error = %v", err)
		}
		if err := copied.Close(); err == nil || !strings.Contains(err.Error(), "copied") {
			t.Fatalf("copied manager Close error = %v", err)
		}
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("original manager was damaged by copied handle: %v", err)
		}
	})

	t.Run("different-device", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "different-device", "client", 1)
		harness.manager.rootDevice++
		if _, err := harness.manager.installVerified(decision); !errors.Is(err, ErrResidue) || !strings.Contains(err.Error(), "filesystem") {
			t.Fatalf("cross-filesystem Install error = %v", err)
		}
	})

	t.Run("interrupted-empty-lock-mode", func(t *testing.T) {
		harness := newTransactionHarness(t, "client")
		decision := harness.decision(t, "interrupted-lock", "client", 1)
		rolePath := filepath.Join(harness.root, "client")
		if err := os.Mkdir(rolePath, 0o750); err != nil {
			t.Fatalf("create role directory: %v", err)
		}
		if err := os.Mkdir(filepath.Join(rolePath, releasesDirectory), 0o750); err != nil {
			t.Fatalf("create releases directory: %v", err)
		}
		lockPath := filepath.Join(rolePath, lockFileName)
		writeTestFile(t, lockPath, nil, 0o600)
		if err := os.Chmod(lockPath, 0o200); err != nil {
			t.Fatalf("simulate interrupted lock chmod: %v", err)
		}
		if _, err := harness.manager.installVerified(decision); err != nil {
			t.Fatalf("install after interrupted lock initialization: %v", err)
		}
		info, err := os.Stat(lockPath)
		if err != nil || info.Mode().Perm() != 0o600 || info.Size() != 0 {
			t.Fatalf("normalized lock = %+v, error = %v", info, err)
		}
	})
}

func TestInstallAcceptsProtectedBundlePathWithSpacesAndRejectsWrongPlatform(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	decision := harness.decision(t, "ordinary-bundle-path", "client", 1)
	ordinaryPath := filepath.Join(harness.base, "bundle with spaces")
	if err := os.Rename(decision.bundleRoot, ordinaryPath); err != nil {
		t.Fatalf("rename bundle: %v", err)
	}
	decision.bundleRoot = ordinaryPath
	if _, err := harness.manager.installVerified(decision); err != nil {
		t.Fatalf("install from protected ordinary path: %v", err)
	}

	other := harness.decision(t, "wrong-platform", "client", 2)
	other.os = "not-" + runtime.GOOS
	if _, err := harness.manager.installVerified(other); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("wrong-platform decision error = %v, want %v", err, ErrInvalidDecision)
	}
}

func TestInstallFailsClosedOnResidueAndFilesystemSubstitution(t *testing.T) {
	tests := map[string]func(*testing.T, *transactionHarness, decision){
		"unexpected-role-entry": func(t *testing.T, harness *transactionHarness, decision decision) {
			writeTestFile(t, filepath.Join(harness.root, "client", "surprise"), []byte("x"), 0o600)
		},
		"selector-symlink": func(t *testing.T, harness *transactionHarness, decision decision) {
			selector := filepath.Join(harness.root, "client", selectorFileName)
			if err := os.Remove(selector); err != nil {
				t.Fatalf("remove selector: %v", err)
			}
			if err := os.Symlink("journal.json", selector); err != nil {
				t.Fatalf("replace selector with symlink: %v", err)
			}
		},
		"hardlinked-payload": func(t *testing.T, harness *transactionHarness, decision decision) {
			payload := filepath.Join(harness.root, "client", releasesDirectory, decision.releaseID, decision.files[0].InstallName)
			if err := os.Link(payload, filepath.Join(harness.base, "outside-hardlink")); err != nil {
				t.Fatalf("hardlink installed payload: %v", err)
			}
		},
		"journal-mode": func(t *testing.T, harness *transactionHarness, _ decision) {
			if err := os.Chmod(filepath.Join(harness.root, "client", journalFileName), 0o644); err != nil {
				t.Fatalf("weaken journal mode: %v", err)
			}
		},
		"unexpected-release": func(t *testing.T, harness *transactionHarness, _ decision) {
			if err := os.Mkdir(filepath.Join(harness.root, "client", releasesDirectory, testReleaseID("unexpected")), 0o750); err != nil {
				t.Fatalf("create unexpected release: %v", err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			harness := newTransactionHarness(t, "client")
			decision := harness.decision(t, "residue-"+name, "client", 1)
			if _, err := harness.manager.installVerified(decision); err != nil {
				t.Fatalf("install fixture: %v", err)
			}
			mutate(t, harness, decision)
			if _, err := harness.manager.installVerified(decision); !errors.Is(err, ErrResidue) {
				t.Fatalf("Install after mutation error = %v, want %v", err, ErrResidue)
			}
		})
	}
}

func TestInstallRejectsInvalidDecisionRoleAndSourceSymlink(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	if _, err := harness.manager.installVerified(decision{}); !errors.Is(err, ErrInvalidDecision) {
		t.Fatalf("zero decision error = %v, want %v", err, ErrInvalidDecision)
	}
	mismatched := harness.decision(t, "mismatched", "connector", 1)
	if _, err := harness.manager.installVerified(mismatched); err == nil || !strings.Contains(err.Error(), "another role") {
		t.Fatalf("mismatched role error = %v", err)
	}

	decision := harness.decision(t, "source-symlink", "client", 1)
	source := filepath.Join(decision.bundleRoot, filepath.FromSlash(decision.files[0].SourcePath))
	target := filepath.Join(decision.bundleRoot, filepath.FromSlash(decision.files[1].SourcePath))
	if err := os.Remove(source); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	if err := os.Symlink(target, source); err != nil {
		t.Fatalf("replace source with symlink: %v", err)
	}
	if _, err := harness.manager.installVerified(decision); err == nil {
		t.Fatal("Install accepted a symlinked authenticated source")
	}
}

func TestInstallRehashesAuthenticatedSourceAtStagingBoundary(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	decision := harness.decision(t, "source-rehash", "client", 1)
	source := filepath.Join(decision.bundleRoot, filepath.FromSlash(decision.files[0].SourcePath))
	changed := make([]byte, decision.files[0].Size)
	for index := range changed {
		changed[index] = 'x'
	}
	if err := os.WriteFile(source, changed, 0o600); err != nil {
		t.Fatalf("replace authenticated source bytes: %v", err)
	}
	if _, err := harness.manager.installVerified(decision); err == nil || !strings.Contains(err.Error(), "digest changed") {
		t.Fatalf("Install error = %v, want authenticated digest failure", err)
	}
	if _, err := os.Stat(filepath.Join(harness.root, "client", selectorFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("selector exists after source authentication failure: %v", err)
	}
}

func TestDescriptorLockRejectsNameReplacement(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	decision := harness.decision(t, "lock-replacement", "client", 1)
	harness.manager.lockOpenHook = func(directory, _ int, name string) error {
		if err := unix.Renameat(directory, name, directory, name+".detached"); err != nil {
			return fmt.Errorf("rename lock: %w", err)
		}
		fd, err := unix.Openat(directory, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err != nil {
			return fmt.Errorf("create replacement lock: %w", err)
		}
		return unix.Close(fd)
	}
	if _, err := harness.manager.installVerified(decision); !errors.Is(err, ErrResidue) {
		t.Fatalf("lock replacement error = %v, want %v", err, ErrResidue)
	}
}

func TestRoleNamespacesDoNotShareSelectorsOrLocks(t *testing.T) {
	harness := newTransactionHarness(t, "client")
	clientDecision := harness.decision(t, "namespace-client", "client", 1)
	if _, err := harness.manager.installVerified(clientDecision); err != nil {
		t.Fatalf("install client: %v", err)
	}
	connector, err := openManager(harness.root, "connector", harness.uid, harness.gid, false, func(int, bool) error { return nil })
	if err != nil {
		t.Fatalf("open connector namespace: %v", err)
	}
	defer connector.Close()
	connectorDecision := harness.decision(t, "namespace-connector", "connector", 1)
	connectorDecision.releaseID = clientDecision.releaseID
	if _, err := connector.installVerified(connectorDecision); err != nil {
		t.Fatalf("install connector: %v", err)
	}
	clientSelector := readSelectorFromDisk(t, harness, "client")
	connectorSelector := readSelectorFromDisk(t, harness, "connector")
	if clientSelector.Current != clientDecision.releaseID || connectorSelector.Current != connectorDecision.releaseID {
		t.Fatalf("role selectors crossed: client %+v, connector %+v", clientSelector, connectorSelector)
	}
}

func interruptAt(want failurePoint) func(failurePoint) error {
	return func(observed failurePoint) error {
		if observed == want {
			return errInterrupted
		}
		return nil
	}
}

func readSelectorFromDisk(t *testing.T, harness *transactionHarness, role string) selectorRecord {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(harness.root, role, selectorFileName))
	if err != nil {
		t.Fatalf("read selector: %v", err)
	}
	var selector selectorRecord
	if err := json.Unmarshal(contents, &selector); err != nil {
		t.Fatalf("decode selector: %v", err)
	}
	return selector
}

func assertReleaseFiles(t *testing.T, harness *transactionHarness, decision decision) {
	t.Helper()
	releasePath := filepath.Join(harness.root, decision.role, releasesDirectory, decision.releaseID)
	for _, file := range decision.files {
		path := filepath.Join(releasePath, file.InstallName)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat installed file %s: %v", file.InstallName, err)
		}
		var stat unix.Stat_t
		if err := unix.Stat(path, &stat); err != nil {
			t.Fatalf("inspect installed file %s: %v", file.InstallName, err)
		}
		if info.Mode().Perm() != file.Mode.Perm() || stat.Nlink != 1 || stat.Uid != harness.uid || stat.Gid != harness.gid {
			t.Fatalf("installed file %s metadata = mode %o links %d owner %d:%d", file.InstallName, info.Mode().Perm(), stat.Nlink, stat.Uid, stat.Gid)
		}
	}
	receipt, err := os.Stat(filepath.Join(releasePath, receiptFileName))
	if err != nil || receipt.Mode().Perm() != 0o600 {
		t.Fatalf("receipt metadata = %v, error = %v", receipt, err)
	}
}

func assertNoStageFiles(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(entry.Name(), ".stage") {
			return fmt.Errorf("stage residue at %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestFile(t *testing.T, path string, contents []byte, mode fs.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func testReleaseID(label string) string {
	digest := sha256.Sum256([]byte(label))
	return protocol.ID(digest).String()
}
