// releasectl is an offline build/release utility. It never downloads a
// manifest, discovers a "latest" version, publishes, installs, or touches
// endpoint/deployment credentials.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/release"
	"github.com/sentrybottale/owntransit/internal/signing"
	"github.com/sentrybottale/owntransit/internal/strictjson"
	"github.com/sentrybottale/owntransit/internal/wireprofile"
)

const (
	canonicalRepository      = "https://github.com/sentrybottale/owntransit"
	candidateLedgerSchema    = "owntransit.release-candidate-ledger.v1"
	candidateLedgerStatus    = "qualification-only"
	maximumCandidateVersion  = 128
	maximumCandidateTimeText = 10
	maximumCandidateLedger   = 16 << 10
	maximumBuildInputs       = 4 << 10
)

var candidateVersion = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.([1-9][0-9]*))?$`)

type metadata struct {
	bundle, version, releaseID, repository, commit, sourceManifest, goVersion, builderImage string
	sequence                                                                                uint64
	created                                                                                 int64
}

type candidateLedger struct {
	Schema                 string `json:"schema"`
	Status                 string `json:"status"`
	Version                string `json:"version"`
	ReleaseID              string `json:"release_id"`
	ReleaseSequence        uint64 `json:"release_sequence"`
	PolicySequence         uint64 `json:"policy_sequence"`
	MinimumReleaseSequence uint64 `json:"minimum_release_sequence"`
	MinimumLifecycle       uint64 `json:"minimum_lifecycle"`
	SourceCommit           string `json:"source_commit"`
	SourceDateEpoch        int64  `json:"source_date_epoch"`
}

type gitMetadata struct {
	Root      string
	Commit    string
	Timestamp int64
}

type candidateBuildInputs struct {
	Version              string
	ReleaseID            string
	ReleaseSequence      uint64
	SourceCommit         string
	SourceDateEpoch      int64
	SourceManifestSHA256 string
}

type stringList []string

func (values *stringList) String() string         { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error { *values = append(*values, value); return nil }

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "owntransit-release: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("command required: candidate-init, candidate-verify, public-key-id, evidence, manifest, sign-manifest, verify-bundle, policy, sign-policy, or verify-policy")
	}
	switch arguments[0] {
	case "candidate-init":
		return candidateInitCommand(arguments[1:], output)
	case "candidate-verify":
		return candidateVerifyCommand(arguments[1:], output)
	case "public-key-id":
		return publicKeyIDCommand(arguments[1:], output)
	case "evidence":
		return evidenceCommand(arguments[1:])
	case "manifest":
		return manifestCommand(arguments[1:])
	case "sign-manifest":
		return signManifestCommand(arguments[1:])
	case "verify-bundle":
		return verifyBundleCommand(arguments[1:], output)
	case "policy":
		return policyCommand(arguments[1:])
	case "sign-policy":
		return signPolicyCommand(arguments[1:])
	case "verify-policy":
		return verifyPolicyCommand(arguments[1:], output)
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func candidateVerifyCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("candidate-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath, bundlePath, sourceRoot := "", "", ""
	var policySequence, releaseFloor, lifecycleFloor uint64
	flags.StringVar(&candidatePath, "candidate", "", "absolute canonical candidate ledger")
	flags.StringVar(&bundlePath, "bundle", "", "absolute canonical bundle directory")
	flags.StringVar(&sourceRoot, "source-root", "", "absolute canonical clean Git root")
	flags.Uint64Var(&policySequence, "policy-sequence", 0, "expected policy sequence")
	flags.Uint64Var(&releaseFloor, "release-floor", 0, "expected release floor")
	flags.Uint64Var(&lifecycleFloor, "lifecycle-floor", 0, "expected lifecycle floor")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || candidatePath == "" || bundlePath == "" || sourceRoot == "" || policySequence == 0 || releaseFloor == 0 || lifecycleFloor == 0 {
		return errors.New("candidate-verify: candidate, bundle, source-root, and positive policy/floor inputs are required")
	}
	candidatePath, err := canonicalExistingFile(candidatePath)
	if err != nil {
		return fmt.Errorf("candidate-verify: candidate ledger: %w", err)
	}
	bundlePath, err = canonicalExistingDirectory(bundlePath)
	if err != nil {
		return fmt.Errorf("candidate-verify: bundle: %w", err)
	}
	sourceRoot, err = canonicalExistingDirectory(sourceRoot)
	if err != nil {
		return fmt.Errorf("candidate-verify: source root: %w", err)
	}
	ledgerBytes, err := readBounded(candidatePath, maximumCandidateLedger, false)
	if err != nil {
		return fmt.Errorf("candidate-verify: read candidate ledger: %w", err)
	}
	ledger, err := parseCandidateLedger(ledgerBytes)
	if err != nil {
		return err
	}
	if ledger.PolicySequence != policySequence || ledger.MinimumReleaseSequence != releaseFloor || ledger.MinimumLifecycle != lifecycleFloor {
		return errors.New("candidate-verify: explicit policy sequence or floor does not match the candidate ledger")
	}
	buildBytes, err := readBounded(filepath.Join(bundlePath, "BUILD-INPUTS"), maximumBuildInputs, false)
	if err != nil {
		return fmt.Errorf("candidate-verify: read BUILD-INPUTS: %w", err)
	}
	build, err := parseCandidateBuildInputs(buildBytes)
	if err != nil {
		return err
	}
	if build.Version != ledger.Version || build.ReleaseID != ledger.ReleaseID || build.ReleaseSequence != ledger.ReleaseSequence ||
		build.SourceCommit != ledger.SourceCommit || build.SourceDateEpoch != ledger.SourceDateEpoch {
		return errors.New("candidate-verify: BUILD-INPUTS does not match the candidate ledger")
	}
	git, err := discoverGitMetadata(sourceRoot)
	if err != nil {
		return fmt.Errorf("candidate-verify: source root: %w", err)
	}
	if git.Root != sourceRoot {
		return errors.New("candidate-verify: source-root must be the exact canonical Git root")
	}
	if git.Commit != ledger.SourceCommit || git.Timestamp != ledger.SourceDateEpoch {
		return errors.New("candidate-verify: clean Git HEAD commit or timestamp does not match the candidate ledger")
	}
	_, err = fmt.Fprintf(output, "verified qualification-only candidate version=%s release_id=%s release_sequence=%d policy_sequence=%d minimum_release_sequence=%d minimum_lifecycle=%d source_commit=%s source_date_epoch=%d\n",
		ledger.Version, ledger.ReleaseID, ledger.ReleaseSequence, ledger.PolicySequence, ledger.MinimumReleaseSequence, ledger.MinimumLifecycle, ledger.SourceCommit, ledger.SourceDateEpoch)
	return err
}

func parseCandidateLedger(encoded []byte) (candidateLedger, error) {
	var ledger candidateLedger
	if err := strictjson.Decode(encoded, &ledger); err != nil {
		return candidateLedger{}, fmt.Errorf("candidate-verify: candidate ledger: %w", err)
	}
	if err := validateCandidateLedger(ledger); err != nil {
		return candidateLedger{}, err
	}
	canonical, err := json.Marshal(ledger)
	if err != nil {
		return candidateLedger{}, fmt.Errorf("candidate-verify: encode candidate ledger: %w", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) {
		return candidateLedger{}, errors.New("candidate-verify: candidate ledger is not canonical JSON")
	}
	return ledger, nil
}

func validateCandidateLedger(ledger candidateLedger) error {
	if ledger.Schema != candidateLedgerSchema || ledger.Status != candidateLedgerStatus {
		return errors.New("candidate-verify: candidate ledger has the wrong schema or status")
	}
	if len(ledger.Version) == 0 || len(ledger.Version) > maximumCandidateVersion || !candidateVersion.MatchString(ledger.Version) {
		return errors.New("candidate-verify: candidate ledger has an invalid release version")
	}
	id, err := protocol.ParseID(ledger.ReleaseID)
	if err != nil || id == (protocol.ID{}) || id.String() != ledger.ReleaseID {
		return errors.New("candidate-verify: candidate ledger has an invalid release ID")
	}
	if ledger.ReleaseSequence == 0 || ledger.PolicySequence == 0 || ledger.MinimumReleaseSequence == 0 || ledger.MinimumLifecycle == 0 ||
		ledger.SourceDateEpoch <= 0 || ledger.SourceDateEpoch > 9999999999 {
		return errors.New("candidate-verify: candidate ledger has a nonpositive sequence, floor, or source time")
	}
	if ledger.MinimumReleaseSequence > ledger.ReleaseSequence {
		return errors.New("candidate-verify: candidate release floor exceeds its release sequence")
	}
	if !validCandidateCommit(ledger.SourceCommit) {
		return errors.New("candidate-verify: candidate ledger has an invalid source commit")
	}
	return nil
}

func parseCandidateBuildInputs(encoded []byte) (candidateBuildInputs, error) {
	lines := strings.Split(string(encoded), "\n")
	if len(lines) != 7 || lines[6] != "" {
		return candidateBuildInputs{}, errors.New("candidate-verify: BUILD-INPUTS must contain exactly six newline-terminated lines")
	}
	expected := []string{"version", "release_id", "release_sequence", "source_commit", "source_date_epoch", "source_manifest_sha256"}
	values := make([]string, len(expected))
	for index, name := range expected {
		prefix := name + "="
		if !strings.HasPrefix(lines[index], prefix) || len(lines[index]) == len(prefix) {
			return candidateBuildInputs{}, fmt.Errorf("candidate-verify: BUILD-INPUTS line %d must be %s", index+1, prefix+"VALUE")
		}
		values[index] = strings.TrimPrefix(lines[index], prefix)
	}
	releaseID, err := protocol.ParseID(values[1])
	if err != nil || releaseID == (protocol.ID{}) || releaseID.String() != values[1] {
		return candidateBuildInputs{}, errors.New("candidate-verify: BUILD-INPUTS release ID is invalid")
	}
	releaseSequence, err := strconv.ParseUint(values[2], 10, 64)
	if err != nil || releaseSequence == 0 || strconv.FormatUint(releaseSequence, 10) != values[2] {
		return candidateBuildInputs{}, errors.New("candidate-verify: BUILD-INPUTS release sequence is invalid")
	}
	sourceDateEpoch, err := strconv.ParseInt(values[4], 10, 64)
	if err != nil || sourceDateEpoch <= 0 || sourceDateEpoch > 9999999999 || strconv.FormatInt(sourceDateEpoch, 10) != values[4] {
		return candidateBuildInputs{}, errors.New("candidate-verify: BUILD-INPUTS source date epoch is invalid")
	}
	if !candidateVersion.MatchString(values[0]) || len(values[0]) > maximumCandidateVersion || !validCandidateCommit(values[3]) || !validCandidateSHA256(values[5]) {
		return candidateBuildInputs{}, errors.New("candidate-verify: BUILD-INPUTS version, commit, or source manifest digest is invalid")
	}
	return candidateBuildInputs{
		Version: values[0], ReleaseID: values[1], ReleaseSequence: releaseSequence,
		SourceCommit: values[3], SourceDateEpoch: sourceDateEpoch, SourceManifestSHA256: values[5],
	}, nil
}

func validCandidateSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func canonicalExistingFile(path string) (string, error) {
	canonical, err := canonicalExistingPath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("path must identify an existing regular non-symlink file")
	}
	return canonical, nil
}

func canonicalExistingDirectory(path string) (string, error) {
	canonical, err := canonicalExistingPath(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(canonical)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path must identify an existing non-symlink directory")
	}
	return canonical, nil
}

func canonicalExistingPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || path == string(filepath.Separator) || filepath.Clean(path) != path {
		return "", errors.New("path must be absolute, canonical, and non-root")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	if resolved != path {
		return "", errors.New("path must contain no symlinked component")
	}
	return resolved, nil
}

func publicKeyIDCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("public-key-id", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyPath := ""
	flags.StringVar(&keyPath, "public-key", "", "canonical Ed25519 public-key PEM")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || keyPath == "" {
		return errors.New("public-key-id: public-key is required")
	}
	keyBytes, err := readBounded(keyPath, 64<<10, false)
	if err != nil {
		return fmt.Errorf("public-key-id: read public key: %w", err)
	}
	key, err := signing.ParsePublic(keyBytes)
	if err != nil {
		return fmt.Errorf("public-key-id: %w", err)
	}
	_, err = fmt.Fprintln(output, signing.KeyID(key))
	return err
}

func candidateInitCommand(arguments []string, output io.Writer) error {
	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("candidate-init: determine working directory: %w", err)
	}
	return candidateInitAt(arguments, output, workingDirectory)
}

func candidateInitAt(arguments []string, output io.Writer, workingDirectory string) error {
	flags := flag.NewFlagSet("candidate-init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	version, out := "", ""
	var releaseSequence, policySequence, releaseFloor, lifecycleFloor uint64
	flags.StringVar(&version, "version", "", "immutable release version")
	flags.Uint64Var(&releaseSequence, "release-sequence", 0, "monotonic release sequence")
	flags.Uint64Var(&policySequence, "policy-sequence", 0, "monotonic policy sequence")
	flags.Uint64Var(&releaseFloor, "release-floor", 0, "minimum release sequence")
	flags.Uint64Var(&lifecycleFloor, "lifecycle-floor", 0, "minimum lifecycle")
	flags.StringVar(&out, "out", "", "absolute new qualification ledger")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("candidate-init: unexpected positional argument")
	}
	if len(version) == 0 || len(version) > maximumCandidateVersion || !candidateVersion.MatchString(version) {
		return errors.New("candidate-init: version must be MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-rc.N with canonical nonnegative components and, when present, a positive N")
	}
	if releaseSequence == 0 || policySequence == 0 || releaseFloor == 0 || lifecycleFloor == 0 {
		return errors.New("candidate-init: release sequence, policy sequence, release floor, and lifecycle floor must be positive")
	}
	if releaseFloor > releaseSequence {
		return errors.New("candidate-init: release floor cannot exceed the candidate release sequence")
	}
	canonicalOut, err := canonicalNewOutput(out)
	if err != nil {
		return fmt.Errorf("candidate-init: %w", err)
	}
	if _, err := os.Lstat(canonicalOut); err == nil {
		return errors.New("candidate-init: output already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("candidate-init: inspect output: %w", err)
	}

	git, err := discoverGitMetadata(workingDirectory)
	if err != nil {
		return fmt.Errorf("candidate-init: %w", err)
	}
	releaseID, err := newNonzeroReleaseID()
	if err != nil {
		return fmt.Errorf("candidate-init: generate release ID: %w", err)
	}
	ledger := candidateLedger{
		Schema:                 candidateLedgerSchema,
		Status:                 candidateLedgerStatus,
		Version:                version,
		ReleaseID:              releaseID,
		ReleaseSequence:        releaseSequence,
		PolicySequence:         policySequence,
		MinimumReleaseSequence: releaseFloor,
		MinimumLifecycle:       lifecycleFloor,
		SourceCommit:           git.Commit,
		SourceDateEpoch:        git.Timestamp,
	}
	encoded, err := json.Marshal(ledger)
	if err != nil {
		return fmt.Errorf("candidate-init: encode ledger: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writePrivateNew(canonicalOut, encoded); err != nil {
		return fmt.Errorf("candidate-init: create ledger: %w", err)
	}
	_, err = fmt.Fprintf(output, "created qualification-only candidate %s release %s sequence %d: %s\n", version, releaseID, releaseSequence, canonicalOut)
	return err
}

func canonicalNewOutput(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) || path == string(filepath.Separator) {
		return "", errors.New("output must be an absolute non-root path")
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || strings.ContainsAny(base, "\r\n\x00") {
		return "", errors.New("output has an invalid basename")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("resolve output parent: %w", err)
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", errors.New("output parent must be an existing directory")
	}
	canonical := filepath.Join(parent, base)
	if canonical != path {
		return "", errors.New("output path must be canonical and contain no symlinked parent")
	}
	return canonical, nil
}

func discoverGitMetadata(workingDirectory string) (gitMetadata, error) {
	rootText, err := runGit(workingDirectory, "rev-parse", "--show-toplevel")
	if err != nil {
		return gitMetadata{}, fmt.Errorf("locate Git root: %w", err)
	}
	if rootText == "" || strings.ContainsRune(rootText, '\n') || !filepath.IsAbs(rootText) || filepath.Clean(rootText) != rootText {
		return gitMetadata{}, errors.New("Git root is not a canonical absolute directory")
	}
	root, err := filepath.EvalSymlinks(rootText)
	if err != nil || root != rootText {
		return gitMetadata{}, errors.New("Git root is not a canonical absolute directory")
	}
	status, err := runGit(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return gitMetadata{}, fmt.Errorf("inspect source tree: %w", err)
	}
	if status != "" {
		return gitMetadata{}, errors.New("source tree must be completely clean")
	}
	commit, err := runGit(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || !validCandidateCommit(commit) {
		return gitMetadata{}, errors.New("Git HEAD is not a canonical commit")
	}
	timestampText, err := runGit(root, "show", "-s", "--format=%ct", commit)
	if err != nil || len(timestampText) == 0 || len(timestampText) > maximumCandidateTimeText {
		return gitMetadata{}, errors.New("Git commit timestamp is invalid")
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil || timestamp <= 0 {
		return gitMetadata{}, errors.New("Git commit timestamp is invalid")
	}
	finalCommit, err := runGit(root, "rev-parse", "--verify", "HEAD^{commit}")
	if err != nil || finalCommit != commit {
		return gitMetadata{}, errors.New("Git HEAD changed while its identity was sampled")
	}
	finalStatus, err := runGit(root, "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return gitMetadata{}, fmt.Errorf("reinspect source tree: %w", err)
	}
	if finalStatus != "" {
		return gitMetadata{}, errors.New("source tree changed while its identity was sampled")
	}
	return gitMetadata{Root: root, Commit: commit, Timestamp: timestamp}, nil
}

func validCandidateCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func runGit(directory string, arguments ...string) (string, error) {
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	command.Env = []string{
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_OPTIONAL_LOCKS=0",
		"LC_ALL=C",
		"PATH=" + os.Getenv("PATH"),
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(arguments, " "), err, strings.TrimSpace(stderr.String()))
	}
	value := strings.TrimSuffix(stdout.String(), "\n")
	if strings.ContainsAny(value, "\r\x00") {
		return "", errors.New("Git returned an invalid value")
	}
	return value, nil
}

func newNonzeroReleaseID() (string, error) {
	for attempts := 0; attempts < 8; attempts++ {
		id, err := protocol.NewID()
		if err != nil {
			return "", err
		}
		if id != (protocol.ID{}) {
			return id.String(), nil
		}
	}
	return "", errors.New("random source repeatedly returned the zero ID")
}

func writePrivateNew(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := parent.Sync()
	closeErr := parent.Close()
	if syncErr != nil {
		return syncErr
	}
	if closeErr != nil {
		return closeErr
	}
	ok = true
	return nil
}

func metadataFlags(name string, arguments []string) (metadata, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var value metadata
	flags.StringVar(&value.bundle, "bundle", "", "absolute protected staging tree")
	flags.StringVar(&value.version, "version", "", "release version")
	flags.StringVar(&value.releaseID, "release-id", "", "canonical 52-character release ID")
	flags.Uint64Var(&value.sequence, "sequence", 0, "monotonic release sequence")
	flags.Int64Var(&value.created, "created-unix", 0, "SOURCE_DATE_EPOCH")
	flags.StringVar(&value.repository, "repository", canonicalRepository, "canonical source repository")
	flags.StringVar(&value.commit, "source-commit", "", "source commit")
	flags.StringVar(&value.sourceManifest, "source-manifest-sha256", "", "source manifest SHA-256")
	flags.StringVar(&value.goVersion, "go-version", "", "Go toolchain version")
	flags.StringVar(&value.builderImage, "builder-image", "", "digest-addressed builder image")
	if err := flags.Parse(arguments); err != nil {
		return metadata{}, err
	}
	if flags.NArg() != 0 {
		return metadata{}, errors.New("unexpected positional argument")
	}
	if value.bundle == "" || value.version == "" || value.releaseID == "" || value.sequence == 0 || value.created <= 0 || value.commit == "" || value.sourceManifest == "" || value.goVersion == "" || value.builderImage == "" {
		return metadata{}, errors.New("complete bundle, release, source and toolchain metadata is required")
	}
	if value.repository != canonicalRepository {
		return metadata{}, errors.New("repository must be the canonical OwnTransit URL")
	}
	return value, nil
}

func manifestSkeleton(value metadata) (release.Manifest, error) {
	artifacts := release.ArtifactMatrix()
	paths := make([]string, len(artifacts))
	for index := range artifacts {
		paths[index] = artifacts[index].File
	}
	measurements, err := release.MeasureBundleFiles(value.bundle, paths)
	if err != nil {
		return release.Manifest{}, err
	}
	for index := range artifacts {
		measurement := measurements[artifacts[index].File]
		artifacts[index].SHA256, artifacts[index].Size = measurement.SHA256, measurement.Size
	}
	return release.Manifest{
		Schema: release.ManifestSchema, Product: "owntransit", Version: value.version,
		ReleaseID: value.releaseID, Sequence: value.sequence, CreatedUnix: value.created,
		Protocol: wireprofile.LegacyV1Protocol, License: "Apache-2.0", MinimumLifecycle: 1,
		Source:    release.Source{Repository: value.repository, Commit: value.commit, ManifestSHA256: value.sourceManifest},
		Toolchain: release.Toolchain{GoVersion: value.goVersion, BuilderImage: value.builderImage},
		Artifacts: artifacts,
	}, nil
}

func evidenceCommand(arguments []string) error {
	value, err := metadataFlags("evidence", arguments)
	if err != nil {
		return err
	}
	manifest, err := manifestSkeleton(value)
	if err != nil {
		return err
	}
	finalEvidenceDir := filepath.Join(value.bundle, "evidence")
	if _, err := os.Lstat(finalEvidenceDir); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence destination already exists")
	}
	evidenceDir, err := os.MkdirTemp(value.bundle, ".evidence-")
	if err != nil {
		return fmt.Errorf("create private evidence staging directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(evidenceDir)
		}
	}()
	if err := os.Chmod(evidenceDir, 0o755); err != nil {
		return err
	}
	packages, licenses, err := dependencyEvidence(value.goVersion)
	if err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		relationships := []release.SPDXRelationship{{SPDXElementID: release.SPDXDocumentID, RelationshipType: "DESCRIBES", RelatedSPDXElement: release.SPDXArtifactID}}
		for _, pkg := range packages {
			relationships = append(relationships, release.SPDXRelationship{SPDXElementID: pkg.SPDXID, RelationshipType: "BUILD_DEPENDENCY_OF", RelatedSPDXElement: release.SPDXArtifactID})
		}
		document := release.SPDXDocument{
			SPDXVersion: release.SPDXVersion, DataLicense: release.SPDXDataLicense, SPDXID: release.SPDXDocumentID,
			Name:              "owntransit-" + artifact.Name,
			DocumentNamespace: "https://spdx.org/spdxdocs/owntransit-" + manifest.ReleaseID + "-" + artifact.Name,
			CreationInfo:      release.SPDXCreationInfo{Created: time.Unix(manifest.CreatedUnix, 0).UTC().Format(time.RFC3339), Creators: []string{release.EvidenceToolCreator}},
			Files:             []release.SPDXFile{{FileName: artifact.File, SPDXID: release.SPDXArtifactID, Checksums: []release.SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: artifact.SHA256}}, LicenseConcluded: "NOASSERTION", CopyrightText: "NOASSERTION"}},
			Packages:          packages,
			Relationships:     relationships,
		}
		encoded, err := release.EncodeSPDX(document, manifest, artifact)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(evidenceDir, artifact.File[strings.LastIndex(artifact.File, "/")+1:]+".spdx.json"), encoded, 0o644); err != nil {
			return err
		}
	}
	if err := writeNew(filepath.Join(evidenceDir, "THIRD_PARTY_LICENSES.txt"), licenses, 0o644); err != nil {
		return err
	}
	provenance := release.Provenance{
		Schema: release.ProvenanceSchema, Product: manifest.Product, Version: manifest.Version, ReleaseID: manifest.ReleaseID,
		Sequence: manifest.Sequence, CreatedUnix: manifest.CreatedUnix, Protocol: manifest.Protocol, License: manifest.License,
		Source: manifest.Source, Toolchain: manifest.Toolchain, BuildProfile: release.BuildProfile,
		SourceDateEpoch: manifest.CreatedUnix, CGOEnabled: false, Trimpath: true, BuildVCS: false,
	}
	for _, artifact := range manifest.Artifacts {
		provenance.Subjects = append(provenance.Subjects, release.ProvenanceSubject{Name: artifact.Name, File: artifact.File, SHA256: artifact.SHA256, Size: artifact.Size})
	}
	encoded, err := release.EncodeProvenance(provenance, manifest)
	if err != nil {
		return err
	}
	if err := writeNew(filepath.Join(evidenceDir, "PROVENANCE.json"), encoded, 0o644); err != nil {
		return err
	}
	if err := os.Rename(evidenceDir, finalEvidenceDir); err != nil {
		return fmt.Errorf("activate complete evidence directory: %w", err)
	}
	complete = true
	return nil
}

func manifestCommand(arguments []string) error {
	value, err := metadataFlags("manifest", arguments)
	if err != nil {
		return err
	}
	manifest, err := manifestSkeleton(value)
	if err != nil {
		return err
	}
	evidence := manifestPackageEvidence()
	for _, artifact := range manifest.Artifacts {
		base := artifact.File[strings.LastIndex(artifact.File, "/")+1:]
		evidence = append(evidence, release.Evidence{Name: artifact.SBOM, File: "evidence/" + base + ".spdx.json", Kind: "sbom"})
	}
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].Name < evidence[j].Name })
	paths := make([]string, len(evidence))
	for index := range evidence {
		paths[index] = evidence[index].File
	}
	measurements, err := release.MeasureBundleFiles(value.bundle, paths)
	if err != nil {
		return err
	}
	for index := range evidence {
		evidence[index].SHA256 = measurements[evidence[index].File].SHA256
		evidence[index].Size = measurements[evidence[index].File].Size
	}
	manifest.Evidence = evidence
	encoded, err := release.Encode(manifest)
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(value.bundle, "RELEASE-MANIFEST.json"), encoded, 0o644)
}

func manifestPackageEvidence() []release.Evidence {
	return []release.Evidence{
		{Name: "package-install-entrypoint", File: "packaging/scripts/install.sh", Kind: "package-payload"},
		{Name: "package-install-linux", File: "packaging/scripts/install-linux.sh", Kind: "package-payload"},
		{Name: "package-install-macos", File: "packaging/scripts/install-macos.sh", Kind: "package-payload"},
		{Name: "package-uninstall-linux", File: "packaging/scripts/uninstall-linux.sh", Kind: "package-payload"},
		{Name: "package-uninstall-macos", File: "packaging/scripts/uninstall-macos.sh", Kind: "package-payload"},
		{Name: "project-license", File: "LICENSE", Kind: "project-license"},
		{Name: "provenance", File: "evidence/PROVENANCE.json", Kind: "provenance"},
		{Name: "systemd-connector", File: "packaging/systemd/owntransit-connector.service", Kind: "package-payload"},
		{Name: "systemd-relay", File: "packaging/systemd/owntransit-relay.service", Kind: "package-payload"},
		{Name: "systemd-relay-exchange", File: "packaging/systemd/owntransit-relay-exchange-template.service", Kind: "package-payload"},
		{Name: "third-party-licenses", File: "evidence/THIRD_PARTY_LICENSES.txt", Kind: "licenses"},
	}
}

func signManifestCommand(arguments []string) error {
	flags := flag.NewFlagSet("sign-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath, keyPath, out := "", "", ""
	flags.StringVar(&manifestPath, "manifest", "", "canonical manifest")
	flags.StringVar(&keyPath, "release-private-key", "", "offline release key")
	flags.StringVar(&out, "out", "", "new signature file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || manifestPath == "" || keyPath == "" || out == "" {
		return errors.New("manifest, release-private-key and out are required")
	}
	manifestBytes, err := readBounded(manifestPath, release.MaxManifestSize, false)
	if err != nil {
		return err
	}
	manifest, err := release.ParseManifest(manifestBytes)
	if err != nil {
		return err
	}
	keyBytes, err := readBounded(keyPath, 64<<10, true)
	if err != nil {
		return err
	}
	defer wipe(keyBytes)
	key, err := signing.ParsePrivate(keyBytes)
	if err != nil {
		return err
	}
	reencoded, signature, err := release.Sign(manifest, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(reencoded, manifestBytes) {
		return errors.New("signer canonicalization mismatch")
	}
	return writeNew(out, signature, 0o644)
}

func verifyBundleCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundle, manifestPath, signaturePath, keyPath := "", "", "", ""
	flags.StringVar(&bundle, "bundle", "", "absolute bundle")
	flags.StringVar(&manifestPath, "manifest", "", "manifest")
	flags.StringVar(&signaturePath, "signature", "", "signature")
	flags.StringVar(&keyPath, "release-public-key", "", "trusted release key")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || bundle == "" || manifestPath == "" || signaturePath == "" || keyPath == "" {
		return errors.New("bundle, manifest, signature and release-public-key are required")
	}
	manifestBytes, err := readBounded(manifestPath, release.MaxManifestSize, false)
	if err != nil {
		return err
	}
	signatureBytes, err := readBounded(signaturePath, 16<<10, false)
	if err != nil {
		return err
	}
	keyBytes, err := readBounded(keyPath, 64<<10, false)
	if err != nil {
		return err
	}
	key, err := signing.ParsePublic(keyBytes)
	if err != nil {
		return err
	}
	verified, err := release.VerifyBundle(bundle, manifestBytes, signatureBytes, key)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "verified release %s sequence %d key %s\n", verified.Manifest.ReleaseID, verified.Manifest.Sequence, signing.KeyID(key))
	return err
}

func policyCommand(arguments []string) error {
	flags := flag.NewFlagSet("policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out, keyPath := "", ""
	var sequence, releaseFloor, lifecycleFloor uint64
	var created int64
	var tombstones stringList
	flags.StringVar(&out, "out", "", "new policy")
	flags.StringVar(&keyPath, "release-public-key", "", "authorized release key")
	flags.Uint64Var(&sequence, "sequence", 0, "policy sequence")
	flags.Int64Var(&created, "created-unix", 0, "creation time")
	flags.Uint64Var(&releaseFloor, "release-floor", 0, "minimum release sequence")
	flags.Uint64Var(&lifecycleFloor, "lifecycle-floor", 0, "minimum lifecycle")
	flags.Var(&tombstones, "tombstone", "cumulative release ID tombstone")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || out == "" || keyPath == "" || sequence == 0 || created <= 0 || releaseFloor == 0 || lifecycleFloor == 0 {
		return errors.New("complete policy inputs are required")
	}
	sort.Strings(tombstones)
	keyBytes, err := readBounded(keyPath, 64<<10, false)
	if err != nil {
		return err
	}
	key, err := signing.ParsePublic(keyBytes)
	if err != nil {
		return err
	}
	policy := release.Policy{Schema: release.PolicySchema, Product: "owntransit", Sequence: sequence, CreatedUnix: created, ReleaseKeyID: signing.KeyID(key), MinimumReleaseSequence: releaseFloor, MinimumLifecycle: lifecycleFloor, TombstonedReleaseIDs: tombstones}
	encoded, err := release.EncodePolicy(policy)
	if err != nil {
		return err
	}
	return writeNew(out, encoded, 0o644)
}

func signPolicyCommand(arguments []string) error {
	flags := flag.NewFlagSet("sign-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath, keyPath, out := "", "", ""
	flags.StringVar(&policyPath, "policy", "", "canonical policy")
	flags.StringVar(&keyPath, "policy-private-key", "", "offline policy key")
	flags.StringVar(&out, "out", "", "new signature")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || policyPath == "" || keyPath == "" || out == "" {
		return errors.New("policy, policy-private-key and out are required")
	}
	policyBytes, err := readBounded(policyPath, release.MaxPolicySize, false)
	if err != nil {
		return err
	}
	policy, err := release.ParsePolicy(policyBytes)
	if err != nil {
		return err
	}
	keyBytes, err := readBounded(keyPath, 64<<10, true)
	if err != nil {
		return err
	}
	defer wipe(keyBytes)
	key, err := signing.ParsePrivate(keyBytes)
	if err != nil {
		return err
	}
	reencoded, signature, err := release.SignPolicy(policy, key)
	if err != nil {
		return err
	}
	if !bytes.Equal(reencoded, policyBytes) {
		return errors.New("policy signer canonicalization mismatch")
	}
	return writeNew(out, signature, 0o644)
}

func verifyPolicyCommand(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("verify-policy", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	policyPath, signaturePath, keyPath := "", "", ""
	var high, releaseFloor, lifecycleFloor uint64
	var tombstones stringList
	flags.StringVar(&policyPath, "policy", "", "policy")
	flags.StringVar(&signaturePath, "signature", "", "signature")
	flags.StringVar(&keyPath, "policy-public-key", "", "trusted policy key")
	flags.Uint64Var(&high, "anchor-policy-sequence", 0, "anchor high water")
	flags.Uint64Var(&releaseFloor, "anchor-release-floor", 0, "anchor release floor")
	flags.Uint64Var(&lifecycleFloor, "anchor-lifecycle-floor", 0, "anchor lifecycle floor")
	flags.Var(&tombstones, "anchor-tombstone", "cumulative anchored tombstone")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || policyPath == "" || signaturePath == "" || keyPath == "" {
		return errors.New("policy, signature and policy-public-key are required")
	}
	sort.Strings(tombstones)
	policyBytes, err := readBounded(policyPath, release.MaxPolicySize, false)
	if err != nil {
		return err
	}
	signatureBytes, err := readBounded(signaturePath, 16<<10, false)
	if err != nil {
		return err
	}
	keyBytes, err := readBounded(keyPath, 64<<10, false)
	if err != nil {
		return err
	}
	key, err := signing.ParsePublic(keyBytes)
	if err != nil {
		return err
	}
	verified, err := release.VerifyPolicyAdvance(policyBytes, signatureBytes, key, release.PolicyAnchor{HighestPolicySequence: high, MinimumReleaseSequence: releaseFloor, MinimumLifecycle: lifecycleFloor, TombstonedReleaseIDs: tombstones})
	if err != nil {
		return err
	}
	next, err := verified.NextAnchor()
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(struct {
		Schema     string   `json:"schema"`
		Highest    uint64   `json:"highest_policy_sequence"`
		Release    uint64   `json:"minimum_release_sequence"`
		Lifecycle  uint64   `json:"minimum_lifecycle"`
		Tombstones []string `json:"tombstoned_release_ids"`
	}{"owntransit.release-policy-anchor.v1", next.HighestPolicySequence, next.MinimumReleaseSequence, next.MinimumLifecycle, next.TombstonedReleaseIDs})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "%s\n", encoded)
	return err
}

type moduleDownload struct {
	Path, Version, Dir, Sum, GoModSum string
	Error                             *struct{ Err string }
}

type listedModule struct {
	Path, Version string
	Main          bool
	Replace       *listedModule
}

type listedPackage struct {
	Module *listedModule
}

var productionBuilds = []struct {
	goos, goarch string
	packages     []string
}{
	{"darwin", "arm64", []string{"./cmd/owntransit", "./cmd/owntransit-launcher", "./cmd/owntransitctl", "./cmd/owntransit-provision"}},
	{"linux", "amd64", []string{"./cmd/owntransit", "./cmd/owntransit-connector", "./cmd/owntransit-relay", "./cmd/owntransitctl", "./cmd/owntransit-provision"}},
	{"linux", "arm64", []string{"./cmd/owntransit", "./cmd/owntransit-connector", "./cmd/owntransit-relay", "./cmd/owntransitctl", "./cmd/owntransit-provision"}},
}

func dependencyEvidence(goVersion string) ([]release.SPDXPackage, []byte, error) {
	modules, err := productionModuleDownloads()
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Path+"@"+modules[i].Version < modules[j].Path+"@"+modules[j].Version
	})
	packages := []release.SPDXPackage{
		{Name: "Go standard library", SPDXID: "SPDXRef-Package-0000", VersionInfo: goVersion, DownloadLocation: "https://go.dev/", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "BSD-3-Clause", CopyrightText: "NOASSERTION", ExternalRefs: []release.SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: "pkg:golang/std@" + url.QueryEscape(goVersion)}}},
		{Name: release.BIP39PackageName, SPDXID: "SPDXRef-Package-0001", VersionInfo: release.BIP39PackageVersion, DownloadLocation: release.BIP39DownloadLocation, FilesAnalyzed: false, LicenseConcluded: "MIT", LicenseDeclared: "MIT", CopyrightText: release.BIP39CopyrightText, ExternalRefs: []release.SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: release.BIP39PackagePURL}}},
	}
	var licenses bytes.Buffer
	licenses.WriteString(release.LicenseEvidenceHeader)
	licenses.WriteString("\nComponent: Go standard library " + goVersion + "\n")
	gorootBytes, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return nil, nil, err
	}
	if err := appendLicenseFiles(&licenses, strings.TrimSpace(string(gorootBytes))); err != nil {
		return nil, nil, err
	}
	wordListNotice, err := readBounded("THIRD_PARTY_NOTICES.md", 64<<10, false)
	if err != nil {
		return nil, nil, fmt.Errorf("embedded word-list notice: %w", err)
	}
	licenses.WriteString("\nComponent: BIP-39 English word list\nFile: THIRD_PARTY_NOTICES.md\n---\n")
	licenses.Write(wordListNotice)
	if wordListNotice[len(wordListNotice)-1] != '\n' {
		licenses.WriteByte('\n')
	}
	licenses.WriteString("---\n")
	for index, module := range modules {
		id := "SPDXRef-Package-" + fmt.Sprintf("%04d", index+2)
		locator := "pkg:golang/" + url.PathEscape(module.Path) + "@" + url.QueryEscape(module.Version)
		packages = append(packages, release.SPDXPackage{Name: module.Path, SPDXID: id, VersionInfo: module.Version, DownloadLocation: "NOASSERTION", FilesAnalyzed: false, LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION", ExternalRefs: []release.SPDXExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: locator}}})
		licenses.WriteString("\nComponent: " + module.Path + " " + module.Version + "\nGo-Sum: " + module.Sum + "\nGo-Mod-Sum: " + module.GoModSum + "\n")
		if err := appendLicenseFiles(&licenses, module.Dir); err != nil {
			return nil, nil, fmt.Errorf("%s@%s: %w", module.Path, module.Version, err)
		}
	}
	return packages, licenses.Bytes(), nil
}

func productionModuleDownloads() ([]moduleDownload, error) {
	coordinates := make(map[string]struct{})
	for _, build := range productionBuilds {
		arguments := []string{"list", "-mod=readonly", "-buildvcs=false", "-deps", "-json"}
		arguments = append(arguments, build.packages...)
		command := exec.Command("go", arguments...)
		command.Env = goCommandEnvironment(build.goos, build.goarch, "")
		var stdout, stderr bytes.Buffer
		command.Stdout, command.Stderr = &stdout, &stderr
		if err := command.Run(); err != nil {
			return nil, fmt.Errorf("go list production dependencies for %s/%s: %w: %s", build.goos, build.goarch, err, strings.TrimSpace(stderr.String()))
		}
		decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
		for {
			var pkg listedPackage
			err := decoder.Decode(&pkg)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("decode go list production dependencies: %w", err)
			}
			if pkg.Module == nil || pkg.Module.Main {
				continue
			}
			if pkg.Module.Replace != nil {
				return nil, fmt.Errorf("production dependency %s uses a module replacement", pkg.Module.Path)
			}
			if pkg.Module.Path == "" || pkg.Module.Version == "" {
				return nil, errors.New("production dependency has incomplete module identity")
			}
			coordinates[pkg.Module.Path+"@"+pkg.Module.Version] = struct{}{}
		}
	}
	if len(coordinates) == 0 {
		return nil, errors.New("production dependency set is empty")
	}

	requested := make([]string, 0, len(coordinates))
	for coordinate := range coordinates {
		requested = append(requested, coordinate)
	}
	sort.Strings(requested)
	arguments := append([]string{"mod", "download", "-json"}, requested...)
	command := exec.Command("go", arguments...)
	command.Env = goCommandEnvironment("", "", "-mod=readonly")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("download production dependency evidence: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	modules := make([]moduleDownload, 0, len(requested))
	seen := make(map[string]struct{}, len(requested))
	for {
		var module moduleDownload
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode production dependency download: %w", err)
		}
		if module.Error != nil {
			return nil, errors.New(module.Error.Err)
		}
		coordinate := module.Path + "@" + module.Version
		if _, ok := coordinates[coordinate]; !ok {
			return nil, fmt.Errorf("download returned unexpected module %s", coordinate)
		}
		if _, duplicate := seen[coordinate]; duplicate {
			return nil, fmt.Errorf("download returned duplicate module %s", coordinate)
		}
		if module.Dir == "" || module.Sum == "" || module.GoModSum == "" {
			return nil, fmt.Errorf("download returned incomplete evidence for %s", coordinate)
		}
		seen[coordinate] = struct{}{}
		modules = append(modules, module)
	}
	if len(modules) != len(requested) {
		return nil, fmt.Errorf("download returned %d production modules, expected %d", len(modules), len(requested))
	}
	return modules, nil
}

func goCommandEnvironment(goos, goarch, goflags string) []string {
	environment := make([]string, 0, len(os.Environ())+5)
	for _, value := range os.Environ() {
		name := value
		if separator := strings.IndexByte(value, '='); separator >= 0 {
			name = value[:separator]
		}
		switch name {
		case "CGO_ENABLED", "GOOS", "GOARCH", "GOFLAGS", "GOWORK":
			continue
		}
		environment = append(environment, value)
	}
	environment = append(environment, "CGO_ENABLED=0", "GOWORK=off")
	if goos != "" {
		environment = append(environment, "GOOS="+goos)
	}
	if goarch != "" {
		environment = append(environment, "GOARCH="+goarch)
	}
	if goflags != "" {
		environment = append(environment, "GOFLAGS="+goflags)
	}
	return environment
}

func appendLicenseFiles(output *bytes.Buffer, directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	found := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		upper := strings.ToUpper(entry.Name())
		if !(strings.HasPrefix(upper, "LICENSE") || strings.HasPrefix(upper, "COPYING") || strings.HasPrefix(upper, "NOTICE") || strings.HasPrefix(upper, "PATENTS")) {
			continue
		}
		contents, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			return err
		}
		found = true
		output.WriteString("File: " + entry.Name() + "\n---\n")
		output.Write(contents)
		if len(contents) == 0 || contents[len(contents)-1] != '\n' {
			output.WriteByte('\n')
		}
		output.WriteString("---\n")
	}
	if !found {
		return errors.New("no top-level license evidence found")
	}
	return nil
}
func readBounded(path string, limit int, private bool) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("input size limit is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("input descriptor is invalid")
	}
	defer file.Close()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, err
	}
	mode := uint32(before.Mode)
	if mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Size <= 0 || before.Size > int64(limit) {
		return nil, errors.New("input is not a bounded regular file")
	}
	if private {
		permissions := mode & 0o7777
		if before.Uid != uint32(unix.Geteuid()) || permissions != 0o400 && permissions != 0o600 {
			return nil, errors.New("private key file must be owned by the effective user, single-linked, and mode 0400 or 0600")
		}
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) == 0 || len(data) > limit {
		return nil, errors.New("input changed or exceeded its size limit")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Mode != after.Mode || before.Uid != after.Uid || before.Nlink != after.Nlink || before.Size != after.Size || after.Size != int64(len(data)) {
		return nil, errors.New("input changed while being read")
	}
	return data, nil
}
func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}
func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
