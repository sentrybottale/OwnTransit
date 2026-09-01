package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentrybottale/owntransit/internal/protocol"
	"github.com/sentrybottale/owntransit/internal/signing"
)

const candidateTestTimestamp = int64(1700000000)

func TestPublicKeyIDPrintsCanonicalParsedKeyIdentity(t *testing.T) {
	keys, err := signing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "release-public.pem")
	if err := os.WriteFile(path, keys.PublicPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := publicKeyIDCommand([]string{"--public-key", path}, &output); err != nil {
		t.Fatal(err)
	}
	if got, want := output.String(), keys.KeyID+"\n"; got != want {
		t.Fatalf("public-key-id output = %q, want %q", got, want)
	}
}

func TestManifestAuthenticatesTheInstallEntrypoint(t *testing.T) {
	var matches int
	for _, evidence := range manifestPackageEvidence() {
		if evidence.Name != "package-install-entrypoint" {
			continue
		}
		matches++
		if evidence.File != "packaging/scripts/install.sh" || evidence.Kind != "package-payload" {
			t.Fatalf("install entrypoint evidence = %+v", evidence)
		}
	}
	if matches != 1 {
		t.Fatalf("install entrypoint evidence count = %d, want 1", matches)
	}
}

func TestManifestAuthenticatesTheRelayBootstrapExchangeUnit(t *testing.T) {
	var matches int
	for _, evidence := range manifestPackageEvidence() {
		if evidence.Name != "systemd-relay-exchange" {
			continue
		}
		matches++
		if evidence.File != "packaging/systemd/owntransit-relay-exchange-template.service" || evidence.Kind != "package-payload" {
			t.Fatalf("relay bootstrap exchange unit evidence = %+v", evidence)
		}
	}
	if matches != 1 {
		t.Fatalf("relay bootstrap exchange unit evidence count = %d, want 1", matches)
	}
}

func TestCandidateInitCreatesStrictQualificationLedgerFromGit(t *testing.T) {
	repository := newCandidateTestRepository(t)
	output := filepath.Join(t.TempDir(), "candidate.json")
	var commandOutput bytes.Buffer
	arguments := validCandidateArguments(output)
	if err := candidateInitAt(arguments, &commandOutput, repository); err != nil {
		t.Fatalf("candidateInitAt: %v", err)
	}

	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		t.Fatal("candidate ledger does not have its canonical final newline")
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("candidate ledger mode = %04o, want 0600", got)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var ledger candidateLedger
	if err := decoder.Decode(&ledger); err != nil {
		t.Fatalf("decode candidate ledger: %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("candidate ledger has trailing JSON: %v", err)
	}
	commit := candidateTestGitOutput(t, repository, "rev-parse", "--verify", "HEAD^{commit}")
	if ledger.Schema != candidateLedgerSchema || ledger.Status != candidateLedgerStatus || ledger.Version != "0.1.0-rc.1" ||
		ledger.ReleaseSequence != 1 || ledger.PolicySequence != 1 || ledger.MinimumReleaseSequence != 1 || ledger.MinimumLifecycle != 1 ||
		ledger.SourceCommit != commit || ledger.SourceDateEpoch != candidateTestTimestamp {
		t.Fatalf("candidate ledger has wrong fixed metadata: %+v", ledger)
	}
	parsedID, err := protocol.ParseID(ledger.ReleaseID)
	if err != nil || parsedID == (protocol.ID{}) || parsedID.String() != ledger.ReleaseID {
		t.Fatalf("candidate release ID = %q, %v", ledger.ReleaseID, err)
	}
	canonical, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(encoded, canonical) {
		t.Fatal("candidate ledger is not canonical JSON")
	}
	if !strings.Contains(commandOutput.String(), ledger.ReleaseID) || !strings.Contains(commandOutput.String(), output) {
		t.Fatalf("candidate-init output does not identify its ledger: %q", commandOutput.String())
	}
}

func TestCandidateInitAcceptsStableVersion(t *testing.T) {
	repository := newCandidateTestRepository(t)
	output := filepath.Join(t.TempDir(), "candidate.json")
	arguments := replaceCandidateOption(validCandidateArguments(output), "--version", "1.0.0")
	if err := candidateInitAt(arguments, io.Discard, repository); err != nil {
		t.Fatalf("candidateInitAt stable version: %v", err)
	}

	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := parseCandidateLedger(encoded)
	if err != nil {
		t.Fatalf("parse stable candidate ledger: %v", err)
	}
	if ledger.Version != "1.0.0" {
		t.Fatalf("stable candidate version = %q, want 1.0.0", ledger.Version)
	}
}

func TestCandidateInitNeverOverwritesLedger(t *testing.T) {
	repository := newCandidateTestRepository(t)
	output := filepath.Join(t.TempDir(), "candidate.json")
	if err := candidateInitAt(validCandidateArguments(output), io.Discard, repository); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidateInitAt(validCandidateArguments(output), io.Discard, repository); err == nil || !strings.Contains(err.Error(), "output already exists") {
		t.Fatalf("second candidate-init error = %v", err)
	}
	after, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("candidate-init changed an existing ledger")
	}
}

func TestCandidateInitRejectsInvalidInputs(t *testing.T) {
	repository := newCandidateTestRepository(t)
	tests := []struct {
		name   string
		option string
		value  string
	}{
		{name: "leading major zero", option: "--version", value: "01.1.0-rc.1"},
		{name: "leading minor zero", option: "--version", value: "0.01.0-rc.1"},
		{name: "leading patch zero", option: "--version", value: "0.1.00-rc.1"},
		{name: "stable leading major zero", option: "--version", value: "01.1.0"},
		{name: "stable leading minor zero", option: "--version", value: "0.01.0"},
		{name: "stable leading patch zero", option: "--version", value: "0.1.00"},
		{name: "zero rc", option: "--version", value: "0.1.0-rc.0"},
		{name: "leading rc zero", option: "--version", value: "0.1.0-rc.01"},
		{name: "unsupported alpha prerelease", option: "--version", value: "0.1.0-alpha.1"},
		{name: "unsupported beta prerelease", option: "--version", value: "0.1.0-beta.1"},
		{name: "missing rc number", option: "--version", value: "0.1.0-rc"},
		{name: "extended rc prerelease", option: "--version", value: "0.1.0-rc.1.1"},
		{name: "build metadata", option: "--version", value: "0.1.0+build.1"},
		{name: "release sequence zero", option: "--release-sequence", value: "0"},
		{name: "policy sequence zero", option: "--policy-sequence", value: "0"},
		{name: "release floor zero", option: "--release-floor", value: "0"},
		{name: "lifecycle floor zero", option: "--lifecycle-floor", value: "0"},
		{name: "floor above release", option: "--release-floor", value: "2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "candidate.json")
			arguments := replaceCandidateOption(validCandidateArguments(output), test.option, test.value)
			if err := candidateInitAt(arguments, io.Discard, repository); err == nil {
				t.Fatal("invalid candidate inputs were accepted")
			}
			if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid candidate inputs created output: %v", err)
			}
		})
	}

	if err := candidateInitAt(validCandidateArguments("candidate.json"), io.Discard, repository); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative output error = %v", err)
	}
}

func TestCandidateInitRequiresCleanGitCommit(t *testing.T) {
	repository := newCandidateTestRepository(t)
	if err := os.WriteFile(filepath.Join(repository, "untracked"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "candidate.json")
	if err := candidateInitAt(validCandidateArguments(output), io.Discard, repository); err == nil || !strings.Contains(err.Error(), "completely clean") {
		t.Fatalf("dirty source error = %v", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dirty source created output: %v", err)
	}
}

func TestCandidateVerifyBindsCanonicalLedgerBundleAndPolicy(t *testing.T) {
	fixture := newCandidateVerifyFixture(t)
	var output bytes.Buffer
	if err := candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), &output); err != nil {
		t.Fatalf("candidateVerifyCommand: %v", err)
	}
	want := "verified qualification-only candidate version=0.1.0-rc.1 release_id=" + fixture.ledger.ReleaseID +
		" release_sequence=1 policy_sequence=1 minimum_release_sequence=1 minimum_lifecycle=1 source_commit=" + fixture.ledger.SourceCommit + " source_date_epoch=1700000000\n"
	if output.String() != want {
		t.Fatalf("candidate-verify output = %q, want %q", output.String(), want)
	}
}

func TestCandidateVerifyAcceptsStableVersion(t *testing.T) {
	fixture := newCandidateVerifyFixtureWithVersion(t, "1.0.0")
	var output bytes.Buffer
	if err := candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), &output); err != nil {
		t.Fatalf("candidateVerifyCommand stable version: %v", err)
	}
	want := "verified qualification-only candidate version=1.0.0 release_id=" + fixture.ledger.ReleaseID +
		" release_sequence=1 policy_sequence=1 minimum_release_sequence=1 minimum_lifecycle=1 source_commit=" + fixture.ledger.SourceCommit + " source_date_epoch=1700000000\n"
	if output.String() != want {
		t.Fatalf("stable candidate-verify output = %q, want %q", output.String(), want)
	}
}

func TestCandidateVerifyRejectsLedgerTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
	}{
		{name: "unknown field", mutate: func(value string) string { return strings.Replace(value, "}\n", ",\"extra\":true}\n", 1) }},
		{name: "duplicate field", mutate: func(value string) string {
			return strings.Replace(value, "\"status\":", "\"schema\":\"owntransit.release-candidate-ledger.v1\",\"status\":", 1)
		}},
		{name: "noncanonical whitespace", mutate: func(value string) string { return " " + value }},
		{name: "wrong status", mutate: func(value string) string { return strings.Replace(value, candidateLedgerStatus, "production", 1) }},
		{name: "unsupported prerelease", mutate: func(value string) string { return strings.Replace(value, "0.1.0-rc.1", "0.1.0-beta.1", 1) }},
		{name: "zero release ID", mutate: func(value string) string {
			return strings.Replace(value, candidateVerifyReleaseID(1), strings.Repeat("a", protocol.EncodedIDSize), 1)
		}},
		{name: "floor above sequence", mutate: func(value string) string {
			return strings.Replace(value, "\"minimum_release_sequence\":1", "\"minimum_release_sequence\":2", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCandidateVerifyFixture(t)
			encoded, err := os.ReadFile(fixture.candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(fixture.candidate, []byte(test.mutate(string(encoded))), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), io.Discard); err == nil {
				t.Fatal("tampered candidate ledger was accepted")
			}
		})
	}
}

func TestCandidateVerifyRejectsBuildInputTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(string) string
	}{
		{name: "version", mutate: func(value string) string {
			return strings.Replace(value, "version=0.1.0-rc.1", "version=0.1.0-rc.2", 1)
		}},
		{name: "unsupported prerelease", mutate: func(value string) string {
			return strings.Replace(value, "version=0.1.0-rc.1", "version=0.1.0-beta.1", 1)
		}},
		{name: "release ID", mutate: func(value string) string {
			return strings.Replace(value, candidateVerifyReleaseID(1), candidateVerifyReleaseID(2), 1)
		}},
		{name: "release sequence", mutate: func(value string) string {
			return strings.Replace(value, "release_sequence=1", "release_sequence=2", 1)
		}},
		{name: "source commit", mutate: func(value string) string {
			return replaceCandidateBuildInput(value, "source_commit", strings.Repeat("d", 40))
		}},
		{name: "source date", mutate: func(value string) string {
			return strings.Replace(value, "source_date_epoch=1700000000", "source_date_epoch=1700000001", 1)
		}},
		{name: "noncanonical sequence", mutate: func(value string) string {
			return strings.Replace(value, "release_sequence=1", "release_sequence=01", 1)
		}},
		{name: "invalid source digest", mutate: func(value string) string {
			return strings.Replace(value, strings.Repeat("c", 64), strings.Repeat("C", 64), 1)
		}},
		{name: "extra line", mutate: func(value string) string { return value + "extra=value\n" }},
		{name: "wrong order", mutate: func(value string) string {
			return strings.Replace(value, "version=0.1.0-rc.1\nrelease_id=", "release_id=", 1)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCandidateVerifyFixture(t)
			path := filepath.Join(fixture.bundle, "BUILD-INPUTS")
			encoded, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(test.mutate(string(encoded))), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), io.Discard); err == nil {
				t.Fatal("tampered BUILD-INPUTS was accepted")
			}
		})
	}
}

func TestCandidateVerifyBindsLedgerTimestampToCleanGitHead(t *testing.T) {
	fixture := newCandidateVerifyFixture(t)
	fixture.ledger.SourceDateEpoch++
	encoded, err := json.Marshal(fixture.ledger)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(fixture.candidate, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	buildPath := filepath.Join(fixture.bundle, "BUILD-INPUTS")
	buildInputs, err := os.ReadFile(buildPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := replaceCandidateBuildInput(string(buildInputs), "source_date_epoch", "1700000001")
	if err := os.WriteFile(buildPath, []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}
	err = candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "Git HEAD commit or timestamp") {
		t.Fatalf("source timestamp mismatch error = %v", err)
	}
}

func TestCandidateVerifyRejectsDirtySourceRoot(t *testing.T) {
	fixture := newCandidateVerifyFixture(t)
	if err := os.WriteFile(filepath.Join(fixture.source, "untracked"), []byte("dirty\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := candidateVerifyCommand(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "completely clean") {
		t.Fatalf("dirty source error = %v", err)
	}
}

func TestCandidateVerifyRequiresMatchingExplicitPolicyInputsAndCanonicalPaths(t *testing.T) {
	for _, option := range []string{"--policy-sequence", "--release-floor", "--lifecycle-floor"} {
		t.Run(option, func(t *testing.T) {
			fixture := newCandidateVerifyFixture(t)
			arguments := replaceCandidateOption(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), option, "2")
			if err := candidateVerifyCommand(arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "does not match") {
				t.Fatalf("mismatched %s error = %v", option, err)
			}
		})
	}
	fixture := newCandidateVerifyFixture(t)
	arguments := replaceCandidateOption(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), "--candidate", "candidate.json")
	if err := candidateVerifyCommand(arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative candidate path error = %v", err)
	}
	candidateLink := filepath.Join(filepath.Dir(fixture.candidate), "candidate-link.json")
	if err := os.Symlink(fixture.candidate, candidateLink); err != nil {
		t.Fatal(err)
	}
	arguments = replaceCandidateOption(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), "--candidate", candidateLink)
	if err := candidateVerifyCommand(arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlinked candidate path error = %v", err)
	}
	bundleLink := filepath.Join(filepath.Dir(fixture.bundle), "bundle-link")
	if err := os.Symlink(fixture.bundle, bundleLink); err != nil {
		t.Fatal(err)
	}
	arguments = replaceCandidateOption(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), "--bundle", bundleLink)
	if err := candidateVerifyCommand(arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlinked bundle path error = %v", err)
	}
	sourceLink := filepath.Join(filepath.Dir(fixture.source), "source-link")
	if err := os.Symlink(fixture.source, sourceLink); err != nil {
		t.Fatal(err)
	}
	arguments = replaceCandidateOption(validCandidateVerifyArguments(fixture.candidate, fixture.bundle, fixture.source), "--source-root", sourceLink)
	if err := candidateVerifyCommand(arguments, io.Discard); err == nil || !strings.Contains(err.Error(), "symlinked") {
		t.Fatalf("symlinked source path error = %v", err)
	}
}

type candidateVerifyFixture struct {
	candidate string
	bundle    string
	source    string
	ledger    candidateLedger
}

func newCandidateVerifyFixture(t *testing.T) candidateVerifyFixture {
	return newCandidateVerifyFixtureWithVersion(t, "0.1.0-rc.1")
}

func newCandidateVerifyFixtureWithVersion(t *testing.T, version string) candidateVerifyFixture {
	t.Helper()
	root := t.TempDir()
	source := newCandidateTestRepository(t)
	bundle := filepath.Join(root, "bundle")
	if err := os.Mkdir(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	ledger := candidateLedger{
		Schema: candidateLedgerSchema, Status: candidateLedgerStatus, Version: version,
		ReleaseID: candidateVerifyReleaseID(1), ReleaseSequence: 1, PolicySequence: 1,
		MinimumReleaseSequence: 1, MinimumLifecycle: 1,
		SourceCommit: candidateTestGitOutput(t, source, "rev-parse", "--verify", "HEAD^{commit}"), SourceDateEpoch: candidateTestTimestamp,
	}
	encoded, err := json.Marshal(ledger)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	candidate := filepath.Join(root, "candidate.json")
	if err := os.WriteFile(candidate, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	buildInputs := "version=" + version + "\n" +
		"release_id=" + ledger.ReleaseID + "\n" +
		"release_sequence=1\n" +
		"source_commit=" + ledger.SourceCommit + "\n" +
		"source_date_epoch=1700000000\n" +
		"source_manifest_sha256=" + strings.Repeat("c", 64) + "\n"
	if err := os.WriteFile(filepath.Join(bundle, "BUILD-INPUTS"), []byte(buildInputs), 0o644); err != nil {
		t.Fatal(err)
	}
	return candidateVerifyFixture{candidate: candidate, bundle: bundle, source: source, ledger: ledger}
}

func candidateVerifyReleaseID(first byte) string {
	var id protocol.ID
	id[0] = first
	return id.String()
}

func validCandidateVerifyArguments(candidate, bundle, source string) []string {
	return []string{
		"--candidate", candidate,
		"--bundle", bundle,
		"--source-root", source,
		"--policy-sequence", "1",
		"--release-floor", "1",
		"--lifecycle-floor", "1",
	}
}

func replaceCandidateBuildInput(value, name, replacement string) string {
	lines := strings.Split(value, "\n")
	prefix := name + "="
	for index, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[index] = prefix + replacement
			return strings.Join(lines, "\n")
		}
	}
	panic("candidate build input not found: " + name)
}

func validCandidateArguments(output string) []string {
	return []string{
		"--version", "0.1.0-rc.1",
		"--release-sequence", "1",
		"--policy-sequence", "1",
		"--release-floor", "1",
		"--lifecycle-floor", "1",
		"--out", output,
	}
}

func replaceCandidateOption(arguments []string, option, value string) []string {
	result := append([]string(nil), arguments...)
	for index := 0; index+1 < len(result); index += 2 {
		if result[index] == option {
			result[index+1] = value
			return result
		}
	}
	panic("candidate test option not found: " + option)
}

func newCandidateTestRepository(t *testing.T) string {
	t.Helper()
	repository := t.TempDir()
	candidateTestGit(t, repository, "init", "-q")
	candidateTestGit(t, repository, "config", "user.name", "OwnTransit Test")
	candidateTestGit(t, repository, "config", "user.email", "owntransit-test@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("qualification fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	candidateTestGit(t, repository, "add", "README.md")
	command := exec.Command("git", "-C", repository, "commit", "-q", "-m", "qualification candidate")
	command.Env = append(os.Environ(), "GIT_AUTHOR_DATE=@1700000000 +0000", "GIT_COMMITTER_DATE=@1700000000 +0000")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v: %s", err, output)
	}
	return repository
}

func candidateTestGit(t *testing.T, repository string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, output)
	}
}

func candidateTestGitOutput(t *testing.T, repository string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", repository}, arguments...)...)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(arguments, " "), err)
	}
	return strings.TrimSpace(string(output))
}

func TestReadBoundedUsesOnePrivateDescriptor(t *testing.T) {
	root := t.TempDir()
	key := filepath.Join(root, "release-key.pem")
	if err := os.WriteFile(key, []byte("private material\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBounded(key, 64, true)
	if err != nil || string(got) != "private material\n" {
		t.Fatalf("private descriptor read = %q, %v", got, err)
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(key, 64, true); err == nil {
		t.Fatal("group/world-readable private input was accepted")
	}
	if _, err := readBounded(key, 64, false); err != nil {
		t.Fatalf("public bounded input was rejected: %v", err)
	}
}

func TestReadBoundedRejectsLinksSpecialFilesAndBounds(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("bounded\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	hardlink := filepath.Join(root, "hardlink")
	if err := os.Link(source, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(source, 64, false); err == nil {
		t.Fatal("multiply linked input was accepted")
	}
	if err := os.Remove(hardlink); err != nil {
		t.Fatal(err)
	}

	symlink := filepath.Join(root, "symlink")
	if err := os.Symlink(source, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(symlink, 64, false); err == nil {
		t.Fatal("symlink input was accepted")
	}
	if _, err := readBounded(source, 3, false); err == nil {
		t.Fatal("oversized input was accepted")
	}

	directory := filepath.Join(root, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(directory, 64, false); err == nil {
		t.Fatal("directory input was accepted")
	}
}
