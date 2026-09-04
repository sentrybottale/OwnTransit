#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

fail() {
  printf 'qualification-signature-test: %s\n' "$*" >&2
  exit 1
}

file_mode() {
  if test "$(uname -s)" = Darwin; then
    file_mode_raw=$(stat -f %p -- "$1") || return 1
    case "$file_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
    printf '%o\n' "$((0$file_mode_raw & 07777))"
  else
    stat -c '%a' -- "$1"
  fi
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-signature-test.XXXXXX") || fail "cannot create test workspace"
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve test workspace"
homebrew_style_tap=
homebrew_style_tap_created=0
cleanup() {
  if test "$homebrew_style_tap_created" -eq 1 && test -n "${OWNTRANSIT_HOMEBREW_BIN:-}"; then
    "$OWNTRANSIT_HOMEBREW_BIN" untap "$homebrew_style_tap" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

ssh-keygen -q -t ed25519 -N '' -C owntransit-test -f "$workspace/signing-key"
chmod 0600 "$workspace/signing-key"
key_type=$(awk '{print $1}' "$workspace/signing-key.pub")
key_data=$(awk '{print $2}' "$workspace/signing-key.pub")
printf 'owntransit-release %s %s\n' "$key_type" "$key_data" > "$workspace/release-allowed"
printf 'owntransit-source %s %s\n' "$key_type" "$key_data" > "$workspace/source-allowed"

mkdir "$workspace/staging" "$workspace/evidence"
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  artifacts/example' > "$workspace/staging/SHA256SUMS"

preflight_output=$("$project_root/packaging/macos/sign-checksums.sh" \
  --preflight-only \
  --signing-key "$workspace/signing-key")
test -z "$preflight_output" || fail "checksum signing preflight produced output"
test -z "$(find "$workspace" -name '*.sig' -print)" ||
  fail "checksum signing preflight created a signature"

expect_checksum_preflight_failure() {
  expected_message=$1
  rejected_key=$2
  if rejection_output=$("$project_root/packaging/macos/sign-checksums.sh" \
    --preflight-only --signing-key "$rejected_key" 2>&1); then
    fail "checksum signing preflight accepted a rejected key: $expected_message"
  fi
  printf '%s\n' "$rejection_output" | grep -Fq "$expected_message" ||
    fail "checksum signing preflight failed for the wrong reason: $rejection_output"
}

expect_checksum_key_failure() {
  expected_message=$1
  rejected_key=$2
  rejected_output=$3
  if rejection_output=$(SSH_AUTH_SOCK="$workspace/nonexistent-agent.sock" \
    SSH_ASKPASS="$workspace/nonexistent-askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY=owntransit-test \
    "$project_root/packaging/macos/sign-checksums.sh" \
      --subject "$workspace/staging/SHA256SUMS" \
      --signing-key "$rejected_key" \
      --allowed-signers "$workspace/release-allowed" \
      --signer owntransit-release \
      --output "$rejected_output" 2>&1); then
    fail "checksum signing helper accepted a rejected key: $expected_message"
  fi
  printf '%s\n' "$rejection_output" | grep -Fq "$expected_message" ||
    fail "checksum signing helper failed for the wrong reason: $rejection_output"
  test ! -e "$rejected_output" && test ! -L "$rejected_output" ||
    fail "checksum signing helper published output after rejecting a key"
}

"$project_root/packaging/macos/sign-checksums.sh" \
  --subject "$workspace/staging/SHA256SUMS" \
  --signing-key "$workspace/signing-key" \
  --allowed-signers "$workspace/release-allowed" \
  --signer owntransit-release \
  --output "$workspace/evidence/SHA256SUMS.sig" >/dev/null
test -s "$workspace/evidence/SHA256SUMS.sig" || fail "checksum signing helper produced no signature"
test ! -e "$workspace/staging/SHA256SUMS.sig" || fail "checksum signing helper polluted the staging tree"

cp "$workspace/signing-key.pub" "$workspace/public-as-private"
chmod 0600 "$workspace/public-as-private"
expect_checksum_key_failure \
  'signing key is not a readable OpenSSH private key' \
  "$workspace/public-as-private" \
  "$workspace/evidence/public-key.sig"

ssh-keygen -q -t rsa -b 2048 -N '' -C owntransit-rsa-test -f "$workspace/rsa-key"
chmod 0600 "$workspace/rsa-key"
expect_checksum_key_failure \
  'signing key must be an Ed25519 private key' \
  "$workspace/rsa-key" \
  "$workspace/evidence/rsa-key.sig"

cp "$workspace/signing-key" "$workspace/hardlinked-key"
ln "$workspace/hardlinked-key" "$workspace/hardlinked-key-alias"
expect_checksum_preflight_failure \
  'signing key must have exactly one hard link' \
  "$workspace/hardlinked-key"
expect_checksum_key_failure \
  'signing key must have exactly one hard link' \
  "$workspace/hardlinked-key" \
  "$workspace/evidence/hardlinked-key.sig"

cp "$workspace/signing-key" "$workspace/permissive-key"
chmod 0640 "$workspace/permissive-key"
expect_checksum_key_failure \
  'signing key mode must be 0400 or 0600' \
  "$workspace/permissive-key" \
  "$workspace/evidence/permissive-key.sig"

cp "$workspace/signing-key" "$workspace/special-mode-key"
chmod 1600 "$workspace/special-mode-key"
expect_checksum_key_failure \
  'signing key mode must be 0400 or 0600' \
  "$workspace/special-mode-key" \
  "$workspace/evidence/special-mode-key.sig"

cp "$workspace/signing-key" "$workspace/staging/embedded-key"
chmod 0600 "$workspace/staging/embedded-key"
expect_checksum_key_failure \
  'signing key must be outside the checksum staging tree' \
  "$workspace/staging/embedded-key" \
  "$workspace/evidence/staging-key.sig"

cp "$workspace/signing-key" "$workspace/evidence/embedded-key"
chmod 0600 "$workspace/evidence/embedded-key"
expect_checksum_key_failure \
  'signing key must be outside the output tree' \
  "$workspace/evidence/embedded-key" \
  "$workspace/evidence/output-key.sig"

if test "$(uname -s)" = Darwin; then
  mkdir -p "$workspace/writable-ancestor/key-vault"
  cp "$workspace/signing-key" "$workspace/writable-ancestor/key-vault/signing-key"
  chmod 0600 "$workspace/writable-ancestor/key-vault/signing-key"
  chmod 0770 "$workspace/writable-ancestor"
  expect_checksum_key_failure \
    'protected key ancestor is group- or world-writable' \
    "$workspace/writable-ancestor/key-vault/signing-key" \
    "$workspace/evidence/writable-ancestor.sig"

  mkdir -p "$workspace/special-mode-ancestor/key-vault"
  cp "$workspace/signing-key" "$workspace/special-mode-ancestor/key-vault/signing-key"
  chmod 0600 "$workspace/special-mode-ancestor/key-vault/signing-key"
  chmod 1700 "$workspace/special-mode-ancestor"
  expect_checksum_key_failure \
    'protected key ancestor has special or invalid mode bits' \
    "$workspace/special-mode-ancestor/key-vault/signing-key" \
    "$workspace/evidence/special-mode-ancestor.sig"

  mkdir -p "$workspace/acl-ancestor/key-vault"
  cp "$workspace/signing-key" "$workspace/acl-ancestor/key-vault/signing-key"
  chmod 0600 "$workspace/acl-ancestor/key-vault/signing-key"
  chmod +a 'everyone deny delete' "$workspace/acl-ancestor"
  expect_checksum_preflight_failure \
    'protected key ancestor has an extended ACL' \
    "$workspace/acl-ancestor/key-vault/signing-key"
  expect_checksum_key_failure \
    'protected key ancestor has an extended ACL' \
    "$workspace/acl-ancestor/key-vault/signing-key" \
    "$workspace/evidence/acl-ancestor.sig"
  chmod -N "$workspace/acl-ancestor"
fi

printf '%s\n' 'authenticated release checksum record' > "$workspace/subject"
subject_digest=$(shasum -a 256 "$workspace/subject" | awk '{print $1}')
ssh-keygen -q -Y sign -f "$workspace/signing-key" -n owntransit-release-v1 "$workspace/subject" >/dev/null
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$workspace/subject" --sha256 "$subject_digest" \
  --signature "$workspace/subject.sig" --allowed-signers "$workspace/release-allowed" \
  --signer owntransit-release --namespace owntransit-release-v1 >/dev/null

printf '%s\n' tampered >> "$workspace/subject"
if "$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$workspace/subject" --sha256 "$subject_digest" \
  --signature "$workspace/subject.sig" --allowed-signers "$workspace/release-allowed" \
  --signer owntransit-release --namespace owntransit-release-v1 >/dev/null 2>&1; then
  fail "tampered subject passed checksum/signature verification"
fi
sed -i.bak '$d' "$workspace/subject"
rm -f "$workspace/subject.bak"
if "$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$workspace/subject" --sha256 "$subject_digest" \
  --signature "$workspace/subject.sig" --allowed-signers "$workspace/release-allowed" \
  --signer wrong-release --namespace owntransit-release-v1 >/dev/null 2>&1; then
  fail "wrong signer identity passed verification"
fi

source_root="$workspace/source"
mkdir -p "$source_root/cmd/example" "$source_root/internal/example"
printf 'module example.invalid/owntransit\n\ngo 1.26\n' > "$source_root/go.mod"
: > "$source_root/go.sum"
printf 'package main\nfunc main() {}\n' > "$source_root/cmd/example/main.go"
printf 'package example\nconst Value = 1\n' > "$source_root/internal/example/example.go"
(
  cd "$source_root"
  find go.mod go.sum cmd internal -type f -print | LC_ALL=C sort |
    while IFS= read -r path; do shasum -a 256 "$path"; done
) > "$source_root/SOURCE-MANIFEST.txt"
ssh-keygen -q -Y sign -f "$workspace/signing-key" -n owntransit-source-v1 "$source_root/SOURCE-MANIFEST.txt" >/dev/null
"$project_root/packaging/homebrew/verify-source-tree.sh" \
  --source "$source_root" --allowed-signers "$workspace/source-allowed" \
  --signer owntransit-source >/dev/null
printf '\n' >> "$source_root/internal/example/example.go"
if "$project_root/packaging/homebrew/verify-source-tree.sh" \
  --source "$source_root" --allowed-signers "$workspace/source-allowed" \
  --signer owntransit-source >/dev/null 2>&1; then
  fail "tampered source tree passed signed-manifest verification"
fi

archive_source="$workspace/archive-source"
archive_output="$workspace/archive-output"
mkdir -p "$archive_source/cmd/example" "$archive_source/internal/example" "$archive_source/tools" "$archive_output"
printf 'module example.invalid/owntransit\n\ngo 1.26\n' > "$archive_source/go.mod"
: > "$archive_source/go.sum"
printf 'package main\nfunc main() {}\n' > "$archive_source/cmd/example/main.go"
printf 'package example\nconst Value = 1\n' > "$archive_source/internal/example/example.go"
printf '#!/bin/sh\nexit 0\n' > "$archive_source/tools/example.sh"
chmod 0755 "$archive_source/tools/example.sh"
git -C "$archive_source" init -q
git -C "$archive_source" config user.name OwnTransit-Test
git -C "$archive_source" config user.email owntransit-test@example.invalid
git -C "$archive_source" config tar.umask 0000
git -C "$archive_source" add go.mod go.sum cmd internal tools
git -C "$archive_source" commit -q -m 'qualification source'
archive_commit=$(git -C "$archive_source" rev-parse --verify HEAD)

expect_source_key_failure() {
  expected_message=$1
  rejected_key=$2
  rejected_output=$3
  if rejection_output=$(SSH_AUTH_SOCK="$workspace/nonexistent-agent.sock" \
    SSH_ASKPASS="$workspace/nonexistent-askpass" \
    SSH_ASKPASS_REQUIRE=force \
    DISPLAY=owntransit-test \
    "$project_root/packaging/homebrew/build-source-archive.sh" \
      --source "$archive_source" \
      --version 0.0.0-test \
      --commit "$archive_commit" \
      --signing-key "$rejected_key" \
      --allowed-signers "$workspace/source-allowed" \
      --signer owntransit-source \
      --output "$rejected_output" 2>&1); then
    fail "source archive helper accepted a rejected key: $expected_message"
  fi
  printf '%s\n' "$rejection_output" | grep -Fq "$expected_message" ||
    fail "source archive helper failed for the wrong reason: $rejection_output"
  test ! -e "$rejected_output" && test ! -L "$rejected_output" ||
    fail "source archive helper published output after rejecting a key"
}

source_archive_a="$archive_output/owntransit-0.0.0-test-source.tar.gz"
"$project_root/packaging/homebrew/build-source-archive.sh" \
  --source "$archive_source" \
  --version 0.0.0-test \
  --commit "$archive_commit" \
  --signing-key "$workspace/signing-key" \
  --allowed-signers "$workspace/source-allowed" \
  --signer owntransit-source \
  --output "$source_archive_a" >/dev/null
test -s "$source_archive_a" ||
  fail "source archive signing helper produced no archive"

git -C "$archive_source" config tar.umask 0077
source_archive_b="$archive_output/owntransit-0.0.0-test-source-repeat.tar.gz"
"$project_root/packaging/homebrew/build-source-archive.sh" \
  --source "$archive_source" \
  --version 0.0.0-test \
  --commit "$archive_commit" \
  --signing-key "$workspace/signing-key" \
  --allowed-signers "$workspace/source-allowed" \
  --signer owntransit-source \
  --output "$source_archive_b" >/dev/null
cmp -s "$source_archive_a" "$source_archive_b" ||
  fail "source archive bytes changed under conflicting repository tar.umask values"

source_extract="$workspace/source-archive-extract"
mkdir "$source_extract"
tar -xzpf "$source_archive_a" -C "$source_extract"
source_archive_root="$source_extract/owntransit-0.0.0-test"
for archive_directory in \
  "$source_archive_root" \
  "$source_archive_root/cmd" \
  "$source_archive_root/cmd/example" \
  "$source_archive_root/internal" \
  "$source_archive_root/internal/example" \
  "$source_archive_root/tools"; do
  test "$(file_mode "$archive_directory")" = 755 ||
    fail "source archive directory mode is not 0755: $archive_directory"
done
for archive_file in \
  "$source_archive_root/go.mod" \
  "$source_archive_root/go.sum" \
  "$source_archive_root/cmd/example/main.go" \
  "$source_archive_root/internal/example/example.go" \
  "$source_archive_root/SOURCE-MANIFEST.txt" \
  "$source_archive_root/SOURCE-MANIFEST.txt.sig"; do
  test "$(file_mode "$archive_file")" = 644 ||
    fail "source archive regular member mode is not 0644: $archive_file"
done
test "$(file_mode "$source_archive_root/tools/example.sh")" = 755 ||
  fail "source archive executable member mode is not 0755"

expect_source_key_failure \
  'signing key must be an Ed25519 private key' \
  "$workspace/rsa-key" \
  "$archive_output/rsa-key.tar.gz"
expect_source_key_failure \
  'signing key must have exactly one hard link' \
  "$workspace/hardlinked-key" \
  "$archive_output/hardlinked-key.tar.gz"
expect_source_key_failure \
  'signing key mode must be 0400 or 0600' \
  "$workspace/special-mode-key" \
  "$archive_output/special-mode-key.tar.gz"

cp "$workspace/signing-key" "$archive_source/embedded-key"
chmod 0600 "$archive_source/embedded-key"
expect_source_key_failure \
  'signing key must be outside the source staging tree' \
  "$archive_source/embedded-key" \
  "$archive_output/source-key.tar.gz"
rm -f "$archive_source/embedded-key"

cp "$workspace/signing-key" "$archive_output/embedded-key"
chmod 0600 "$archive_output/embedded-key"
expect_source_key_failure \
  'signing key must be outside the output tree' \
  "$archive_output/embedded-key" \
  "$archive_output/output-key.tar.gz"

formula_dir="$workspace/formula"
mkdir "$formula_dir"
release_id=aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
source_digest=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
"$project_root/packaging/homebrew/render-formula.sh" \
  --github-owner example-owner \
  --source-repository owntransit \
  --license Apache-2.0 \
  --version 0.1.0-rc.3 \
  --source-sha256 "$source_digest" \
  --release-id "$release_id" \
  --source-commit "$source_commit" \
  --go-version go1.26.7 \
  --signer-public-key "$workspace/signing-key.pub" \
  --output "$formula_dir/owntransit.rb" >/dev/null
grep -Fq 'license "Apache-2.0"' "$formula_dir/owntransit.rb" || fail "rendered formula lost the explicit license"
grep -Fq 'https://github.com/example-owner/owntransit/releases/download/v0.1.0-rc.3/owntransit-0.1.0-rc.3-source.tar.gz' "$formula_dir/owntransit.rb" || fail "rendered formula has the wrong source URL"
grep -Fq "source_signer = \"$key_type $key_data\"" "$formula_dir/owntransit.rb" || fail "rendered formula lost the signer pin"
grep -Fq 'allowed_signers.atomic_write("owntransit-source #{source_signer}\n")' "$formula_dir/owntransit.rb" || fail "rendered formula does not write the pinned signer identity"
grep -Fq 'intentionally does not install owntransitctl' "$formula_dir/owntransit.rb" || fail "rendered formula lost the privileged lifecycle boundary"
if grep -Fq './cmd/owntransitctl' "$formula_dir/owntransit.rb" || grep -Fq 'bin/"owntransitctl"' "$formula_dir/owntransit.rb"; then
  fail "rendered formula exposes a Cellar lifecycle executable"
fi
if test -n "${OWNTRANSIT_HOMEBREW_BIN:-}"; then
  case "$OWNTRANSIT_HOMEBREW_BIN" in
    /*) ;;
    *) fail "Homebrew executable path must be absolute" ;;
  esac
  test -x "$OWNTRANSIT_HOMEBREW_BIN" || fail "Homebrew executable is not executable"
  homebrew_style_tap="owntransit-ci/formula-style-test-$$"
  if "$OWNTRANSIT_HOMEBREW_BIN" tap | grep -Fxq "$homebrew_style_tap"; then
    fail "temporary Homebrew style tap already exists"
  fi
  "$OWNTRANSIT_HOMEBREW_BIN" tap-new --no-git "$homebrew_style_tap" >/dev/null
  homebrew_style_tap_created=1
  homebrew_style_root=$("$OWNTRANSIT_HOMEBREW_BIN" --repository "$homebrew_style_tap")
  cp "$formula_dir/owntransit.rb" "$homebrew_style_root/Formula/owntransit.rb"
  chmod 0644 "$homebrew_style_root/Formula/owntransit.rb"
  "$OWNTRANSIT_HOMEBREW_BIN" style "$homebrew_style_tap/owntransit"
  "$OWNTRANSIT_HOMEBREW_BIN" audit --strict "$homebrew_style_tap/owntransit"
  homebrew_style_version=$(
    "$OWNTRANSIT_HOMEBREW_BIN" info --json=v2 "$homebrew_style_tap/owntransit" |
      ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("formulae").fetch(0).fetch("versions").fetch("stable")'
  )
  test "$homebrew_style_version" = 0.1.0-rc.3 || fail "Homebrew inferred the wrong RC version"
  "$OWNTRANSIT_HOMEBREW_BIN" untap "$homebrew_style_tap" >/dev/null
  homebrew_style_tap_created=0
fi

printf '%s\n' 'platform signature and formula tests passed'
