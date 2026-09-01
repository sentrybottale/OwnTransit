#!/bin/sh
set -eu

umask 077
LC_ALL=C
export LC_ALL

fail() {
  printf 'qualification-native-archive-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
archiver="$project_root/scripts/release/archive-native.sh"
workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-native-archive-test.XXXXXX") || fail "cannot create test workspace"
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve test workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

file_mode() {
  if test "$(uname -s)" = Darwin; then
    stat -f '%Lp' -- "$1"
  else
    stat -c '%a' -- "$1"
  fi
}

file_mtime() {
  if test "$(uname -s)" = Darwin; then
    stat -f '%m' -- "$1"
  else
    stat -c '%Y' -- "$1"
  fi
}

write_fixture_paths() {
  cat <<'EOF'
BUILD-INPUTS
LICENSE
RELEASE-MANIFEST.json
SOURCE-MANIFEST.txt
artifacts/owntransit-connector-linux-amd64
artifacts/owntransit-darwin-arm64
artifacts/owntransit-launcher-darwin-arm64
artifacts/owntransit-linux-amd64
artifacts/owntransit-provision-darwin-arm64
artifacts/owntransit-provision-linux-amd64
artifacts/owntransit-relay-linux-amd64.oci.tar
artifacts/owntransitctl-darwin-arm64
artifacts/owntransitctl-linux-amd64
evidence/PROVENANCE.json
evidence/THIRD_PARTY_LICENSES.txt
evidence/owntransit-connector-linux-amd64.spdx.json
evidence/owntransit-darwin-arm64.spdx.json
evidence/owntransit-launcher-darwin-arm64.spdx.json
evidence/owntransit-linux-amd64.spdx.json
evidence/owntransit-provision-darwin-arm64.spdx.json
evidence/owntransit-provision-linux-amd64.spdx.json
evidence/owntransit-relay-linux-amd64.oci.tar.spdx.json
evidence/owntransitctl-darwin-arm64.spdx.json
evidence/owntransitctl-linux-amd64.spdx.json
packaging/launchd/README.md
packaging/scripts/install-linux.sh
packaging/scripts/install-macos.sh
packaging/scripts/uninstall-linux.sh
packaging/scripts/uninstall-macos.sh
packaging/systemd/README.md
packaging/systemd/owntransit-connector.service
packaging/systemd/owntransit-relay.service
EOF
}

fixture_mode() {
  case "$1" in
    artifacts/owntransit-relay-linux-amd64.oci.tar) printf '%s\n' 0644 ;;
    artifacts/*|packaging/scripts/*) printf '%s\n' 0755 ;;
    *) printf '%s\n' 0644 ;;
  esac
}

version=0.1.0-rc.1
release_id=aeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
source_date_epoch=1700000000
bundle="$workspace/bundle"
paths="$workspace/fixture-paths"
mkdir "$bundle"
chmod 0755 "$bundle"
write_fixture_paths | LC_ALL=C sort > "$paths"

while IFS= read -r relative; do
  case "$relative" in */*) mkdir -p "$bundle/${relative%/*}" ;; esac
done < "$paths"
find "$bundle" -type d -exec chmod 0755 {} \;

printf '%s\n' 'qualification source manifest' > "$bundle/SOURCE-MANIFEST.txt"
source_manifest_sha256=$(sha256_file "$bundle/SOURCE-MANIFEST.txt")
printf '%s\n' \
  "version=$version" \
  "release_id=$release_id" \
  'release_sequence=1' \
  "source_commit=$source_commit" \
  "source_date_epoch=$source_date_epoch" \
  "source_manifest_sha256=$source_manifest_sha256" \
  > "$bundle/BUILD-INPUTS"

while IFS= read -r relative; do
  case "$relative" in BUILD-INPUTS|SOURCE-MANIFEST.txt) continue ;; esac
  printf 'qualification fixture: %s\n' "$relative" > "$bundle/$relative"
done < "$paths"
while IFS= read -r relative; do
  chmod "$(fixture_mode "$relative")" "$bundle/$relative"
done < "$paths"
(
  cd "$bundle"
  while IFS= read -r relative; do
    printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
  done < "$paths"
) > "$bundle/SHA256SUMS"
chmod 0644 "$bundle/SHA256SUMS"

output_a="$workspace/output-a"
output_b="$workspace/output-b"
mkdir "$output_a" "$output_b"
archive_name="owntransit-$version-native.tar.gz"
archive_a="$output_a/$archive_name"
archive_b="$output_b/$archive_name"

"$archiver" --bundle "$bundle" --output "$archive_a" >/dev/null
"$archiver" --bundle "$bundle" --output "$archive_b" >/dev/null
test -s "$archive_a" && test -s "$archive_b" || fail "archiver produced no output"
cmp -s "$archive_a" "$archive_b" || fail "separate archiver runs were not byte-identical"
test "$(file_mode "$archive_a")" = 644 || fail "archive output mode is not 0644"
test "$(od -An -tx1 -N8 "$archive_a" | tr -d '[:space:]')" = 1f8b080000000000 ||
  fail "gzip header retained a filename, timestamp, or flags"

archive_listing="$workspace/archive-listing"
gzip -cd "$archive_a" | tar -tf - > "$archive_listing"
expected_archive_listing="$workspace/expected-archive-listing"
archive_root_name="owntransit-$version-native"
{
  printf '%s/\n' "$archive_root_name"
  sed "s|^|$archive_root_name/|" "$paths"
  printf '%s/SHA256SUMS\n' "$archive_root_name"
  printf '%s\n' \
    "$archive_root_name/artifacts/" \
    "$archive_root_name/evidence/" \
    "$archive_root_name/packaging/" \
    "$archive_root_name/packaging/launchd/" \
    "$archive_root_name/packaging/scripts/" \
    "$archive_root_name/packaging/systemd/"
} | LC_ALL=C sort > "$expected_archive_listing"
cmp -s "$expected_archive_listing" "$archive_listing" || {
  diff -u "$expected_archive_listing" "$archive_listing" >&2 || true
  fail "archive member inventory or order is not exact"
}
if grep -Eiq '(^|/)(RELEASE-POLICY|allowed_signers)|\.(sig|pem)$' "$archive_listing"; then
  fail "archive contains signature, policy, key, or trust material"
fi
ustar_magic=$(gzip -cd "$archive_a" | dd bs=1 skip=257 count=6 2>/dev/null | od -An -tx1 | tr -d '[:space:]')
test "$ustar_magic" = 757374617200 || fail "archive is not canonical ustar"
stored_uid=$(gzip -cd "$archive_a" | dd bs=1 skip=108 count=8 2>/dev/null | tr -d '\000[:space:]')
stored_gid=$(gzip -cd "$archive_a" | dd bs=1 skip=116 count=8 2>/dev/null | tr -d '\000[:space:]')
test "$stored_uid" = 0000000 && test "$stored_gid" = 0000000 || fail "archive owner/group are not numeric zero"

extracted="$workspace/extracted"
mkdir "$extracted"
gzip -cd "$archive_a" | tar -xpf - -C "$extracted"
archive_root="$extracted/owntransit-$version-native"
test -d "$archive_root" || fail "canonical archive root did not extract"
{
  cat "$paths"
  printf '%s\n' SHA256SUMS
} | LC_ALL=C sort > "$workspace/extracted-file-paths"
while IFS= read -r relative; do
  cmp -s "$bundle/$relative" "$archive_root/$relative" || fail "archive changed $relative"
  expected_mode=$(fixture_mode "$relative")
  expected_mode=${expected_mode#0}
  test "$(file_mode "$archive_root/$relative")" = "$expected_mode" || fail "archive changed mode for $relative"
  test "$(file_mtime "$archive_root/$relative")" = "$source_date_epoch" || fail "archive changed mtime for $relative"
done < "$workspace/extracted-file-paths"
for directory in \
  "$archive_root" \
  "$archive_root/artifacts" \
  "$archive_root/evidence" \
  "$archive_root/packaging" \
  "$archive_root/packaging/launchd" \
  "$archive_root/packaging/scripts" \
  "$archive_root/packaging/systemd"; do
  test "$(file_mode "$directory")" = 755 || fail "archive directory mode is not 0755: $directory"
  test "$(file_mtime "$directory")" = "$source_date_epoch" || fail "archive directory mtime is not SOURCE_DATE_EPOCH: $directory"
done

expect_failure() {
  expected_message=$1
  rejected_output=$2
  if rejection=$("$archiver" --bundle "$bundle" --output "$rejected_output" 2>&1); then
    fail "archiver unexpectedly accepted invalid input: $expected_message"
  fi
  printf '%s\n' "$rejection" | grep -Fq "$expected_message" ||
    fail "archiver failed for the wrong reason: $rejection"
  test ! -e "$rejected_output" && test ! -L "$rejected_output" ||
    fail "archiver published output after rejecting invalid input"
}

expect_existing_output_failure() {
  rejected_output=$1
  if rejection=$("$archiver" --bundle "$bundle" --output "$rejected_output" 2>&1); then
    fail "archiver unexpectedly overwrote an existing output"
  fi
  printf '%s\n' "$rejection" | grep -Fq 'output already exists' ||
    fail "archiver failed for the wrong reason: $rejection"
}

wrong_name="$workspace/output-a/wrong-name.tar.gz"
expect_failure "output basename must be exactly $archive_name" "$wrong_name"

existing_output_dir="$workspace/existing-output"
mkdir "$existing_output_dir"
printf '%s\n' sentinel > "$existing_output_dir/$archive_name"
expect_existing_output_failure "$existing_output_dir/$archive_name"
test "$(sed -n '1p' "$existing_output_dir/$archive_name")" = sentinel || fail "existing output was overwritten"

dangling_output_dir="$workspace/dangling-output"
mkdir "$dangling_output_dir"
ln -s absent "$dangling_output_dir/$archive_name"
expect_existing_output_failure "$dangling_output_dir/$archive_name"
test -L "$dangling_output_dir/$archive_name" || fail "dangling output was replaced"

printf '%s\n' 'must remain external' > "$bundle/RELEASE-MANIFEST.sig"
chmod 0644 "$bundle/RELEASE-MANIFEST.sig"
extra_output_dir="$workspace/extra-output"
mkdir "$extra_output_dir"
expect_failure 'bundle file inventory is not the exact unsigned native staging tree' "$extra_output_dir/$archive_name"
rm -f "$bundle/RELEASE-MANIFEST.sig"

ln -s LICENSE "$bundle/unexpected-link"
link_output_dir="$workspace/link-output"
mkdir "$link_output_dir"
expect_failure 'bundle tree contains a symlink or non-regular entry' "$link_output_dir/$archive_name"
rm -f "$bundle/unexpected-link"

ln "$bundle/LICENSE" "$bundle/unexpected-hardlink"
hardlink_output_dir="$workspace/hardlink-output"
mkdir "$hardlink_output_dir"
expect_failure 'bundle file has multiple hard links' "$hardlink_output_dir/$archive_name"
rm -f "$bundle/unexpected-hardlink"

cp "$bundle/LICENSE" "$workspace/LICENSE.saved"
printf '%s\n' tampered >> "$bundle/LICENSE"
checksum_output_dir="$workspace/checksum-output"
mkdir "$checksum_output_dir"
expect_failure 'SHA256SUMS verification failed' "$checksum_output_dir/$archive_name"
mv "$workspace/LICENSE.saved" "$bundle/LICENSE"
chmod 0644 "$bundle/LICENSE"

cp "$bundle/SHA256SUMS" "$workspace/SHA256SUMS.saved"
{
  sed -n '2p' "$workspace/SHA256SUMS.saved"
  sed -n '1p' "$workspace/SHA256SUMS.saved"
  sed -n '3,$p' "$workspace/SHA256SUMS.saved"
} > "$bundle/SHA256SUMS"
unsorted_output_dir="$workspace/unsorted-output"
mkdir "$unsorted_output_dir"
expect_failure 'SHA256SUMS paths are not sorted' "$unsorted_output_dir/$archive_name"
mv "$workspace/SHA256SUMS.saved" "$bundle/SHA256SUMS"
chmod 0644 "$bundle/SHA256SUMS"

inside_output="$bundle/$archive_name"
expect_failure 'output must remain outside the native staging tree' "$inside_output"

printf '%s\n' 'deterministic native qualification archive tests passed'
