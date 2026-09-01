#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

fail() {
  printf 'package-pkg: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: package-pkg.sh \
  --mode unsigned|developer-id \
  --role provisioner \
  --version SAFE_VERSION \
  --release-id 52_CHAR_CANONICAL_BASE32 \
  --bundle ABSOLUTE_STAGING_DIRECTORY \
  --checksums-sha256 64_HEX \
  --checksums-signature ABSOLUTE_FILE \
  --allowed-signers ABSOLUTE_FILE \
  --signer SAFE_IDENTITY \
  --output ABSOLUTE_NEW_DIRECTORY \
  [--application-identity 'Developer ID Application: ...'] \
  [--installer-identity 'Developer ID Installer: ...'] \
  [--notary-profile KEYCHAIN_PROFILE]

The unsigned mode is qualification-only and is never described as notarized.
Developer ID output is currently disabled: codesigning and stapling change the
final bytes after OwnTransit release authentication. It remains unavailable
until the final package digest and authenticated BUILD-INPUTS version are bound
by an independently verifiable OwnTransit signature.
Client package generation is disabled because a package invocation has no
authenticated, explicit local reader-user selector; use install-macos.sh.
EOF
}

mode=
role=
version=
release_id=
bundle=
checksums_sha256=
checksums_signature=
allowed_signers=
signer=
output=
application_identity=
installer_identity=
notary_profile=
while test "$#" -gt 0; do
  case "$1" in
    --mode|--role|--version|--release-id|--bundle|--checksums-sha256|--checksums-signature|--allowed-signers|--signer|--output|--application-identity|--installer-identity|--notary-profile)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --mode) mode=$value ;;
        --role) role=$value ;;
        --version) version=$value ;;
        --release-id) release_id=$value ;;
        --bundle) bundle=$value ;;
        --checksums-sha256) checksums_sha256=$value ;;
        --checksums-signature) checksums_signature=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --signer) signer=$value ;;
        --output) output=$value ;;
        --application-identity) application_identity=$value ;;
        --installer-identity) installer_identity=$value ;;
        --notary-profile) notary_profile=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

case "$mode" in unsigned|developer-id) ;; *) fail "mode must be unsigned or developer-id" ;; esac
if test "$mode" = developer-id; then
  fail "developer-id package output is disabled until OwnTransit authenticates the final package bytes and BUILD-INPUTS version"
fi
case "$role" in
  client)
    fail "client .pkg generation is disabled: a package cannot securely select and revalidate the explicit local --client-user reader identity; use the authenticated install-macos.sh lane"
    ;;
  provisioner)
    artifact_name=owntransit-provision-darwin-arm64
    installed_name=owntransit-provision
    lifecycle_name=
    package_identifier=com.owntransit.provisioner
    ;;
  *) fail "role must be provisioner (client package generation is disabled)" ;;
esac
case "$version" in ''|*[!A-Za-z0-9._+-]*) fail "version contains an unsafe character" ;; esac
case "$version" in [A-Za-z0-9]*) ;; *) fail "version must begin with an alphanumeric character" ;; esac
test "${#version}" -le 128 || fail "version is too long"

valid_digest() {
  digest_value=$1
  case "$digest_value" in ''|*[!0-9a-f]*) return 1 ;; esac
  test "${#digest_value}" -eq 64
}
case "$release_id" in ''|*[!a-z2-7]*) fail "release ID must be lowercase unpadded base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical trailing base32 bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
valid_digest "$checksums_sha256" || fail "checksums SHA-256 is invalid"
test "$signer" = owntransit-release || fail "release signer identity must be exactly owntransit-release"

if test "$mode" = developer-id; then
  test -n "$application_identity" || fail "developer-id mode requires --application-identity"
  test -n "$installer_identity" || fail "developer-id mode requires --installer-identity"
  test -n "$notary_profile" || fail "developer-id mode requires --notary-profile"
  printf '%s\n' "$application_identity" | LC_ALL=C grep -Eq '^[A-Za-z0-9._,:+() -]+$' || fail "application identity contains an unsafe character"
  printf '%s\n' "$installer_identity" | LC_ALL=C grep -Eq '^[A-Za-z0-9._,:+() -]+$' || fail "installer identity contains an unsafe character"
  case "$notary_profile" in *[!A-Za-z0-9._-]*|'') fail "notary profile contains an unsafe character" ;; esac
else
  test -z "$application_identity$installer_identity$notary_profile" || fail "Apple credential selectors are accepted only in developer-id mode"
fi

test "$(uname -s)" = Darwin || fail "macOS packaging requires Darwin"
test "$(uname -m)" = arm64 || fail "macOS packaging requires arm64"
for command_name in awk codesign cmp dirname file find grep install ln mktemp mv pkgbuild pkgutil rm shasum stat tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
if test "$mode" = developer-id; then
  for command_name in productsign security spctl xcrun; do
    command -v "$command_name" >/dev/null 2>&1 || fail "Developer ID command is unavailable: $command_name"
  done
fi

case "$bundle" in /*) ;; *) fail "bundle path must be absolute" ;; esac
test -d "$bundle" && test ! -L "$bundle" || fail "bundle must be a regular non-symlink directory"
bundle_resolved=$(CDPATH= cd -P -- "$bundle" && pwd) || fail "cannot resolve bundle"
test "$bundle_resolved" = "$bundle" || fail "bundle path must be canonical"
case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "cannot resolve output parent"
test "$output_parent/$(basename "$output")" = "$output" || fail "output path must be canonical"
case "$(basename "$output")" in *[!A-Za-z0-9._+-]*|'') fail "output basename contains an unsafe character" ;; esac

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$bundle/SHA256SUMS" \
  --sha256 "$checksums_sha256" \
  --signature "$checksums_signature" \
  --allowed-signers "$allowed_signers" \
  --signer "$signer" \
  --namespace owntransit-release-v1 >/dev/null

sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
verification=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-pkg-verify.XXXXXX") || fail "cannot create checksum workspace"
workspace=$(mktemp -d "$output_parent/.owntransit-pkg.XXXXXX") || {
  rm -rf -- "$verification"
  fail "cannot create package workspace"
}
cleanup() { rm -rf -- "$verification" "$workspace"; }
trap cleanup EXIT HUP INT TERM
seen="$verification/seen"
: > "$seen"
checksum_count=0
while read -r expected path extra; do
  test -z "${extra:-}" || fail "SHA256SUMS contains an invalid line"
  valid_digest "${expected:-}" || fail "SHA256SUMS contains a non-canonical digest"
  case "${path:-}" in ''|/*|*[!A-Za-z0-9._/+:-]*) fail "SHA256SUMS contains an unsafe path" ;; esac
  case "/$path/" in */../*|*/./*|*//*) fail "SHA256SUMS contains path traversal" ;; esac
  grep -Fqx "$path" "$seen" && fail "SHA256SUMS contains a duplicate path"
  candidate="$bundle/$path"
  test -f "$candidate" && test ! -L "$candidate" || fail "checksummed member is absent or not regular: $path"
  test "$(stat -f %l "$candidate")" -eq 1 || fail "checksummed member has multiple hard links: $path"
  test "$(sha256_file "$candidate")" = "$expected" || fail "checksum mismatch: $path"
  printf '%s\n' "$path" >> "$seen"
  checksum_count=$((checksum_count + 1))
done < "$bundle/SHA256SUMS"
test "$checksum_count" -gt 0 || fail "SHA256SUMS is empty"
test -z "$(find "$bundle" -type l -print)" || fail "bundle contains a symlink"
test -z "$(find "$bundle" ! -type f ! -type d -print)" || fail "bundle contains a special entry"
actual_file_count=$(find "$bundle" -type f -print | wc -l | tr -d '[:space:]')
test "$actual_file_count" -eq $((checksum_count + 1)) || fail "bundle contains a file absent from SHA256SUMS"

listed_digest() {
  listed_path=$1
  value=$(awk -v wanted="$listed_path" '$2 == wanted { print $1 }' "$bundle/SHA256SUMS")
  valid_digest "$value" || fail "required bundle member is absent: $listed_path"
  printf '%s\n' "$value"
}
build_release_id=$(awk -F= '$1 == "release_id" { print $2 }' "$bundle/BUILD-INPUTS")
test "$build_release_id" = "$release_id" || fail "BUILD-INPUTS release ID mismatch"
artifact_path="artifacts/$artifact_name"
artifact_digest=$(listed_digest "$artifact_path")
lifecycle_digest=
if test -n "$lifecycle_name"; then
  lifecycle_path="artifacts/$lifecycle_name"
  lifecycle_digest=$(listed_digest "$lifecycle_path")
fi

payload="$workspace/payload"
release_directory="$payload/Library/OwnTransit/provisioner/releases/$release_id"
bin_directory="$payload/Library/OwnTransit/bin"
install -d -m 0755 "$release_directory" "$bin_directory"
install -m 0755 "$bundle/$artifact_path" "$release_directory/$installed_name"
test "$(sha256_file "$release_directory/$installed_name")" = "$artifact_digest" || fail "copied artifact changed during packaging"
test "$(listed_digest LICENSE)" = "$(sha256_file "$bundle/LICENSE")" || fail "project license is not authenticated by the release"
test "$(listed_digest evidence/THIRD_PARTY_LICENSES.txt)" = "$(sha256_file "$bundle/evidence/THIRD_PARTY_LICENSES.txt")" || fail "third-party notices are not authenticated by the release"
install -m 0644 "$bundle/LICENSE" "$release_directory/LICENSE"
install -m 0644 "$bundle/evidence/THIRD_PARTY_LICENSES.txt" "$release_directory/THIRD_PARTY_LICENSES.txt"
printf '%s\n' "$release_id" > "$release_directory/release-id"
chmod 0644 "$release_directory/release-id"
ln -s "../provisioner/releases/$release_id/$installed_name" "$bin_directory/$installed_name"
if test -n "$lifecycle_name"; then
  install -m 0700 "$bundle/$lifecycle_path" "$release_directory/owntransitctl"
  test "$(sha256_file "$release_directory/owntransitctl")" = "$lifecycle_digest" || fail "copied lifecycle artifact changed during packaging"
  ln -s "../releases/$release_id/owntransitctl" "$bin_directory/owntransitctl"
fi
file -b "$release_directory/$installed_name" | grep -Fq 'Mach-O 64-bit arm64' || fail "payload executable is not Mach-O arm64"
if test -n "$lifecycle_name"; then
  file -b "$release_directory/owntransitctl" | grep -Fq 'Mach-O 64-bit arm64' || fail "lifecycle payload is not Mach-O arm64"
fi

if test "$mode" = developer-id; then
  security find-identity -v -p codesigning | grep -F -- "$application_identity" >/dev/null || fail "Developer ID Application identity is unavailable"
  security find-identity -v -p basic | grep -F -- "$installer_identity" >/dev/null || fail "Developer ID Installer identity is unavailable"
  codesign --force --sign "$application_identity" --options runtime --timestamp "$release_directory/$installed_name"
  codesign --verify --strict --verbose=2 "$release_directory/$installed_name"
  if test -n "$lifecycle_name"; then
    codesign --force --sign "$application_identity" --options runtime --timestamp "$release_directory/owntransitctl"
    codesign --verify --strict --verbose=2 "$release_directory/owntransitctl"
  fi
fi

unsigned_pkg="$workspace/unsigned.pkg"
pkgbuild --root "$payload" --identifier "$package_identifier" --version "$version" --ownership recommended "$unsigned_pkg" >/dev/null
pkgutil --payload-files "$unsigned_pkg" >/dev/null || fail "pkgutil could not inspect generated package"

package_name="owntransit-$role-$version-darwin-arm64.pkg"
notarization_status=not-requested
package_signature=unsigned
notary_id=
if test "$mode" = developer-id; then
  signed_pkg="$workspace/$package_name"
  productsign --timestamp --sign "$installer_identity" "$unsigned_pkg" "$signed_pkg" >/dev/null
  pkgutil --check-signature "$signed_pkg" >/dev/null || fail "signed package signature validation failed"
  notary_json="$verification/notary.json"
  xcrun notarytool submit "$signed_pkg" --keychain-profile "$notary_profile" --wait --output-format json > "$notary_json"
  notarization_status=$(plutil -extract status raw -o - "$notary_json") || fail "notarytool result has no status"
  test "$notarization_status" = Accepted || fail "notarization status is not Accepted: $notarization_status"
  notary_id=$(plutil -extract id raw -o - "$notary_json") || fail "notarytool result has no submission ID"
  case "$notary_id" in ''|*[!A-Fa-f0-9-]*) fail "notarytool returned an unsafe submission ID" ;; esac
  xcrun stapler staple "$signed_pkg" >/dev/null
  xcrun stapler validate "$signed_pkg" >/dev/null
  spctl --assess --type install --verbose=2 "$signed_pkg" >/dev/null
  package_signature=developer-id
  final_pkg="$signed_pkg"
else
  final_pkg="$unsigned_pkg"
fi

stage_output="$workspace/output"
install -d -m 0755 "$stage_output"
install -m 0644 "$final_pkg" "$stage_output/$package_name"
package_digest=$(sha256_file "$stage_output/$package_name")
if test "$mode" = developer-id; then
  printf '{"schema":"owntransit.qualify.macos-package.v1","result":"pass","mode":"developer-id","role":"%s","version":"%s","release_id":"%s","package":"%s","package_sha256":"%s","package_signature":"%s","notarization_status":"%s","notary_submission_id":"%s","stapled":true,"gatekeeper_assessment":"pass"}\n' \
    "$role" "$version" "$release_id" "$package_name" "$package_digest" "$package_signature" "$notarization_status" "$notary_id" > "$stage_output/evidence.json"
else
  printf '{"schema":"owntransit.qualify.macos-package.v1","result":"qualification-only","mode":"unsigned","role":"%s","version":"%s","release_id":"%s","package":"%s","package_sha256":"%s","package_signature":"unsigned","notarization_status":"not-requested","stapled":false,"gatekeeper_assessment":"not-run"}\n' \
    "$role" "$version" "$release_id" "$package_name" "$package_digest" > "$stage_output/evidence.json"
fi
chmod 0644 "$stage_output/evidence.json"
mv "$stage_output" "$output"
trap - EXIT HUP INT TERM
rm -rf -- "$verification" "$workspace"
printf 'created macOS package evidence: %s/evidence.json\n' "$output"
