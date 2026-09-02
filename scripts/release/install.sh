#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'owntransit-install: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: install.sh \
  --bundle ABSOLUTE_EXTRACTED_NATIVE_BUNDLE \
  --assets ABSOLUTE_SIGNED_ASSETS_DIRECTORY \
  --trust ABSOLUTE_INDEPENDENTLY_AUTHENTICATED_TRUST_DIRECTORY \
  --role client|connector|relay|provisioner \
  [--client-user EXISTING_LOCAL_USER]

Verifies the signed handoff, derives the exact release ID and artifact digests,
then executes the fail-closed installer for this platform. Run it from its exact
path inside a protected extracted native bundle. The client role requires one
explicit --client-user; other roles reject it.

The trust directory is not self-authenticating. Before invoking this command,
compare the exact SHA-256 of TRUST-STATEMENT.txt through a pre-existing
authenticated administrator channel independent of the release download,
GitHub account and OwnTransit relay. This command then verifies its signature
and every release, policy, distribution, allowed-signers and outer-inventory
binding. All three trees must use fresh root-created
inodes on a local filesystem; changing ownership of a user-created extraction
does not make retained writable descriptors safe. This command never downloads
or imports trust.
EOF
}

bundle=
assets=
trust=
role=
client_user=
bundle_seen=no
assets_seen=no
trust_seen=no
role_seen=no
client_user_seen=no

while test "$#" -gt 0; do
  case "$1" in
    --bundle|--assets|--trust|--role|--client-user)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --bundle)
          test "$bundle_seen" = no || fail "--bundle may be specified only once"
          bundle_seen=yes
          bundle=$value
          ;;
        --assets)
          test "$assets_seen" = no || fail "--assets may be specified only once"
          assets_seen=yes
          assets=$value
          ;;
        --trust)
          test "$trust_seen" = no || fail "--trust may be specified only once"
          trust_seen=yes
          trust=$value
          ;;
        --role)
          test "$role_seen" = no || fail "--role may be specified only once"
          role_seen=yes
          role=$value
          ;;
        --client-user)
          test "$client_user_seen" = no || fail "--client-user may be specified only once"
          client_user_seen=yes
          client_user=$value
          ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

case "$role" in
  client)
    test -n "$client_user" || fail "the client role requires --client-user"
    ;;
  connector|relay|provisioner)
    test -z "$client_user" || fail "--client-user is valid only for the client role"
    ;;
  *) fail "role must be client, connector, relay, or provisioner" ;;
esac

test "$(id -u)" -eq 0 || fail "installation requires root"

for command_name in awk basename cmp dirname find grep id ls sed sha256sum shasum stat ssh-keygen tr uname wc; do
  case "$command_name" in
    sha256sum|shasum)
      # The portable digest helper below requires one of these, not both.
      ;;
    *) command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name" ;;
  esac
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  fail "sha256sum or shasum is required"
fi

canonical_directory() {
  candidate_directory=$1
  directory_label=$2
  case "$candidate_directory" in
    /*) ;;
    *) fail "$directory_label path must be absolute" ;;
  esac
  test -d "$candidate_directory" && test ! -L "$candidate_directory" || fail "$directory_label must be a non-symlink directory"
  directory_parent=$(CDPATH= cd -P -- "$(dirname "$candidate_directory")" && pwd) || fail "cannot resolve $directory_label parent"
  directory_base=$(basename "$candidate_directory")
  resolved_directory="$directory_parent/$directory_base"
  test "$directory_parent" != / || resolved_directory="/$directory_base"
  test "$resolved_directory" = "$candidate_directory" || fail "$directory_label path must be canonical and contain no symlinked component"
}

canonical_directory "$bundle" bundle
canonical_directory "$assets" assets
canonical_directory "$trust" trust

case "$assets/" in "$bundle/"*) fail "assets must remain outside the native bundle" ;; esac
case "$trust/" in "$bundle/"*) fail "trust must remain outside the native bundle" ;; esac
case "$trust/" in "$assets/"*) fail "trust must remain outside the assets directory" ;; esac
case "$assets/" in "$trust/"*) fail "assets must remain outside the trust directory" ;; esac

expected_owner=0

path_owner() {
  if test "$(uname -s)" = Darwin; then
    stat -f %u -- "$1"
  else
    stat -c %u -- "$1"
  fi
}

path_mode() {
  if test "$(uname -s)" = Darwin; then
    stat -f %Lp -- "$1"
  else
    stat -c %a -- "$1"
  fi
}

path_links() {
  if test "$(uname -s)" = Darwin; then
    stat -f %l -- "$1"
  else
    stat -c %h -- "$1"
  fi
}

require_protected_path() {
  protected_path=$1
  protected_owner=$(path_owner "$protected_path")
  test "$protected_owner" -eq "$expected_owner" || fail "protected handoff path has the wrong owner: $protected_path"
  protected_mode=$(path_mode "$protected_path")
  case "$protected_mode" in
    [0-7][0-7][0-7]) ;;
    *) fail "protected handoff path has special or non-canonical mode bits: $protected_path" ;;
  esac
  protected_permissions=$((0$protected_mode))
  test $((protected_permissions & 022)) -eq 0 || fail "protected handoff path is group/world writable: $protected_path"
  if test "$(uname -s)" = Darwin; then
    test "$(ls -lde "$protected_path" | wc -l | tr -d '[:space:]')" -eq 1 || fail "protected handoff path has an extended ACL: $protected_path"
  fi
}

require_protected_tree() {
  protected_root=$1
  protected_label=$2
  ancestor=$protected_root
  while :; do
    test -d "$ancestor" && test ! -L "$ancestor" || fail "$protected_label ancestor is not a regular directory: $ancestor"
    require_protected_path "$ancestor"
    test "$ancestor" != / || break
    ancestor=$(dirname "$ancestor")
  done
  unexpected=$(find "$protected_root" ! -type f ! -type d -print) || fail "cannot inspect $protected_label tree"
  test -z "$unexpected" || fail "$protected_label tree contains a symlink or non-regular entry"
  protected_entries=$(find "$protected_root" -print) || fail "cannot enumerate $protected_label tree"
  while IFS= read -r protected_entry; do
    test -n "$protected_entry" || continue
    require_protected_path "$protected_entry"
    if test -f "$protected_entry"; then
      test "$(path_links "$protected_entry")" -eq 1 || fail "$protected_label file has multiple hard links: $protected_entry"
    fi
  done <<EOF
$protected_entries
EOF
}

require_protected_tree "$bundle" bundle
require_protected_tree "$assets" assets
require_protected_tree "$trust" trust

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

valid_digest() {
  digest_value=$1
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest_value}" -eq 64
}

validate_checksum_record() {
  checksum_record=$1
  checksum_label=$2
  test -s "$checksum_record" || fail "$checksum_label is empty"
  awk '
    BEGIN { ok = 1 }
    {
      if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ ||
          $0 != $1 "  " $2 || $2 !~ /^[A-Za-z0-9._\/+:-]+$/ ||
          $2 ~ /^\// || $2 ~ /^\.\// || $2 ~ /^\.\.\// ||
          $2 == "." || $2 == ".." || $2 ~ /\/$/ ||
          $2 ~ /\/\.\// || $2 ~ /\/\.\.\// || $2 ~ /\/\.$/ ||
          $2 ~ /\/\.\.$/ || $2 ~ /\/\// || seen[$2]++) {
        ok = 0
      }
    }
    END { exit ok ? 0 : 1 }
  ' "$checksum_record" || fail "$checksum_label is malformed, unsafe, or contains duplicate paths"
}

listed_digest() {
  listed_record=$1
  listed_path=$2
  awk -v wanted="$listed_path" '
    $2 == wanted { value = $1; count++ }
    END { if (count != 1) exit 1; print value }
  ' "$listed_record"
}

require_listed_file() {
  listed_root=$1
  listed_record=$2
  listed_path=$3
  listed_label=$4
  expected_digest=$(listed_digest "$listed_record" "$listed_path") || fail "$listed_label is absent or duplicated in its signed checksum inventory: $listed_path"
  valid_digest "$expected_digest" || fail "$listed_label has an invalid digest for $listed_path"
  selected_file="$listed_root/$listed_path"
  test -f "$selected_file" && test ! -L "$selected_file" || fail "$listed_label member is not a regular file: $listed_path"
  test "$(sha256_file "$selected_file")" = "$expected_digest" || fail "$listed_label checksum mismatch: $listed_path"
}

require_exact_flat_files() {
  exact_root=$1
  exact_label=$2
  expected_count=$3
  shift 3
  test "$(find "$exact_root" -type d -print | wc -l | tr -d '[:space:]')" -eq 1 || fail "$exact_label contains a nested directory"
  test "$(find "$exact_root" -type f -print | wc -l | tr -d '[:space:]')" -eq "$expected_count" || fail "$exact_label file inventory has the wrong size"
  for exact_name in "$@"; do
    test -f "$exact_root/$exact_name" && test ! -L "$exact_root/$exact_name" || fail "$exact_label is missing $exact_name"
  done
}

require_exact_flat_files "$trust" trust 7 \
  SHA256SUMS.sig \
  TRUST-STATEMENT.txt \
  TRUST-STATEMENT.txt.sig \
  allowed_signers \
  distribution-public.key \
  policy-public.pem \
  release-public.pem

test -s "$trust/allowed_signers" || fail "allowed-signers trust is empty"
test "$(wc -c < "$trust/allowed_signers" | tr -d '[:space:]')" -le 65536 || fail "allowed-signers trust is unexpectedly large"
test -s "$trust/SHA256SUMS.sig" || fail "outer checksum signature is empty"
test "$(wc -c < "$trust/SHA256SUMS.sig" | tr -d '[:space:]')" -le 16384 || fail "outer checksum signature is unexpectedly large"
test -s "$trust/TRUST-STATEMENT.txt" || fail "trust statement is empty"
test "$(wc -c < "$trust/TRUST-STATEMENT.txt" | tr -d '[:space:]')" -le 4096 || fail "trust statement is unexpectedly large"
test -s "$trust/TRUST-STATEMENT.txt.sig" || fail "trust statement signature is empty"
test "$(wc -c < "$trust/TRUST-STATEMENT.txt.sig" | tr -d '[:space:]')" -le 16384 || fail "trust statement signature is unexpectedly large"

test "$(wc -l < "$trust/distribution-public.key" | tr -d '[:space:]')" -eq 1 || fail "distribution public key must contain exactly one line"
read -r distribution_type distribution_data distribution_comment < "$trust/distribution-public.key" || fail "cannot read distribution public key"
test "$distribution_type" = ssh-ed25519 && test -n "$distribution_data" || fail "distribution public key must be Ed25519"
ssh-keygen -l -f "$trust/distribution-public.key" >/dev/null 2>&1 || fail "distribution public key is invalid"
expected_release_signer="owntransit-release $distribution_type $distribution_data"
expected_source_signer="owntransit-source $distribution_type $distribution_data"
test "$(wc -l < "$trust/allowed_signers" | tr -d '[:space:]')" -eq 2 || fail "allowed-signers must contain exactly the two canonical v1 principals"
test "$(sed -n '1p' "$trust/allowed_signers")" = "$expected_release_signer" || fail "allowed-signers release principal is not bound to the distribution public key"
test "$(sed -n '2p' "$trust/allowed_signers")" = "$expected_source_signer" || fail "allowed-signers source principal is not bound to the distribution public key"
expected_allowed_signers_size=$(printf '%s\n%s\n' "$expected_release_signer" "$expected_source_signer" | wc -c | tr -d '[:space:]')
test "$(wc -c < "$trust/allowed_signers" | tr -d '[:space:]')" -eq "$expected_allowed_signers_size" || fail "allowed-signers is not the exact canonical v1 byte representation"
distribution_data=
expected_release_signer=
expected_source_signer=

outer_checksums="$assets/SHA256SUMS"
test -f "$outer_checksums" && test ! -L "$outer_checksums" || fail "assets/SHA256SUMS is absent"
validate_checksum_record "$outer_checksums" "outer asset SHA256SUMS"
ssh-keygen -Y verify \
  -f "$trust/allowed_signers" \
  -I owntransit-release \
  -n owntransit-release-v1 \
  -s "$trust/SHA256SUMS.sig" \
  < "$outer_checksums" >/dev/null 2>&1 || fail "outer asset checksum signature did not verify under the independently supplied trust"
ssh-keygen -Y verify \
  -f "$trust/allowed_signers" \
  -I owntransit-release \
  -n owntransit-trust-v1 \
  -s "$trust/TRUST-STATEMENT.txt.sig" \
  < "$trust/TRUST-STATEMENT.txt" >/dev/null 2>&1 || fail "trust statement signature did not verify"

require_listed_file "$assets" "$outer_checksums" NATIVE-SHA256SUMS.sig "outer asset inventory"
test "$(wc -c < "$assets/NATIVE-SHA256SUMS.sig" | tr -d '[:space:]')" -le 16384 || fail "native checksum signature is unexpectedly large"

native_checksums="$bundle/SHA256SUMS"
test -f "$native_checksums" && test ! -L "$native_checksums" || fail "native bundle SHA256SUMS is absent"
validate_checksum_record "$native_checksums" "native bundle SHA256SUMS"
ssh-keygen -Y verify \
  -f "$trust/allowed_signers" \
  -I owntransit-release \
  -n owntransit-release-v1 \
  -s "$assets/NATIVE-SHA256SUMS.sig" \
  < "$native_checksums" >/dev/null 2>&1 || fail "native bundle checksum signature did not verify"

bundled_entrypoint="$bundle/packaging/scripts/install.sh"
case "$0" in /*) ;; *) fail "installer entry point must be invoked by its absolute path" ;; esac
test "$0" = "$bundled_entrypoint" || fail "installer entry point must run directly from the selected native bundle"
require_listed_file "$bundle" "$native_checksums" packaging/scripts/install.sh "native bundle"
test "$(sha256_file "$0")" = "$(listed_digest "$native_checksums" packaging/scripts/install.sh)" || fail "running installer entry point differs from the signed native bundle"

require_listed_file "$bundle" "$native_checksums" BUILD-INPUTS "native bundle"
build_inputs="$bundle/BUILD-INPUTS"
{
  IFS= read -r version_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r release_id_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r release_sequence_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_commit_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_date_epoch_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_manifest_line || fail "BUILD-INPUTS is incomplete"
  if IFS= read -r extra_line; then
    fail "BUILD-INPUTS contains an unexpected extra line"
  fi
} < "$build_inputs"
case "$version_line" in version=*) version=${version_line#version=} ;; *) fail "BUILD-INPUTS version field is invalid" ;; esac
case "$release_id_line" in release_id=*) release_id=${release_id_line#release_id=} ;; *) fail "BUILD-INPUTS release ID field is invalid" ;; esac
case "$release_sequence_line" in release_sequence=*) release_sequence=${release_sequence_line#release_sequence=} ;; *) fail "BUILD-INPUTS release sequence field is invalid" ;; esac
case "$source_commit_line" in source_commit=*) source_commit=${source_commit_line#source_commit=} ;; *) fail "BUILD-INPUTS source commit field is invalid" ;; esac
case "$source_date_epoch_line" in source_date_epoch=*) source_date_epoch=${source_date_epoch_line#source_date_epoch=} ;; *) fail "BUILD-INPUTS source date field is invalid" ;; esac
case "$source_manifest_line" in source_manifest_sha256=*) source_manifest_sha256=${source_manifest_line#source_manifest_sha256=} ;; *) fail "BUILD-INPUTS source manifest field is invalid" ;; esac
case "$version" in ''|*[!A-Za-z0-9._+-]*|[!A-Za-z0-9]*) fail "BUILD-INPUTS version is unsafe" ;; esac
test "${#version}" -le 64 || fail "BUILD-INPUTS version is too long"
case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
case "$release_sequence" in *[!0-9]*|'') fail "release sequence must be a positive decimal integer" ;; esac
test "$release_sequence" -gt 0 || fail "release sequence must be positive"
case "$source_commit" in *[!0-9a-f]*|'') fail "source commit must be lowercase hexadecimal" ;; esac
case "${#source_commit}" in 40|64) ;; *) fail "source commit must contain 40 or 64 hexadecimal characters" ;; esac
case "$source_date_epoch" in *[!0-9]*|'') fail "source date must be a positive decimal integer" ;; esac
test "${#source_date_epoch}" -le 10 && test "$source_date_epoch" -gt 0 || fail "source date is out of the supported range"
valid_digest "$source_manifest_sha256" || fail "source manifest digest is invalid"

{
  IFS= read -r trust_schema_line || fail "trust statement is incomplete"
  IFS= read -r trust_product_line || fail "trust statement is incomplete"
  IFS= read -r trust_version_line || fail "trust statement is incomplete"
  IFS= read -r trust_release_id_line || fail "trust statement is incomplete"
  IFS= read -r trust_source_commit_line || fail "trust statement is incomplete"
  IFS= read -r trust_distribution_line || fail "trust statement is incomplete"
  IFS= read -r trust_release_line || fail "trust statement is incomplete"
  IFS= read -r trust_policy_line || fail "trust statement is incomplete"
  IFS= read -r trust_allowed_signers_line || fail "trust statement is incomplete"
  IFS= read -r trust_outer_line || fail "trust statement is incomplete"
  if IFS= read -r extra_trust_line; then
    fail "trust statement contains an unexpected extra line"
  fi
} < "$trust/TRUST-STATEMENT.txt"
expected_trust_schema='schema=owntransit.release-trust.v1'
expected_trust_product='product=owntransit'
expected_trust_version="version=$version"
expected_trust_release_id="release_id=$release_id"
expected_trust_source_commit="source_commit=$source_commit"
expected_trust_distribution="distribution_public_sha256=$(sha256_file "$trust/distribution-public.key")"
expected_trust_release="release_public_sha256=$(sha256_file "$trust/release-public.pem")"
expected_trust_policy="policy_public_sha256=$(sha256_file "$trust/policy-public.pem")"
expected_trust_allowed_signers="allowed_signers_sha256=$(sha256_file "$trust/allowed_signers")"
expected_trust_outer="outer_sha256sums_sha256=$(sha256_file "$outer_checksums")"
test "$trust_schema_line" = "$expected_trust_schema" || fail "trust statement schema is invalid"
test "$trust_product_line" = "$expected_trust_product" || fail "trust statement product is invalid"
test "$trust_version_line" = "$expected_trust_version" || fail "trust statement version does not match BUILD-INPUTS"
test "$trust_release_id_line" = "$expected_trust_release_id" || fail "trust statement release ID does not match BUILD-INPUTS"
test "$trust_source_commit_line" = "$expected_trust_source_commit" || fail "trust statement source commit does not match BUILD-INPUTS"
test "$trust_distribution_line" = "$expected_trust_distribution" || fail "trust statement does not bind the distribution public key"
test "$trust_release_line" = "$expected_trust_release" || fail "trust statement does not bind the release public key"
test "$trust_policy_line" = "$expected_trust_policy" || fail "trust statement does not bind the policy public key"
test "$trust_allowed_signers_line" = "$expected_trust_allowed_signers" || fail "trust statement does not bind allowed-signers"
test "$trust_outer_line" = "$expected_trust_outer" || fail "trust statement does not bind the outer asset inventory"
expected_trust_size=$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n' \
  "$expected_trust_schema" "$expected_trust_product" "$expected_trust_version" \
  "$expected_trust_release_id" "$expected_trust_source_commit" "$expected_trust_distribution" \
  "$expected_trust_release" "$expected_trust_policy" "$expected_trust_allowed_signers" \
  "$expected_trust_outer" | wc -c | tr -d '[:space:]')
test "$(wc -c < "$trust/TRUST-STATEMENT.txt" | tr -d '[:space:]')" -eq "$expected_trust_size" || fail "trust statement is not the exact canonical byte representation"

native_archive="owntransit-$version-native.tar.gz"
source_archive="owntransit-$version-source.tar.gz"
require_exact_flat_files "$assets" assets 10 \
  NATIVE-SHA256SUMS.sig \
  RELEASE-CANDIDATE.json \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  SHA256SUMS \
  "$native_archive" \
  "$source_archive" \
  owntransit.rb

test "$(wc -l < "$outer_checksums" | tr -d '[:space:]')" -eq 9 || fail "outer asset checksum inventory is not the fixed nine-file set"
for asset_name in \
  NATIVE-SHA256SUMS.sig \
  RELEASE-CANDIDATE.json \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  "$native_archive" \
  "$source_archive" \
  owntransit.rb; do
  require_listed_file "$assets" "$outer_checksums" "$asset_name" "outer asset inventory"
done

require_listed_file "$bundle" "$native_checksums" RELEASE-MANIFEST.json "native bundle"
cmp -s "$bundle/RELEASE-MANIFEST.json" "$assets/RELEASE-MANIFEST.json" || fail "external and native release manifests differ"

checksums_sha256=$(sha256_file "$native_checksums")
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)
    platform=darwin
    case "$role" in
      client) artifact_path=artifacts/owntransit-darwin-arm64 ;;
      provisioner) artifact_path=artifacts/owntransit-provision-darwin-arm64 ;;
      *) fail "$role is not supported on macOS arm64" ;;
    esac
    platform_installer="$bundle/packaging/scripts/install-macos.sh"
    ;;
  Linux/x86_64|Linux/amd64)
    platform=linux
    case "$role" in
      client) artifact_path=artifacts/owntransit-linux-amd64 ;;
      connector) artifact_path=artifacts/owntransit-connector-linux-amd64 ;;
      relay) artifact_path=artifacts/owntransit-relay-linux-amd64.oci.tar ;;
      provisioner) artifact_path=artifacts/owntransit-provision-linux-amd64 ;;
    esac
    platform_installer="$bundle/packaging/scripts/install-linux.sh"
    ;;
  *) fail "this installer supports macOS arm64 and Linux amd64 only" ;;
esac

platform_installer_relative=${platform_installer#"$bundle/"}
require_listed_file "$bundle" "$native_checksums" "$platform_installer_relative" "native bundle"
require_listed_file "$bundle" "$native_checksums" "$artifact_path" "native bundle"
artifact_sha256=$(listed_digest "$native_checksums" "$artifact_path") || fail "cannot derive the selected artifact digest"
case "$role" in
  client|connector|relay|provisioner)
    lifecycle_path="artifacts/owntransitctl-$platform-amd64"
    test "$platform" != darwin || lifecycle_path=artifacts/owntransitctl-darwin-arm64
    require_listed_file "$bundle" "$native_checksums" "$lifecycle_path" "native bundle"
    lifecycle_sha256=$(listed_digest "$native_checksums" "$lifecycle_path") || fail "cannot derive the lifecycle artifact digest"
    for signed_input in \
      "$assets/RELEASE-MANIFEST.sig" \
      "$trust/release-public.pem" \
      "$assets/RELEASE-POLICY.json" \
      "$assets/RELEASE-POLICY.sig" \
      "$trust/policy-public.pem"; do
      test -f "$signed_input" && test ! -L "$signed_input" || fail "required signed lifecycle input is absent: $signed_input"
    done
    ;;
esac

if test "$role" = client && test "$platform" = darwin; then
  launcher_path=artifacts/owntransit-launcher-darwin-arm64
  require_listed_file "$bundle" "$native_checksums" "$launcher_path" "native bundle"
  launcher_sha256=$(listed_digest "$native_checksums" "$launcher_path") || fail "cannot derive the launcher artifact digest"
  exec "$platform_installer" \
    --bundle "$bundle" \
    --role "$role" \
    --release-id "$release_id" \
    --checksums-sha256 "$checksums_sha256" \
    --artifact-sha256 "$artifact_sha256" \
    --launcher-sha256 "$launcher_sha256" \
    --lifecycle-sha256 "$lifecycle_sha256" \
    --client-user "$client_user" \
    --manifest-signature "$assets/RELEASE-MANIFEST.sig" \
    --release-public-key "$trust/release-public.pem" \
    --policy "$assets/RELEASE-POLICY.json" \
    --policy-signature "$assets/RELEASE-POLICY.sig" \
    --policy-public-key "$trust/policy-public.pem"
elif test "$role" = client; then
  exec "$platform_installer" \
    --bundle "$bundle" \
    --role "$role" \
    --release-id "$release_id" \
    --checksums-sha256 "$checksums_sha256" \
    --artifact-sha256 "$artifact_sha256" \
    --lifecycle-sha256 "$lifecycle_sha256" \
    --client-user "$client_user" \
    --manifest-signature "$assets/RELEASE-MANIFEST.sig" \
    --release-public-key "$trust/release-public.pem" \
    --policy "$assets/RELEASE-POLICY.json" \
    --policy-signature "$assets/RELEASE-POLICY.sig" \
    --policy-public-key "$trust/policy-public.pem"
elif test "$role" = connector || test "$role" = relay || test "$role" = provisioner; then
  exec "$platform_installer" \
    --bundle "$bundle" \
    --role "$role" \
    --release-id "$release_id" \
    --checksums-sha256 "$checksums_sha256" \
    --artifact-sha256 "$artifact_sha256" \
    --lifecycle-sha256 "$lifecycle_sha256" \
    --manifest-signature "$assets/RELEASE-MANIFEST.sig" \
    --release-public-key "$trust/release-public.pem" \
    --policy "$assets/RELEASE-POLICY.json" \
    --policy-signature "$assets/RELEASE-POLICY.sig" \
    --policy-public-key "$trust/policy-public.pem"
else
  fail "selected role has no authenticated platform installer invocation"
fi
