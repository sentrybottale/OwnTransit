#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'install-macos: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: install-macos.sh \
  --bundle ABSOLUTE_STAGING_DIRECTORY \
  --role client|provisioner \
  --release-id 52_CHAR_BASE32_ID \
  --checksums-sha256 64_HEX \
  --artifact-sha256 64_HEX \
  [--launcher-sha256 64_HEX] \
  [--client-user EXISTING_LOCAL_SHORT_NAME] \
  [--lifecycle-sha256 64_HEX] \
  [--manifest-signature ABSOLUTE_FILE] \
  [--release-public-key ABSOLUTE_FILE] \
  [--policy ABSOLUTE_FILE] \
  [--policy-signature ABSOLUTE_FILE] \
  [--policy-public-key ABSOLUTE_FILE]

This is offline package payload logic. Its checksum and artifact digests must
come from an independently authenticated signed release. Developer ID package
output is disabled; this installer is the protected handoff boundary for the
free source/Homebrew lane. The client role requires one
explicit existing non-root local --client-user. It creates or exactly adopts a
dedicated local reader group and protected identity receipt; it never creates a
user, downloads, imports trust, edits SSH configuration, or installs launchd.
For both roles, the signed manifest and signed monotonic policy inputs are
mandatory. The authenticated current owntransitctl performs the per-role
package transaction; only a true first install executes the authenticated
candidate from the bundle. Exact reinstall resumes/idempotently verifies the
same selector. Provisioner package lifecycle creates no reader identity,
endpoint state or credential. This script does not bootstrap trust: verify this
installer and every supplied public key through the independent release
channel first.
EOF
}

bundle=
role=
release_id=
checksums_sha256=
artifact_sha256=
lifecycle_sha256=
launcher_sha256=
client_user=
manifest_signature=
release_public_key=
policy=
policy_signature=
policy_public_key=
while test "$#" -gt 0; do
  case "$1" in
    --bundle|--role|--release-id|--checksums-sha256|--artifact-sha256|--launcher-sha256|--lifecycle-sha256|--client-user|--manifest-signature|--release-public-key|--policy|--policy-signature|--policy-public-key)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --bundle) bundle=$value ;;
        --role) role=$value ;;
        --release-id) release_id=$value ;;
        --checksums-sha256) checksums_sha256=$value ;;
        --artifact-sha256) artifact_sha256=$value ;;
        --launcher-sha256) launcher_sha256=$value ;;
        --lifecycle-sha256) lifecycle_sha256=$value ;;
        --client-user) client_user=$value ;;
        --manifest-signature) manifest_signature=$value ;;
        --release-public-key) release_public_key=$value ;;
        --policy) policy=$value ;;
        --policy-signature) policy_signature=$value ;;
        --policy-public-key) policy_public_key=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$(uname -s)" = Darwin || fail "this installer supports macOS only"
test "$(uname -m)" = arm64 || fail "this installer supports arm64 only"
test "$(id -u)" -eq 0 || fail "installation requires root"

valid_digest() {
  digest_value=$1
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest_value}" -eq 64
}

legacy_unlocked_lifecycle_tuple() {
	case "$1:$2" in
		5dcdpm6bdsp5jxlw3vdgljhyapr5uhah5aewm42lqgjlmsca6s7a:31dd7799d78a53079c6f651864655706364e6aa27adcc223433a2dbc5eb9ba30|\
		resy4feogxdah3vtv3fnctmh7thp2vkopf5p3c45b7jrzxaj4nta:317ecb9eb24adfb2b0e70a600309209ddc9dd8ee0b2132bdfa9bed0b58f33c19|\
		aceg34dlxq7yo7tdbtmzbwwvlhdhfaeuis2dcct4k32kar5dj3na:a6793d0acc506e6824d76a0841beb29d30fc18ade0d8cc0f3fec818a1d49f653)
			return 0
			;;
		*) return 1 ;;
	esac
}

case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
valid_digest "$checksums_sha256" || fail "--checksums-sha256 is invalid"
valid_digest "$artifact_sha256" || fail "--artifact-sha256 is invalid"

case "$role" in
  client)
    artifact_name=owntransit-darwin-arm64
    installed_name=owntransit
    needs_lifecycle=yes
    valid_digest "$launcher_sha256" || fail "--launcher-sha256 is required and must be canonical"
    case "$client_user" in
      ''|*[!A-Za-z0-9._-]*|-*) fail "--client-user must be an explicit safe local short name" ;;
    esac
    test "${#client_user}" -le 64 || fail "--client-user is too long"
    test "$client_user" != _owntransit || fail "--client-user must not reuse the dedicated group name"
    ;;
  provisioner)
    artifact_name=owntransit-provision-darwin-arm64
    installed_name=owntransit-provision
    needs_lifecycle=yes
    test -z "$launcher_sha256" || fail "--launcher-sha256 is valid only for the client role"
    test -z "$client_user" || fail "--client-user is valid only for the client role"
    ;;
  *) fail "role must be client or provisioner" ;;
esac
if test "$needs_lifecycle" = yes; then
  valid_digest "$lifecycle_sha256" || fail "--lifecycle-sha256 is required and must be canonical"
	if legacy_unlocked_lifecycle_tuple "$release_id" "$lifecycle_sha256"; then
		fail "this hardened installer cannot target an obsolete unguarded macOS lifecycle"
	fi
  for signed_input in "$manifest_signature" "$release_public_key" "$policy" "$policy_signature" "$policy_public_key"; do
    case "$signed_input" in
      /*) ;;
      *) fail "each role requires every signed release/policy input as an absolute path" ;;
    esac
  done
fi

case "$bundle" in
  /*) ;;
  *) fail "bundle path must be absolute" ;;
esac
test -d "$bundle" && test ! -L "$bundle" || fail "bundle must be a regular directory, not a symlink"
bundle_resolved=$(CDPATH= cd -P -- "$bundle" && pwd) || fail "cannot resolve bundle"
test "$bundle_resolved" = "$bundle" || fail "bundle path must be canonical and contain no symlinked component"

for command_name in awk basename cat chmod chown cmp dirname dscl dseditgroup dsmemberutil find grep id install ln lockf ls mktemp mv plutil readlink rm rmdir sed shasum stat sudo tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

macos_mode() {
  macos_mode_raw=$(stat -f %p -- "$1") || return 1
  case "$macos_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
  printf '%o\n' "$((0$macos_mode_raw & 07777))"
}

require_root_owned_protected() {
  protected_path=$1
  test "$(stat -f %u "$protected_path")" -eq 0 || fail "bundle path is not root-owned: $protected_path"
  protected_mode=$(macos_mode "$protected_path") || fail "cannot read bundle path mode: $protected_path"
  case "$protected_mode" in
    [0-7][0-7][0-7]) ;;
    *) fail "bundle path has special or non-canonical mode bits: $protected_path" ;;
  esac
  protected_permissions=$((0$protected_mode))
  test $((protected_permissions & 022)) -eq 0 || fail "bundle path is group/world writable: $protected_path"
  test "$(ls -lde "$protected_path" | wc -l | tr -d '[:space:]')" -eq 1 || fail "bundle path has an extended ACL: $protected_path"
}

require_no_extended_acl() {
  acl_path=$1
  test "$(ls -lde "$acl_path" | wc -l | tr -d '[:space:]')" -eq 1 || fail "installed path has an extended ACL: $acl_path"
}

ancestor=$bundle
while :; do
  test -d "$ancestor" && test ! -L "$ancestor" || fail "bundle ancestor is not a regular directory: $ancestor"
  require_root_owned_protected "$ancestor"
  test "$ancestor" != / || break
  ancestor=$(dirname "$ancestor")
done
find "$bundle" -type d -print |
  while IFS= read -r directory; do
    require_root_owned_protected "$directory"
  done
test "$(find "$bundle" -type l -print | wc -l | tr -d '[:space:]')" -eq 0 || fail "bundle tree contains a symlink"
test "$(find "$bundle" ! -type f ! -type d -print | wc -l | tr -d '[:space:]')" -eq 0 || fail "bundle tree contains a non-file entry"

require_root_owned_regular() {
  regular_path=$1
  test -f "$regular_path" && test ! -L "$regular_path" || fail "bundle member is not a regular non-symlink file: $regular_path"
  test "$(stat -f %l "$regular_path")" -eq 1 || fail "bundle member has multiple hard links: $regular_path"
  require_root_owned_protected "$regular_path"
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

inspect_canonical_lifecycle_version() {
  lifecycle_executable=$1
  expected_lifecycle_release=$2
  version_output_name=$3
  version_output_path="$verification_directory/$version_output_name.version.json"
  test ! -e "$version_output_path" && test ! -L "$version_output_path" ||
    fail "lifecycle version inspection output already exists"
  if ! /usr/bin/env -i \
    HOME=/var/root \
    LANG=C \
    LC_ALL=C \
    PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    "$lifecycle_executable" version </dev/null >"$version_output_path" 2>/dev/null; then
    fail "$version_output_name lifecycle version inspection failed"
  fi
  version_output_size=$(wc -c < "$version_output_path" | tr -d '[:space:]')
  case "$version_output_size" in ''|*[!0-9]*) fail "$version_output_name lifecycle version output size is invalid" ;; esac
  test "$version_output_size" -gt 0 && test "$version_output_size" -le 1024 ||
    fail "$version_output_name lifecycle version output is empty or oversized"
  test "$(wc -l < "$version_output_path" | tr -d '[:space:]')" -eq 1 ||
    fail "$version_output_name lifecycle version output is not one canonical line"
  inspected_version=$(awk -F '"' \
    -v expected_release="$expected_lifecycle_release" '
      {
        if (NR != 1 || NF != 41 ||
            $1 != "{" || $2 != "schema" || $3 != ":" || $4 != "owntransit.build.v1" || $5 != "," ||
            $6 != "product" || $7 != ":" || $8 != "OwnTransit" || $9 != "," ||
            $10 != "version" || $11 != ":" || $13 != "," ||
            $14 != "release_id" || $15 != ":" || $16 != expected_release || $17 != "," ||
            $18 != "source_commit" || $19 != ":" || $21 != "," ||
            $22 != "source_dirty" || $23 != ":" || $24 != "false" || $25 != "," ||
            $26 != "role" || $27 != ":" || $28 != "lifecycle" || $29 != "," ||
            $30 != "protocol" || $31 != ":" || $33 != "," ||
            $34 != "goos" || $35 != ":" || $36 != "darwin" || $37 != "," ||
            $38 != "goarch" || $39 != ":" || $40 != "arm64" || $41 != "}") {
          invalid = 1
          next
        }
        if ($12 == "" || length($12) > 64 || $12 ~ /[^0-9A-Za-z.+-]/ ||
            $32 == "" || length($32) > 64 || $32 ~ /[^0-9A-Za-z._\/-]/ ||
            (length($20) != 40 && length($20) != 64) || $20 ~ /[^0-9a-f]/) {
          invalid = 1
          next
        }
        version = $12
      }
      END {
        if (NR != 1 || invalid || version == "") exit 1
        print version
      }
    ' "$version_output_path") || fail "$version_output_name lifecycle version output is not canonical OwnTransit build information"
  printf '%s\n' "$inspected_version"
}

is_owntransit_010_release_candidate() {
  case "$1" in
    0.1.0-rc.*)
      rc_number=${1#0.1.0-rc.}
      case "$rc_number" in ''|0|0*|*[!0-9]*) return 1 ;; esac
      return 0
      ;;
    *) return 1 ;;
  esac
}

checksums="$bundle/SHA256SUMS"
require_root_owned_regular "$checksums"
test "$(sha256_file "$checksums")" = "$checksums_sha256" || fail "SHA256SUMS does not match its independently supplied digest"

verification_directory=$(mktemp -d /var/tmp/owntransit-install.XXXXXX) || fail "cannot create checksum workspace"
test "$(stat -f %u "$verification_directory")" -eq 0 && test "$(stat -f %g "$verification_directory")" -eq 0 && test "$(macos_mode "$verification_directory")" = 700 || fail "checksum workspace is not private and root:wheel owned"
require_no_extended_acl "$verification_directory"
seen_paths="$verification_directory/seen-paths"
cleanup_seen() { rm -rf "$verification_directory"; }
trap cleanup_seen EXIT HUP INT TERM
: > "$seen_paths"
checksum_count=0
while read -r expected path extra; do
  test -z "${extra:-}" || fail "SHA256SUMS contains an invalid line"
  valid_digest "${expected:-}" || fail "SHA256SUMS contains a non-canonical digest"
  case "${path:-}" in
    ''|/*|*[!A-Za-z0-9._/+:-]*) fail "SHA256SUMS contains an unsafe path" ;;
  esac
  case "/$path/" in
    */../*|*/./*|*//*) fail "SHA256SUMS contains path traversal" ;;
  esac
  test "$path" != SHA256SUMS || fail "SHA256SUMS must not list itself"
  grep -Fqx "$path" "$seen_paths" && fail "SHA256SUMS contains a duplicate path"
  printf '%s\n' "$path" >> "$seen_paths"
  candidate="$bundle/$path"
  require_root_owned_regular "$candidate"
  test "$(sha256_file "$candidate")" = "$expected" || fail "checksum mismatch: $path"
  checksum_count=$((checksum_count + 1))
done < "$checksums"
test "$checksum_count" -gt 0 || fail "SHA256SUMS is empty"
actual_file_count=$(find "$bundle" -type f -print | wc -l | tr -d '[:space:]')
test "$actual_file_count" -eq $((checksum_count + 1)) || fail "bundle contains a file absent from SHA256SUMS"

listed_digest() {
  listed_path=$1
  listed_value=$(awk -v wanted="$listed_path" '$2 == wanted { print $1 }' "$checksums")
  valid_digest "$listed_value" || fail "required bundle member is absent from SHA256SUMS: $listed_path"
  printf '%s\n' "$listed_value"
}

bundled_installer="$bundle/packaging/scripts/install-macos.sh"
test "$(listed_digest packaging/scripts/install-macos.sh)" = "$(sha256_file "$bundled_installer")" || fail "macOS installer is not authenticated by SHA256SUMS"
case "$0" in
  /*) ;;
  *) fail "installer must be invoked by its absolute protected bundle path" ;;
esac
test ! -L "$0" || fail "installer entry point must not be a symlink"
test "$0" = "$bundled_installer" || fail "installer must run directly from the selected protected bundle"
require_root_owned_regular "$bundled_installer"
cmp -s "$0" "$bundled_installer" || fail "running installer is not the checksummed bundle copy"
build_inputs="$bundle/BUILD-INPUTS"
test "$(listed_digest BUILD-INPUTS)" = "$(sha256_file "$build_inputs")" || fail "BUILD-INPUTS is not authenticated by SHA256SUMS"
{
  IFS= read -r build_version_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r build_release_id_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r build_release_sequence_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r build_source_commit_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r build_source_date_epoch_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r build_source_manifest_line || fail "BUILD-INPUTS is incomplete"
  if IFS= read -r build_extra_line; then
    fail "BUILD-INPUTS contains an unexpected extra line"
  fi
} < "$build_inputs"
case "$build_version_line" in version=*) candidate_version=${build_version_line#version=} ;; *) fail "BUILD-INPUTS version field is invalid" ;; esac
case "$build_release_id_line" in release_id=*) build_release_id=${build_release_id_line#release_id=} ;; *) fail "BUILD-INPUTS release ID field is invalid" ;; esac
case "$build_release_sequence_line" in release_sequence=*) build_release_sequence=${build_release_sequence_line#release_sequence=} ;; *) fail "BUILD-INPUTS release sequence field is invalid" ;; esac
case "$build_source_commit_line" in source_commit=*) build_source_commit=${build_source_commit_line#source_commit=} ;; *) fail "BUILD-INPUTS source commit field is invalid" ;; esac
case "$build_source_date_epoch_line" in source_date_epoch=*) build_source_date_epoch=${build_source_date_epoch_line#source_date_epoch=} ;; *) fail "BUILD-INPUTS source date field is invalid" ;; esac
case "$build_source_manifest_line" in source_manifest_sha256=*) build_source_manifest=${build_source_manifest_line#source_manifest_sha256=} ;; *) fail "BUILD-INPUTS source manifest field is invalid" ;; esac
case "$candidate_version" in ''|*[!A-Za-z0-9._+-]*|[!A-Za-z0-9]*) fail "BUILD-INPUTS version is unsafe" ;; esac
test "${#candidate_version}" -le 64 || fail "BUILD-INPUTS version is too long"
test "$build_release_id" = "$release_id" || fail "bundle release ID does not match --release-id"
case "$build_release_sequence" in ''|0|0*|*[!0-9]*) fail "BUILD-INPUTS release sequence is not canonical positive decimal" ;; esac
test "${#build_release_sequence}" -le 20 || fail "BUILD-INPUTS release sequence is out of range"
case "$build_source_commit" in ''|*[!0-9a-f]*) fail "BUILD-INPUTS source commit is invalid" ;; esac
case "${#build_source_commit}" in 40|64) ;; *) fail "BUILD-INPUTS source commit length is invalid" ;; esac
case "$build_source_date_epoch" in ''|*[!0-9]*) fail "BUILD-INPUTS source date is invalid" ;; esac
test "${#build_source_date_epoch}" -le 10 && test "$build_source_date_epoch" -gt 0 || fail "BUILD-INPUTS source date is out of range"
valid_digest "$build_source_manifest" || fail "BUILD-INPUTS source manifest digest is invalid"
project_license_path=LICENSE
third_party_licenses_path=evidence/THIRD_PARTY_LICENSES.txt
test "$(listed_digest "$project_license_path")" = "$(sha256_file "$bundle/$project_license_path")" || fail "project license is not authenticated by SHA256SUMS"
test "$(listed_digest "$third_party_licenses_path")" = "$(sha256_file "$bundle/$third_party_licenses_path")" || fail "third-party licenses are not authenticated by SHA256SUMS"
artifact_path="artifacts/$artifact_name"
test "$(listed_digest "$artifact_path")" = "$artifact_sha256" || fail "selected artifact digest does not match the authenticated release"
if test "$needs_lifecycle" = yes; then
  manifest_path="$bundle/RELEASE-MANIFEST.json"
  test "$(listed_digest RELEASE-MANIFEST.json)" = "$(sha256_file "$manifest_path")" || fail "release manifest is not authenticated by SHA256SUMS"
  lifecycle_path=artifacts/owntransitctl-darwin-arm64
  test "$(listed_digest "$lifecycle_path")" = "$lifecycle_sha256" || fail "lifecycle artifact digest does not match the authenticated release"
  if test "$role" = client; then
    launcher_path=artifacts/owntransit-launcher-darwin-arm64
    test "$(listed_digest "$launcher_path")" = "$launcher_sha256" || fail "client launcher artifact digest does not match the authenticated release"
  fi
  for signed_input in "$manifest_signature" "$release_public_key" "$policy" "$policy_signature" "$policy_public_key"; do
    require_root_owned_regular "$signed_input"
    signed_parent=$(CDPATH= cd -P -- "$(dirname "$signed_input")" && pwd) || fail "cannot resolve signed input parent"
    signed_resolved="$signed_parent/$(basename "$signed_input")"
    test "$signed_resolved" = "$signed_input" || fail "signed input path must be canonical and contain no symlinked parent"
    case "$signed_input" in
      "$bundle"|"$bundle"/*) fail "release/policy trust input must remain outside the candidate bundle" ;;
    esac
  done
fi

ensure_root_directory() {
  directory=$1
  permissions=$2
  if test -e "$directory" || test -L "$directory"; then
    test -d "$directory" && test ! -L "$directory" || fail "$directory is not a regular directory"
    test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" -eq 0 || fail "$directory is not root:wheel owned"
    test "$(macos_mode "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
  else
    install -d -o root -g wheel -m "$permissions" "$directory"
  fi
  require_no_extended_acl "$directory"
}

ensure_reader_directory() {
  directory=$1
  permissions=$2
  if test -e "$directory" || test -L "$directory"; then
    test -d "$directory" && test ! -L "$directory" || fail "$directory is not a regular directory"
    test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" = "$reader_gid" || fail "$directory is not root:reader owned"
    test "$(macos_mode "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
  else
    install -d -o root -g wheel -m 0700 "$directory"
    chown "0:$reader_gid" "$directory"
    chmod "$permissions" "$directory"
  fi
  require_no_extended_acl "$directory"
}

valid_positive_id() {
  numeric_id=$1
  case "$numeric_id" in
    ''|0|0*|*[!0-9]*) return 1 ;;
  esac
  test "${#numeric_id}" -le 10 || return 1
  test "$numeric_id" -le 2147483646
}

valid_generated_uid() {
  printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
}

plist_array_count() {
  plist_file=$1
  plist_key=$2
  /usr/bin/plutil -extract "$plist_key" raw -expect array -o - "$plist_file" 2>/dev/null
}

plist_array_value() {
  plist_file=$1
  plist_key=$2
  plist_index=$3
  /usr/bin/plutil -extract "$plist_key.$plist_index" raw -expect string -n -o - "$plist_file" 2>/dev/null
}

plist_array_absent_or_empty() {
  plist_file=$1
  plist_key=$2
  if /usr/bin/plutil -type "$plist_key" "$plist_file" >/dev/null 2>&1; then
    test "$(plist_array_count "$plist_file" "$plist_key")" -eq 0
  fi
}

read_directory_record() {
  directory_node=$1
  record_path=$2
  record_output=$3
  /usr/bin/dscl -plist "$directory_node" -read "$record_path" > "$record_output" 2>/dev/null ||
    fail "cannot read exact Directory Services record: $directory_node $record_path"
  /usr/bin/plutil -lint -s "$record_output" || fail "Directory Services returned a malformed record: $record_path"
}

read_directory_list() {
  directory_node=$1
  record_path=$2
  attribute=$3
  list_output=$4
  if test -n "$attribute"; then
    /usr/bin/dscl "$directory_node" -list "$record_path" "$attribute" > "$list_output" 2>/dev/null ||
      fail "cannot enumerate Directory Services $record_path $attribute on $directory_node"
  else
    /usr/bin/dscl "$directory_node" -list "$record_path" > "$list_output" 2>/dev/null ||
      fail "cannot enumerate Directory Services $record_path on $directory_node"
  fi
}

record_name_count() {
  list_file=$1
  expected_name=$2
  awk -v expected="$expected_name" '$0 == expected { count++ } END { print count + 0 }' "$list_file"
}

assert_unique_numeric_owner() {
  list_file=$1
  numeric_value=$2
  expected_name=$3
  description=$4
  awk -v wanted="$numeric_value" -v expected="$expected_name" '
    $NF == wanted {
      count++
      if (NF == 2 && $1 == expected) exact++
    }
    END { exit !(count == 1 && exact == 1) }
  ' "$list_file" || fail "$description is missing, duplicated, ambiguous, or owned by another record"
}

assert_numeric_unowned() {
  list_file=$1
  numeric_value=$2
  description=$3
  awk -v wanted="$numeric_value" '$NF == wanted { found = 1 } END { exit found ? 1 : 0 }' "$list_file" ||
    fail "$description is already assigned"
}

numeric_value_is_owned() {
  list_file=$1
  numeric_value=$2
  awk -v wanted="$numeric_value" '$NF == wanted { found = 1 } END { exit found ? 0 : 1 }' "$list_file"
}

load_user_record() {
  user_plist=$1
  expected_user=$2
  record_name_key='dsAttrTypeStandard:RecordName'
  unique_id_key='dsAttrTypeStandard:UniqueID'
  primary_gid_key='dsAttrTypeStandard:PrimaryGroupID'
  generated_uid_key='dsAttrTypeStandard:GeneratedUID'

  record_name_count_value=$(plist_array_count "$user_plist" "$record_name_key") || fail "user RecordName is absent or malformed"
  valid_positive_id "$record_name_count_value" || fail "user RecordName array is empty or malformed"
  record_name_value=$(plist_array_value "$user_plist" "$record_name_key" 0) || fail "user canonical RecordName is malformed"
  test "$record_name_value" = "$expected_user" || fail "Directory Services canonical user name does not match --client-user"

  test "$(plist_array_count "$user_plist" "$unique_id_key")" -eq 1 || fail "user UniqueID is not singular"
  loaded_user_uid=$(plist_array_value "$user_plist" "$unique_id_key" 0) || fail "user UniqueID is malformed"
  valid_positive_id "$loaded_user_uid" || fail "user UniqueID is zero, sentinel, or non-canonical"

  test "$(plist_array_count "$user_plist" "$primary_gid_key")" -eq 1 || fail "user PrimaryGroupID is not singular"
  loaded_user_primary_gid=$(plist_array_value "$user_plist" "$primary_gid_key" 0) || fail "user PrimaryGroupID is malformed"
  valid_positive_id "$loaded_user_primary_gid" || fail "user PrimaryGroupID is zero, sentinel, or non-canonical"

  test "$(plist_array_count "$user_plist" "$generated_uid_key")" -eq 1 || fail "user GeneratedUID is not singular"
  loaded_user_uuid=$(plist_array_value "$user_plist" "$generated_uid_key" 0) || fail "user GeneratedUID is malformed"
  valid_generated_uid "$loaded_user_uuid" || fail "user GeneratedUID is not canonical"
}

verify_group_record() {
  group_plist=$1
  expected_gid=$2
  record_name_key='dsAttrTypeStandard:RecordName'
  primary_gid_key='dsAttrTypeStandard:PrimaryGroupID'
  generated_uid_key='dsAttrTypeStandard:GeneratedUID'
  membership_key='dsAttrTypeStandard:GroupMembership'
  members_key='dsAttrTypeStandard:GroupMembers'
  nested_key='dsAttrTypeStandard:NestedGroups'

  test "$(/usr/bin/plutil -type "$record_name_key" "$group_plist" 2>/dev/null)" = array || fail "plutil cannot prove Directory Services attribute types"
  test "$(plist_array_count "$group_plist" "$record_name_key")" -eq 1 || fail "reader group RecordName is not singular"
  test "$(plist_array_value "$group_plist" "$record_name_key" 0)" = _owntransit || fail "reader group RecordName changed"
  test "$(plist_array_count "$group_plist" "$primary_gid_key")" -eq 1 || fail "reader group PrimaryGroupID is not singular"
  test "$(plist_array_value "$group_plist" "$primary_gid_key" 0)" = "$expected_gid" || fail "reader group GID changed"
  test "$(plist_array_count "$group_plist" "$generated_uid_key")" -eq 1 || fail "reader group GeneratedUID is not singular"
  verified_group_uuid=$(plist_array_value "$group_plist" "$generated_uid_key" 0) || fail "reader group GeneratedUID is malformed"
  valid_generated_uid "$verified_group_uuid" || fail "reader group GeneratedUID is not canonical"
  plist_array_absent_or_empty "$group_plist" "$membership_key" || fail "reader group has a named member or malformed membership attribute"
  plist_array_absent_or_empty "$group_plist" "$members_key" || fail "reader group has a UUID member or malformed member attribute"
  plist_array_absent_or_empty "$group_plist" "$nested_key" || fail "reader group has a nested group or malformed nesting attribute"
}

require_reader_receipt_protected() {
  test -d "$identity_directory" && test ! -L "$identity_directory" || fail "client reader identity directory is absent or not regular"
  test "$(stat -f %u "$identity_directory")" -eq 0 && test "$(stat -f %g "$identity_directory")" -eq 0 || fail "client reader identity directory is not root:wheel owned"
  test "$(macos_mode "$identity_directory")" = 700 || fail "client reader identity directory mode is not 0700"
  require_no_extended_acl "$identity_directory"
  test -f "$reader_receipt" && test ! -L "$reader_receipt" || fail "client reader identity receipt is absent or not regular"
  test "$(stat -f %u "$reader_receipt")" -eq 0 && test "$(stat -f %g "$reader_receipt")" -eq 0 || fail "client reader identity receipt is not root:wheel owned"
  test "$(macos_mode "$reader_receipt")" = 600 || fail "client reader identity receipt mode is not 0600"
  test "$(stat -f %l "$reader_receipt")" -eq 1 || fail "client reader identity receipt has multiple hard links"
  require_no_extended_acl "$reader_receipt"
}

load_reader_receipt() {
  require_reader_receipt_protected
  test "$(wc -l < "$reader_receipt" | tr -d '[:space:]')" -eq 8 || fail "client reader identity receipt has the wrong line count"
  receipt_schema=$(sed -n '1{s/^schema=//p;}' "$reader_receipt")
  receipt_user=$(sed -n '2{s/^client_user=//p;}' "$reader_receipt")
  receipt_uid=$(sed -n '3{s/^client_uid=//p;}' "$reader_receipt")
  receipt_primary_gid=$(sed -n '4{s/^client_primary_gid=//p;}' "$reader_receipt")
  receipt_user_uuid=$(sed -n '5{s/^client_uuid=//p;}' "$reader_receipt")
  receipt_group=$(sed -n '6{s/^reader_group=//p;}' "$reader_receipt")
  receipt_gid=$(sed -n '7{s/^reader_gid=//p;}' "$reader_receipt")
  receipt_group_uuid=$(sed -n '8{s/^reader_group_uuid=//p;}' "$reader_receipt")
  receipt_expected=$(printf '%s\n' \
    "schema=$receipt_schema" \
    "client_user=$receipt_user" \
    "client_uid=$receipt_uid" \
    "client_primary_gid=$receipt_primary_gid" \
    "client_uuid=$receipt_user_uuid" \
    "reader_group=$receipt_group" \
    "reader_gid=$receipt_gid" \
    "reader_group_uuid=$receipt_group_uuid")
  test "$(cat "$reader_receipt")" = "$receipt_expected" || fail "client reader identity receipt is malformed or has unknown fields"
  test "$receipt_schema" = owntransit.macos-client-reader.v1 || fail "client reader identity receipt schema is unsupported"
  case "$receipt_user" in ''|*[!A-Za-z0-9._-]*|-*) fail "client reader identity receipt user is unsafe" ;; esac
  test "$receipt_user" = "$client_user" || fail "--client-user does not match the protected identity receipt"
  valid_positive_id "$receipt_uid" || fail "client reader identity receipt UID is invalid"
  valid_positive_id "$receipt_primary_gid" || fail "client reader identity receipt primary GID is invalid"
  valid_generated_uid "$receipt_user_uuid" || fail "client reader identity receipt user GeneratedUID is invalid"
  test "$receipt_group" = _owntransit || fail "client reader identity receipt group is unsupported"
  valid_positive_id "$receipt_gid" || fail "client reader identity receipt GID is invalid"
  test "$receipt_gid" -ge 5000 && test "$receipt_gid" -le 59999 || fail "client reader identity receipt GID is outside the dedicated range"
  valid_generated_uid "$receipt_group_uuid" || fail "client reader identity receipt group GeneratedUID is invalid"
}

write_reader_receipt() {
  test ! -e "$reader_receipt" && test ! -L "$reader_receipt" || fail "client reader identity receipt appeared concurrently"
  reader_receipt_temporary=$(mktemp "$identity_directory/.client-reader.v1.XXXXXX") || fail "cannot create client reader identity receipt"
  test "$(stat -f %u "$reader_receipt_temporary")" -eq 0 && test "$(stat -f %g "$reader_receipt_temporary")" -eq 0 || fail "temporary identity receipt is not root:wheel owned"
  test "$(macos_mode "$reader_receipt_temporary")" = 600 || fail "temporary identity receipt mode is not 0600"
  require_no_extended_acl "$reader_receipt_temporary"
  printf '%s\n' \
    'schema=owntransit.macos-client-reader.v1' \
    "client_user=$client_user" \
    "client_uid=$client_uid" \
    "client_primary_gid=$client_primary_gid" \
    "client_uuid=$client_uuid" \
    'reader_group=_owntransit' \
    "reader_gid=$reader_gid" \
    "reader_group_uuid=$reader_group_uuid" > "$reader_receipt_temporary"
  chmod 0600 "$reader_receipt_temporary"
  require_no_extended_acl "$reader_receipt_temporary"
  mv "$reader_receipt_temporary" "$reader_receipt"
  reader_receipt_temporary=
  load_reader_receipt
}

refresh_directory_facts() {
  local_group_names="$verification_directory/local-group-names"
  search_group_names="$verification_directory/search-group-names"
  local_group_gids="$verification_directory/local-group-gids"
  search_group_gids="$verification_directory/search-group-gids"
  local_user_uids="$verification_directory/local-user-uids"
  search_user_uids="$verification_directory/search-user-uids"
  local_user_primary_gids="$verification_directory/local-user-primary-gids"
  search_user_primary_gids="$verification_directory/search-user-primary-gids"
  read_directory_list . /Groups '' "$local_group_names"
  read_directory_list /Search /Groups '' "$search_group_names"
  read_directory_list . /Groups PrimaryGroupID "$local_group_gids"
  read_directory_list /Search /Groups PrimaryGroupID "$search_group_gids"
  read_directory_list . /Users UniqueID "$local_user_uids"
  read_directory_list /Search /Users UniqueID "$search_user_uids"
  read_directory_list . /Users PrimaryGroupID "$local_user_primary_gids"
  read_directory_list /Search /Users PrimaryGroupID "$search_user_primary_gids"
}

verify_client_user_identity() {
  local_user_plist="$verification_directory/local-client-user.plist"
  search_user_plist="$verification_directory/search-client-user.plist"
  user_records=/Users
  read_directory_record . "$user_records/$client_user" "$local_user_plist"
  load_user_record "$local_user_plist" "$client_user"
  client_uid=$loaded_user_uid
  client_primary_gid=$loaded_user_primary_gid
  client_uuid=$loaded_user_uuid
  read_directory_record /Search "$user_records/$client_user" "$search_user_plist"
  load_user_record "$search_user_plist" "$client_user"
  test "$loaded_user_uid" = "$client_uid" || fail "search-policy user UID does not match the local user"
  test "$loaded_user_primary_gid" = "$client_primary_gid" || fail "search-policy user primary GID does not match the local user"
  test "$loaded_user_uuid" = "$client_uuid" || fail "search-policy user GeneratedUID does not match the local user"
  assert_unique_numeric_owner "$local_user_uids" "$client_uid" "$client_user" "local user UID $client_uid"
  assert_unique_numeric_owner "$search_user_uids" "$client_uid" "$client_user" "search-policy user UID $client_uid"
  test "$(/usr/bin/id -u "$client_user")" = "$client_uid" || fail "system user lookup does not resolve --client-user to its local UID"
  test "$(/usr/bin/id -un "$client_uid")" = "$client_user" || fail "system UID lookup does not resolve to the canonical --client-user"
  test "$(/usr/bin/id -g "$client_user")" = "$client_primary_gid" || fail "system user lookup does not resolve the exact primary GID"
}

allocate_reader_gid() {
  reader_gid=5000
  while test "$reader_gid" -le 59999; do
    if ! numeric_value_is_owned "$local_group_gids" "$reader_gid" &&
       ! numeric_value_is_owned "$search_group_gids" "$reader_gid" &&
       ! numeric_value_is_owned "$local_user_primary_gids" "$reader_gid" &&
       ! numeric_value_is_owned "$search_user_primary_gids" "$reader_gid"; then
      return 0
    fi
    reader_gid=$((reader_gid + 1))
  done
  fail "no collision-free dedicated reader GID is available in 5000..59999"
}

verify_reader_group_live() {
  expected_group_uuid=${1:-}
  refresh_directory_facts
  test "$(record_name_count "$local_group_names" _owntransit)" -eq 1 || fail "local reader group name is absent or ambiguous"
  test "$(record_name_count "$search_group_names" _owntransit)" -eq 1 || fail "search-policy reader group name is absent or ambiguous"
  assert_unique_numeric_owner "$local_group_gids" "$reader_gid" _owntransit "local reader GID $reader_gid"
  assert_unique_numeric_owner "$search_group_gids" "$reader_gid" _owntransit "search-policy reader GID $reader_gid"
  assert_numeric_unowned "$local_user_primary_gids" "$reader_gid" "local user primary GID $reader_gid"
  assert_numeric_unowned "$search_user_primary_gids" "$reader_gid" "search-policy user primary GID $reader_gid"

  local_group_plist="$verification_directory/local-reader-group.plist"
  search_group_plist="$verification_directory/search-reader-group.plist"
  read_directory_record . /Groups/_owntransit "$local_group_plist"
  verify_group_record "$local_group_plist" "$reader_gid"
  local_group_uuid=$verified_group_uuid
  read_directory_record /Search /Groups/_owntransit "$search_group_plist"
  verify_group_record "$search_group_plist" "$reader_gid"
  test "$verified_group_uuid" = "$local_group_uuid" || fail "search-policy reader group does not resolve to the local group UUID"
  if test -n "$expected_group_uuid"; then
    test "$local_group_uuid" = "$expected_group_uuid" || fail "reader group GeneratedUID does not match the protected identity receipt"
  fi
  reader_group_uuid=$local_group_uuid

  /usr/bin/dsmemberutil flushcache >/dev/null 2>&1 || fail "cannot flush Directory Services membership cache"
  membership_result=$(/usr/bin/dsmemberutil checkmembership -u "$client_uid" -g "$reader_gid" 2>/dev/null) || fail "cannot verify client reader exclusion"
  test "$membership_result" = 'user is not a member of the group' || fail "client user is unexpectedly an effective member of the reader group"
  client_group_ids=$(/usr/bin/id -G "$client_user") || fail "cannot resolve client user supplementary groups"
  printf '%s\n' "$client_group_ids" | awk -v wanted="$reader_gid" '
    { for (field_number = 1; field_number <= NF; field_number++) if ($field_number == wanted) found = 1 }
    END { exit found ? 1 : 0 }
  ' || fail "client user effective group vector contains the reader GID"
}

prepare_client_reader_identity() {
  reader_group_name=_owntransit
  identity_directory="$install_root/identity"
  reader_receipt="$identity_directory/client-reader.v1"
  reader_receipt_temporary=
  refresh_directory_facts
  verify_client_user_identity

  local_group_count=$(record_name_count "$local_group_names" "$reader_group_name")
  search_group_count=$(record_name_count "$search_group_names" "$reader_group_name")
  receipt_present=no
  if test -e "$reader_receipt" || test -L "$reader_receipt"; then
    receipt_present=yes
  fi

  if test "$local_group_count" -eq 0 && test "$search_group_count" -eq 0 && test "$receipt_present" = no; then
    test ! -e "$identity_directory" && test ! -L "$identity_directory" || fail "identity directory exists without its receipt; manual residue review is required"
    ensure_root_directory "$identity_directory" 700
    allocate_reader_gid
    identity_mutation_attempted=yes
    /usr/sbin/dseditgroup -q -o create -n . -i "$reader_gid" "$reader_group_name" >/dev/null 2>&1 ||
      fail "dedicated reader group creation failed; manual residue review is required"
    verify_reader_group_live ''
    write_reader_receipt
    identity_mode=created
    return 0
  fi

  if test "$local_group_count" -eq 1 && test "$search_group_count" -eq 1 && test "$receipt_present" = yes; then
    load_reader_receipt
    test "$receipt_uid" = "$client_uid" || fail "protected identity receipt UID does not match the live local user"
    test "$receipt_primary_gid" = "$client_primary_gid" || fail "protected identity receipt primary GID does not match the live local user"
    test "$receipt_user_uuid" = "$client_uuid" || fail "protected identity receipt GeneratedUID does not match the live local user"
    reader_gid=$receipt_gid
    verify_reader_group_live "$receipt_group_uuid"
    identity_mode=adopted
    return 0
  fi

  fail "reader group/receipt state is missing, reused, ambiguous, or partially mutated; manual residue review is required"
}

run_as_uid() {
  target_uid=$1
  shift
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C \
    /usr/bin/sudo -n -u "#$target_uid" -- "$@"
}

numeric_owner_is_exact() {
  list_file=$1
  numeric_value=$2
  expected_name=$3
  awk -v wanted="$numeric_value" -v expected="$expected_name" '
    $NF == wanted {
      count++
      if (NF == 2 && $1 == expected) exact++
    }
    END { exit count == 1 && exact == 1 ? 0 : 1 }
  ' "$list_file"
}

choose_unrelated_local_uid() {
  unrelated_user=
  unrelated_uid=
  while IFS=' ' read -r candidate_user candidate_uid candidate_extra; do
    test -z "${candidate_extra:-}" || continue
    case "$candidate_user" in ''|*[!A-Za-z0-9._-]*|-*) continue ;; esac
    valid_positive_id "$candidate_uid" || continue
    test "$candidate_uid" != "$client_uid" || continue
    numeric_owner_is_exact "$local_user_uids" "$candidate_uid" "$candidate_user" || continue
    numeric_owner_is_exact "$search_user_uids" "$candidate_uid" "$candidate_user" || continue
    test "$(/usr/bin/id -u "$candidate_user" 2>/dev/null || true)" = "$candidate_uid" || continue
    candidate_control=$(run_as_uid "$candidate_uid" /usr/bin/id -u 2>/dev/null || true)
    test "$candidate_control" = "$candidate_uid" || continue
    unrelated_user=$candidate_user
    unrelated_uid=$candidate_uid
    break
  done < "$local_user_uids"
  test -n "$unrelated_uid" || fail "no unambiguous unrelated local user is available for the permission probe"
}

verify_client_executable_boundary() {
	release_launcher=$1
	public_launcher=$2
	client_real=$3
	for client_launcher in "$release_launcher" "$public_launcher"; do
		test -f "$client_launcher" && test ! -L "$client_launcher" || fail "client launcher is not a regular non-symlink file: $client_launcher"
		test "$(stat -f %u "$client_launcher")" -eq 0 && test "$(stat -f %g "$client_launcher")" = "$reader_gid" || fail "client launcher is not root:reader owned: $client_launcher"
		test "$(macos_mode "$client_launcher")" = 2751 || fail "client launcher mode is not setgid 2751: $client_launcher"
		test "$(stat -f %l "$client_launcher")" -eq 1 || fail "client launcher is not a fresh single-link inode: $client_launcher"
		require_no_extended_acl "$client_launcher"
		test "$(sha256_file "$client_launcher")" = "$launcher_sha256" || fail "authenticated client launcher changed during installation: $client_launcher"
	done
	test "$(stat -f '%d:%i' "$release_launcher")" != "$(stat -f '%d:%i' "$public_launcher")" || fail "public launcher is a hard link to the protected release launcher"

  test -f "$client_real" && test ! -L "$client_real" || fail "real client is not a regular non-symlink file"
  test "$(stat -f %u "$client_real")" -eq 0 && test "$(stat -f %g "$client_real")" = "$reader_gid" || fail "real client is not root:reader owned"
  test "$(macos_mode "$client_real")" = 750 || fail "real client mode is not 0750"
  test "$(stat -f %l "$client_real")" -eq 1 || fail "real client is not a fresh single-link inode"
  require_no_extended_acl "$client_real"
  test "$(sha256_file "$client_real")" = "$artifact_sha256" || fail "authenticated real client changed during installation"

  target_control=$(run_as_uid "$client_uid" /usr/bin/id -u 2>/dev/null) || fail "cannot execute a fixed control command as --client-user"
  test "$target_control" = "$client_uid" || fail "client-user control command ran as the wrong UID"
  if run_as_uid "$client_uid" /bin/test -r "$launcher_binding"; then fail "ordinary client-user process can read the protected launcher binding"; fi
  if run_as_uid "$client_uid" /bin/cat "$launcher_binding" >/dev/null 2>&1; then fail "ordinary client-user process read protected launcher binding bytes"; fi
	if run_as_uid "$client_uid" /bin/test -r "$public_launcher"; then fail "client user can read the public setgid launcher"; fi
	run_as_uid "$client_uid" /bin/test -x "$public_launcher" || fail "client user cannot execute the public setgid launcher"
	if run_as_uid "$client_uid" /bin/test -x "$release_launcher"; then fail "client user can directly traverse and execute the protected release launcher"; fi
	if run_as_uid "$client_uid" /bin/test -w "$public_launcher"; then fail "client user can write the public client launcher"; fi
  if run_as_uid "$client_uid" /bin/test -w "$client_real"; then fail "client user can write the real client"; fi
  if run_as_uid "$client_uid" /bin/test -w "$(dirname "$client_real")"; then fail "client user can mutate the release directory"; fi
  if run_as_uid "$client_uid" "$client_real" verify-reader-gid "$reader_gid" >/dev/null 2>&1; then
    fail "direct real-client execution acquired reader authority without the launcher"
  fi
	run_as_uid "$client_uid" "$public_launcher" --qualify-reader-gid >/dev/null 2>&1 ||
		fail "authenticated launcher did not grant the exact reader EGID to the bound user"
	if run_as_uid "$client_uid" "$public_launcher" --config=/var/tmp/attacker >/dev/null 2>&1; then
    fail "launcher accepted caller-selected configuration"
  fi

  choose_unrelated_local_uid
  unrelated_membership=$(/usr/bin/dsmemberutil checkmembership -u "$unrelated_uid" -g "$reader_gid" 2>/dev/null) ||
    fail "cannot verify unrelated-user group exclusion"
  test "$unrelated_membership" = 'user is not a member of the group' || fail "unrelated user is unexpectedly a reader-group member"
  if run_as_uid "$unrelated_uid" /bin/test -r "$launcher_binding"; then fail "unrelated user can read the protected launcher binding"; fi
	if run_as_uid "$unrelated_uid" /bin/test -r "$public_launcher"; then fail "unrelated user can read the public setgid launcher"; fi
	run_as_uid "$unrelated_uid" /bin/test -x "$public_launcher" || fail "public setgid launcher is not reachable for its own UID authorization check"
	if run_as_uid "$unrelated_uid" "$public_launcher" --qualify-reader-gid >/dev/null 2>&1; then
    fail "unrelated user $unrelated_user passed the launcher's exact-UID authorization"
  fi

	test "$(sha256_file "$release_launcher")" = "$launcher_sha256" || fail "release launcher changed during permission probes"
	test "$(sha256_file "$public_launcher")" = "$launcher_sha256" || fail "public launcher changed during permission probes"
  test "$(sha256_file "$client_real")" = "$artifact_sha256" || fail "real client changed during permission probes"
  test -z "$(find "$install_root" -type f -perm -4000 -print)" || fail "installation root contains a setuid file"
}

require_package_mutation_lock_file() {
	mutation_lock="$launcher_stage_directory/package-mutation.v1.lock"
	test -f "$mutation_lock" && test ! -L "$mutation_lock" || fail "package-mutation lock is absent or not regular"
	test "$(stat -f %u "$mutation_lock")" -eq 0 && test "$(stat -f %g "$mutation_lock")" -eq 0 ||
		fail "package-mutation lock is not root:wheel owned"
	test "$(macos_mode "$mutation_lock")" = 600 && test "$(stat -f %l "$mutation_lock")" -eq 1 &&
		test "$(stat -f %z "$mutation_lock")" -eq 0 || fail "package-mutation lock metadata is invalid"
	require_no_extended_acl "$mutation_lock"
}

require_package_mutation_lock() {
	test "$(ls -A "$launcher_stage_directory")" = package-mutation.v1.lock ||
		fail "private launcher stage contains missing or unexpected transaction state"
	require_package_mutation_lock_file
}

prepare_package_mutation_lock() {
	mutation_lock="$launcher_stage_directory/package-mutation.v1.lock"
	if test ! -e "$mutation_lock" && test ! -L "$mutation_lock"; then
		# noclobber makes concurrent creation fail without replacing an inode
		# another installer may already have locked.
		(set -C; : > "$mutation_lock") 2>/dev/null || true
	fi
	require_package_mutation_lock_file
}

require_selected_lifecycle_directory() {
  selected_directory=$1
  test -d "$selected_directory" && test ! -L "$selected_directory" ||
    fail "selected lifecycle ancestor is not a regular directory: $selected_directory"
  test "$(stat -f %u "$selected_directory")" -eq 0 ||
    fail "selected lifecycle ancestor is not root-owned: $selected_directory"
  selected_mode=$(macos_mode "$selected_directory") ||
    fail "cannot inspect selected lifecycle ancestor mode: $selected_directory"
  case "$selected_mode" in [0-7][0-7][0-7]) ;; *) fail "selected lifecycle ancestor mode is non-canonical: $selected_directory" ;; esac
  test $((0$selected_mode & 022)) -eq 0 ||
    fail "selected lifecycle ancestor is group/world writable: $selected_directory"
  require_no_extended_acl "$selected_directory"
}

guard_retained_prerelease_install() {
  selected_current_link="/Library/OwnTransit/roles/$role/current"
  test -e "$selected_current_link" || test -L "$selected_current_link" || return 0

  for selected_directory in \
    / /Library /Library/OwnTransit /Library/OwnTransit/roles \
    "/Library/OwnTransit/roles/$role" "/Library/OwnTransit/roles/$role/releases"; do
    require_selected_lifecycle_directory "$selected_directory"
  done
  test -L "$selected_current_link" || fail "role current selector exists and is not a symlink"
  selected_target=$(readlink "$selected_current_link")
  case "$selected_target" in releases/*) selected_release=${selected_target#releases/} ;; *) fail "role current selector has an invalid target" ;; esac
  case "$selected_release" in *[!a-z2-7]*|'') fail "role current selector has an invalid release ID" ;; esac
  test "${#selected_release}" -eq 52 || fail "role current selector release ID has the wrong length"
  case "$selected_release" in *[aq]) ;; *) fail "role current selector release ID is non-canonical" ;; esac
  test "$selected_release" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "role current selector release ID is zero"
  test "$selected_target" = "releases/$selected_release" || fail "role current selector target is not canonical"

  selected_release_directory="/Library/OwnTransit/roles/$role/releases/$selected_release"
  require_selected_lifecycle_directory "$selected_release_directory"
  selected_lifecycle="$selected_release_directory/owntransitctl"
  test -f "$selected_lifecycle" && test ! -L "$selected_lifecycle" || fail "selected lifecycle executable is absent or not regular"
  test "$(stat -f %u "$selected_lifecycle")" -eq 0 && test "$(stat -f %g "$selected_lifecycle")" -eq 0 || fail "selected lifecycle executable is not root:wheel owned"
  test "$(macos_mode "$selected_lifecycle")" = 700 && test "$(stat -f %l "$selected_lifecycle")" -eq 1 || fail "selected lifecycle executable metadata is invalid"
  require_no_extended_acl "$selected_lifecycle"
  selected_version=$(inspect_canonical_lifecycle_version "$selected_lifecycle" "$selected_release" selected)

  if test "$candidate_version" = 0.1.0 && is_owntransit_010_release_candidate "$selected_version"; then
    fail "selected $role role retains OwnTransit $selected_version state and cannot be replaced by stable 0.1.0. Do not purge it: preserve the retained role state for recovery; use a different unused role state or another host for this role"
  fi
}

guard_retained_prerelease_install

install_root=/Library/OwnTransit
roles_root="$install_root/roles"
bin_directory="$install_root/bin"
launcher_auth_directory="$install_root/launcher-auth"
launcher_stage_directory="$install_root/launcher-stage"
launcher_binding="$launcher_auth_directory/client.v1"
reader_receipt_temporary=
identity_mutation_attempted=no

cleanup_install() {
  test -z "$reader_receipt_temporary" || rm -f -- "$reader_receipt_temporary"
  rm -rf -- "$verification_directory"
  if test "$identity_mutation_attempted" = yes; then
    printf '%s\n' 'install-macos: dedicated zero-member reader identity mutation was attempted; the protected group/receipt remains for exact retry and must be reviewed before choosing another identity' >&2
  fi
}
trap cleanup_install EXIT HUP INT TERM

ensure_root_directory /Library 755
ensure_root_directory "$install_root" 755
ensure_root_directory "$bin_directory" 755
ensure_root_directory "$roles_root" 755
ensure_root_directory /private/var/db/OwnTransit 755
ensure_root_directory /private/var/db/OwnTransit/package-rollback 700
ensure_root_directory "$launcher_stage_directory" 700
if test "$role" = client; then
  ensure_root_directory "$install_root/client" 755
  ensure_root_directory /private/var/db/OwnTransit/client 755
	prepare_client_reader_identity
	ensure_reader_directory "$launcher_auth_directory" 750
fi

lifecycle_candidate="$bundle/$lifecycle_path"
lifecycle_runner=$lifecycle_candidate
legacy_unlocked_lifecycle=no
current_link="$roles_root/$role/current"
if test -e "$current_link" || test -L "$current_link"; then
  test -L "$current_link" || fail "role current selector exists and is not a symlink"
  current_target=$(readlink "$current_link")
  case "$current_target" in
    releases/*) current_release=${current_target#releases/} ;;
    *) fail "role current selector has an invalid target" ;;
  esac
  case "$current_release" in *[!a-z2-7]*|'') fail "role current selector has an invalid release ID" ;; esac
  test "${#current_release}" -eq 52 || fail "role current selector release ID has the wrong length"
  case "$current_release" in *[aq]) ;; *) fail "role current selector release ID is non-canonical" ;; esac
  test "$current_release" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "role current selector release ID is zero"
  test "$current_target" = "releases/$current_release" || fail "role current selector target is not canonical"
  lifecycle_runner="$roles_root/$role/releases/$current_release/owntransitctl"
  test -f "$lifecycle_runner" && test ! -L "$lifecycle_runner" || fail "selected lifecycle executable is absent or not regular"
  test "$(stat -f %u "$lifecycle_runner")" -eq 0 && test "$(stat -f %g "$lifecycle_runner")" -eq 0 || fail "selected lifecycle executable is not root:wheel owned"
  test "$(macos_mode "$lifecycle_runner")" = 700 && test "$(stat -f %l "$lifecycle_runner")" -eq 1 || fail "selected lifecycle executable metadata is invalid"
  require_no_extended_acl "$lifecycle_runner"
	current_lifecycle_sha256=$(sha256_file "$lifecycle_runner")
	# RC5-RC7 predate the lifecycle-owned package mutation guard. Keep only
	# these exact public ID+digest tuples behind the compatibility wrapper,
	# including an idempotent invocation with a legacy bundle. Unknown
	# predecessors fail closed; later releases must add their exact self-locking
	# predecessor tuple instead of guessing from an ID alone.
	if legacy_unlocked_lifecycle_tuple "$current_release" "$current_lifecycle_sha256"; then
		legacy_unlocked_lifecycle=yes
	else
		test "$current_release" = "$release_id" && test "$current_lifecycle_sha256" = "$lifecycle_sha256" ||
			fail "selected predecessor is not an authenticated supported macOS upgrade source"
	fi
fi

if test "$legacy_unlocked_lifecycle" = yes; then
	mutation_lock="$launcher_stage_directory/package-mutation.v1.lock"
	prepare_package_mutation_lock
	/usr/bin/lockf -k -n -t 0 "$mutation_lock" \
		/usr/bin/env -i \
			HOME=/var/root \
			LANG=C \
			LC_ALL=C \
			PATH=/usr/bin:/bin:/usr/sbin:/sbin \
			"$lifecycle_runner" package-apply \
				--role "$role" \
				--bundle "$bundle" \
				--manifest "$manifest_path" \
				--manifest-signature "$manifest_signature" \
				--release-public-key "$release_public_key" \
				--policy "$policy" \
				--policy-signature "$policy_signature" \
				--policy-public-key "$policy_public_key"
else
	/usr/bin/env -i \
		HOME=/var/root \
		LANG=C \
		LC_ALL=C \
		PATH=/usr/bin:/bin:/usr/sbin:/sbin \
		"$lifecycle_runner" package-apply \
			--role "$role" \
			--bundle "$bundle" \
			--manifest "$manifest_path" \
			--manifest-signature "$manifest_signature" \
			--release-public-key "$release_public_key" \
			--policy "$policy" \
			--policy-signature "$policy_signature" \
			--policy-public-key "$policy_public_key"
fi

test -L "$current_link" || fail "package transaction did not publish the role current selector"
test "$(readlink "$current_link")" = "releases/$release_id" || fail "package transaction selected another release"
release_directory="$roles_root/$role/releases/$release_id"

test "$(sha256_file "$release_directory/owntransitctl")" = "$lifecycle_sha256" || fail "installed lifecycle artifact changed"
test -f "$release_directory/owntransitctl" && test ! -L "$release_directory/owntransitctl" || fail "installed lifecycle artifact is absent or not regular"
test "$(stat -f %u "$release_directory/owntransitctl")" -eq 0 && test "$(stat -f %g "$release_directory/owntransitctl")" -eq 0 || fail "installed lifecycle artifact is not root:wheel owned"
test "$(macos_mode "$release_directory/owntransitctl")" = 700 && test "$(stat -f %l "$release_directory/owntransitctl")" -eq 1 || fail "installed lifecycle artifact metadata is invalid"
require_no_extended_acl "$release_directory/owntransitctl"
/usr/bin/env -i \
	HOME=/var/root \
	LANG=C \
	LC_ALL=C \
	PATH=/usr/bin:/bin:/usr/sbin:/sbin \
	"$release_directory/owntransitctl" package-recover --role "$role"
test "$(sha256_file "$release_directory/LICENSE")" = "$(sha256_file "$bundle/$project_license_path")" || fail "installed project license differs from the authenticated evidence"
test "$(sha256_file "$release_directory/THIRD_PARTY_LICENSES.txt")" = "$(sha256_file "$bundle/$third_party_licenses_path")" || fail "installed third-party notices differ from the authenticated evidence"
require_package_mutation_lock

if test "$role" = provisioner; then
  test -d "$release_directory" && test ! -L "$release_directory" || fail "provisioner release path is not a regular directory"
  test "$(stat -f %u "$release_directory")" -eq 0 && test "$(stat -f %g "$release_directory")" -eq 0 && test "$(macos_mode "$release_directory")" = 750 || fail "provisioner release directory metadata is invalid"
  require_no_extended_acl "$release_directory"
  for installed_record in 'owntransit-provision:755' 'owntransitctl:700' 'receipt.json:600' 'LICENSE:644' 'THIRD_PARTY_LICENSES.txt:644'; do
    installed_file=${installed_record%%:*}
    installed_mode=${installed_record#*:}
    installed_path="$release_directory/$installed_file"
    test -f "$installed_path" && test ! -L "$installed_path" || fail "provisioner package file is absent or not regular: $installed_file"
    test "$(stat -f %u "$installed_path")" -eq 0 && test "$(stat -f %g "$installed_path")" -eq 0 || fail "provisioner package file is not root:wheel owned: $installed_file"
    test "$(macos_mode "$installed_path")" = "$installed_mode" && test "$(stat -f %l "$installed_path")" -eq 1 || fail "provisioner package file metadata is invalid: $installed_file"
    require_no_extended_acl "$installed_path"
  done
  test "$(sha256_file "$release_directory/owntransit-provision")" = "$artifact_sha256" || fail "installed provisioner differs from the authenticated artifact"
  public_provisioner="$bin_directory/owntransit-provision"
  test -f "$public_provisioner" && test ! -L "$public_provisioner" || fail "package finalizer did not publish a regular provisioner frontend"
  test "$(stat -f %u "$public_provisioner")" -eq 0 && test "$(stat -f %g "$public_provisioner")" -eq 0 && test "$(macos_mode "$public_provisioner")" = 755 || fail "public provisioner frontend metadata is invalid"
  test "$(stat -f %l "$public_provisioner")" -eq 1 || fail "public provisioner frontend is not a fresh single-link inode"
  require_no_extended_acl "$public_provisioner"
  test "$(sha256_file "$public_provisioner")" = "$artifact_sha256" || fail "public provisioner frontend differs from the authenticated artifact"
  test "$(stat -f '%d:%i' "$public_provisioner")" != "$(stat -f '%d:%i' "$release_directory/owntransit-provision")" || fail "public provisioner frontend is a hard link to the protected release artifact"
  trap - EXIT HUP INT TERM
  rm -rf -- "$verification_directory"
  printf 'installed OwnTransit macOS provisioner release %s under selector %s\n' "$release_id" "$current_link"
  printf 'installed license evidence: %s/LICENSE and %s/THIRD_PARTY_LICENSES.txt\n' "$current_link" "$current_link"
  printf '%s\n' 'provisioner package lifecycle created no reader identity, endpoint state, credential, or launchd job'
  exit 0
fi

public_launcher="$bin_directory/owntransit"
verify_client_executable_boundary "$release_directory/owntransit" "$public_launcher" "$release_directory/owntransit-real"
public_frontend="$bin_directory/owntransit-cli"
test -f "$public_frontend" && test ! -L "$public_frontend" || fail "package finalizer did not publish a regular normal client frontend"
test "$(stat -f %u "$public_frontend")" -eq 0 && test "$(stat -f %g "$public_frontend")" -eq 0 && test "$(macos_mode "$public_frontend")" = 755 || fail "normal client frontend activation is invalid"
test "$(sha256_file "$public_frontend")" = "$artifact_sha256" || fail "normal client frontend changed during activation"
require_no_extended_acl "$public_frontend"
if find "$install_root" -type f -perm -4000 -print | grep . >/dev/null; then
  fail "installation root contains a setuid file"
fi
unexpected_setgid="$verification_directory/unexpected-setgid"
find "$install_root" -type f -perm -2000 -print | while IFS= read -r setgid_file; do
	case "$setgid_file" in
		"$roles_root/client/releases/"*/owntransit) ;;
		"$public_launcher") ;;
		*) printf '%s\n' "$setgid_file" ;;
	esac
done > "$unexpected_setgid"
test ! -s "$unexpected_setgid" || fail "installation root contains a setgid file outside authenticated client launchers"

trap - EXIT HUP INT TERM
rm -rf -- "$verification_directory"
printf 'installed OwnTransit macOS client release %s under selector %s\n' "$release_id" "$current_link"
printf 'installed license evidence: %s/LICENSE and %s/THIRD_PARTY_LICENSES.txt\n' "$current_link" "$current_link"
printf '%s\n' 'no trust, SSH configuration, user account, or launchd job was created'
printf 'fixed protected SSH launcher: %s/owntransit\n' "$bin_directory"
printf 'normal non-setgid setup frontend: %s/owntransit-cli\n' "$bin_directory"
printf '%s\n' 'privileged lifecycle execution remains behind the authenticated per-role current selector, never a Homebrew Cellar or source-tree binary'
printf 'dedicated reader identity %s: user=%s group=%s gid=%s receipt=%s\n' "$identity_mode" "$client_user" "$reader_group_name" "$reader_gid" "$reader_receipt"
printf '%s\n' 'the reader group has no members; only the authenticated fixed setgid launcher can grant the bound client its exact reader EGID'
