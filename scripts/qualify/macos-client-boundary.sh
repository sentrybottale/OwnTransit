#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'macos-client-boundary: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: macos-client-boundary.sh \
  --client-user EXISTING_LOCAL_SHORT_NAME \
  --release-id 52_CHAR_BASE32_ID \
  --reader-gid POSITIVE_DECIMAL_GID

Performs a non-mutating post-install preflight of the exact-user macOS
setgid-launcher boundary. This is not full ship qualification: it does not
exercise the live proxy path, debugger/task-port isolation, or a reboot. Run it
as root on a clean test Mac only after the authenticated client installer and
lifecycle activation succeed. It never
creates, edits, or removes an identity, release, lifecycle state, trust, or SSH
material.
EOF
}

client_user=
release_id=
reader_gid=
while test "$#" -gt 0; do
  case "$1" in
    --client-user|--release-id|--reader-gid)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --client-user) client_user=$value ;;
        --release-id) release_id=$value ;;
        --reader-gid) reader_gid=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$(uname -s)" = Darwin || fail "qualification requires macOS"
test "$(uname -m)" = arm64 || fail "qualification requires arm64"
test "$(id -u)" -eq 0 || fail "qualification requires root"
case "$client_user" in ''|*[!A-Za-z0-9._-]*|-*) fail "--client-user is unsafe or absent" ;; esac
test "${#client_user}" -le 64 || fail "--client-user is too long"
test "$client_user" != _owntransit || fail "--client-user reuses the reader group name"
case "$release_id" in ''|*[!a-z2-7]*) fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

valid_positive_id() {
  numeric_id=$1
  case "$numeric_id" in ''|0|0*|*[!0-9]*) return 1 ;; esac
  test "${#numeric_id}" -le 10 || return 1
  test "$numeric_id" -le 2147483646
}

valid_generated_uid() {
  printf '%s\n' "$1" | grep -Eq '^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
}

valid_positive_id "$reader_gid" || fail "--reader-gid must be a positive canonical decimal GID"
test "$reader_gid" -ge 5000 && test "$reader_gid" -le 59999 || fail "--reader-gid is outside the installer range"

for command_name in awk cat dscl dsmemberutil find grep id ls mktemp plutil readlink rm sed shasum stat sudo touch tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

macos_mode() {
  macos_mode_raw=$(stat -f %p -- "$1") || return 1
  case "$macos_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
  printf '%o\n' "$((0$macos_mode_raw & 07777))"
}

workspace=$(mktemp -d /var/tmp/owntransit-macos-qualify.XXXXXX) || fail "cannot create qualification workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM
test "$(stat -f %u "$workspace")" -eq 0 && test "$(stat -f %g "$workspace")" -eq 0 && test "$(macos_mode "$workspace")" = 700 || fail "qualification workspace is not root:wheel 0700"

require_no_extended_acl() {
  acl_path=$1
  test "$(ls -lde "$acl_path" | wc -l | tr -d '[:space:]')" -eq 1 || fail "path has an extended ACL: $acl_path"
}

require_root_wheel_directory() {
  directory=$1
  mode=$2
  test -d "$directory" && test ! -L "$directory" || fail "directory is absent, special, or a symlink: $directory"
  test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" -eq 0 || fail "directory is not root:wheel owned: $directory"
  test "$(macos_mode "$directory")" = "$mode" || fail "directory has the wrong mode: $directory"
  require_no_extended_acl "$directory"
}

require_root_reader_directory() {
  directory=$1
  mode=$2
  test -d "$directory" && test ! -L "$directory" || fail "reader directory is absent, special, or a symlink: $directory"
  test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" = "$reader_gid" || fail "directory is not root:reader owned: $directory"
  test "$(macos_mode "$directory")" = "$mode" || fail "reader directory has the wrong mode: $directory"
  require_no_extended_acl "$directory"
}

valid_digest() {
  case "$1" in *[!0-9a-f]*|'') return 1 ;; esac
  test "${#1}" -eq 64
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

plist_array_count() {
  /usr/bin/plutil -extract "$2" raw -expect array -o - "$1" 2>/dev/null
}

plist_array_value() {
  /usr/bin/plutil -extract "$2.$3" raw -expect string -n -o - "$1" 2>/dev/null
}

plist_array_absent_or_empty() {
  if /usr/bin/plutil -type "$2" "$1" >/dev/null 2>&1; then
    test "$(plist_array_count "$1" "$2")" -eq 0
  fi
}

read_record() {
  /usr/bin/dscl -plist "$1" -read "$2" > "$3" 2>/dev/null || fail "cannot read Directory Services record: $1 $2"
  /usr/bin/plutil -lint -s "$3" || fail "Directory Services returned malformed record data: $2"
}

load_user_record() {
  user_plist=$1
  test "$(plist_array_count "$user_plist" 'dsAttrTypeStandard:RecordName')" -ge 1 || fail "user RecordName array is empty"
  loaded_name=$(plist_array_value "$user_plist" 'dsAttrTypeStandard:RecordName' 0) || fail "user RecordName is malformed"
  test "$loaded_name" = "$client_user" || fail "user canonical RecordName does not match --client-user"
  test "$(plist_array_count "$user_plist" 'dsAttrTypeStandard:UniqueID')" -eq 1 || fail "user UniqueID is not singular"
  loaded_uid=$(plist_array_value "$user_plist" 'dsAttrTypeStandard:UniqueID' 0) || fail "user UniqueID is malformed"
  valid_positive_id "$loaded_uid" || fail "user UniqueID is invalid"
  test "$(plist_array_count "$user_plist" 'dsAttrTypeStandard:PrimaryGroupID')" -eq 1 || fail "user PrimaryGroupID is not singular"
  loaded_primary_gid=$(plist_array_value "$user_plist" 'dsAttrTypeStandard:PrimaryGroupID' 0) || fail "user PrimaryGroupID is malformed"
  valid_positive_id "$loaded_primary_gid" || fail "user PrimaryGroupID is invalid"
  test "$(plist_array_count "$user_plist" 'dsAttrTypeStandard:GeneratedUID')" -eq 1 || fail "user GeneratedUID is not singular"
  loaded_uuid=$(plist_array_value "$user_plist" 'dsAttrTypeStandard:GeneratedUID' 0) || fail "user GeneratedUID is malformed"
  valid_generated_uid "$loaded_uuid" || fail "user GeneratedUID is invalid"
}

verify_group_record() {
  group_plist=$1
  test "$(/usr/bin/plutil -type 'dsAttrTypeStandard:RecordName' "$group_plist" 2>/dev/null)" = array || fail "plutil cannot prove Directory Services attribute types"
  test "$(plist_array_count "$group_plist" 'dsAttrTypeStandard:RecordName')" -eq 1 || fail "reader group RecordName is not singular"
  test "$(plist_array_value "$group_plist" 'dsAttrTypeStandard:RecordName' 0)" = _owntransit || fail "reader group name changed"
  test "$(plist_array_count "$group_plist" 'dsAttrTypeStandard:PrimaryGroupID')" -eq 1 || fail "reader group GID is not singular"
  test "$(plist_array_value "$group_plist" 'dsAttrTypeStandard:PrimaryGroupID' 0)" = "$reader_gid" || fail "reader group GID changed"
  test "$(plist_array_count "$group_plist" 'dsAttrTypeStandard:GeneratedUID')" -eq 1 || fail "reader group GeneratedUID is not singular"
  loaded_group_uuid=$(plist_array_value "$group_plist" 'dsAttrTypeStandard:GeneratedUID' 0) || fail "reader group GeneratedUID is malformed"
  valid_generated_uid "$loaded_group_uuid" || fail "reader group GeneratedUID is invalid"
  plist_array_absent_or_empty "$group_plist" 'dsAttrTypeStandard:GroupMembership' || fail "reader group contains a named member or malformed membership attribute"
  plist_array_absent_or_empty "$group_plist" 'dsAttrTypeStandard:GroupMembers' || fail "reader group contains a UUID member or malformed member attribute"
  plist_array_absent_or_empty "$group_plist" 'dsAttrTypeStandard:NestedGroups' || fail "reader group contains nesting or a malformed nesting attribute"
}

assert_unique_numeric_owner() {
  list_file=$1
  wanted=$2
  expected=$3
  label=$4
  awk -v wanted="$wanted" -v expected="$expected" '
    $NF == wanted { count++; if (NF == 2 && $1 == expected) exact++ }
    END { exit count == 1 && exact == 1 ? 0 : 1 }
  ' "$list_file" || fail "$label is missing, duplicated, ambiguous, or owned by another record"
}

assert_numeric_unowned() {
  awk -v wanted="$2" '$NF == wanted { found = 1 } END { exit found ? 1 : 0 }' "$1" || fail "$3 is assigned to a user as its primary GID"
}

read_list() {
  /usr/bin/dscl "$1" -list "$2" "$3" > "$4" 2>/dev/null || fail "cannot enumerate $1 $2 $3"
}

install_root=/Library/OwnTransit
roles_root="$install_root/roles"
role_root="$roles_root/client"
release_parent="$role_root/releases"
bin_directory="$install_root/bin"
identity_directory="$install_root/identity"
receipt="$identity_directory/client-reader.v1"
release_directory="$release_parent/$release_id"
client_launcher="$release_directory/owntransit"
client_executable="$release_directory/owntransit-real"
client_frontend="$bin_directory/owntransit-cli"
lifecycle_executable="$release_directory/owntransitctl"
launcher_auth_directory="$install_root/launcher-auth"
launcher_binding="$launcher_auth_directory/client.v1"
runtime_directory="$install_root/client/runtime"
runtime_file="$runtime_directory/runtime.json"
anchor_directory="$install_root/client/anchor-view"
anchor_file="$anchor_directory/anchor.json"

require_root_wheel_directory /Library 755
require_root_wheel_directory "$install_root" 755
require_root_wheel_directory "$roles_root" 755
require_root_reader_directory "$role_root" 750
require_root_reader_directory "$release_parent" 750
require_root_wheel_directory "$bin_directory" 755
require_root_wheel_directory "$identity_directory" 700
require_root_reader_directory "$release_directory" 750
test -L "$role_root/current" && test "$(readlink "$role_root/current")" = "releases/$release_id" || fail "authenticated client selector identifies another release"

test -f "$receipt" && test ! -L "$receipt" || fail "reader identity receipt is absent or not regular"
test "$(stat -f %u "$receipt")" -eq 0 && test "$(stat -f %g "$receipt")" -eq 0 && test "$(macos_mode "$receipt")" = 600 || fail "reader identity receipt is not root:wheel 0600"
test "$(stat -f %l "$receipt")" -eq 1 || fail "reader identity receipt has multiple hard links"
require_no_extended_acl "$receipt"
test "$(wc -l < "$receipt" | tr -d '[:space:]')" -eq 8 || fail "reader identity receipt has the wrong line count"
receipt_schema=$(sed -n '1{s/^schema=//p;}' "$receipt")
receipt_user=$(sed -n '2{s/^client_user=//p;}' "$receipt")
receipt_uid=$(sed -n '3{s/^client_uid=//p;}' "$receipt")
receipt_primary_gid=$(sed -n '4{s/^client_primary_gid=//p;}' "$receipt")
receipt_user_uuid=$(sed -n '5{s/^client_uuid=//p;}' "$receipt")
receipt_group=$(sed -n '6{s/^reader_group=//p;}' "$receipt")
receipt_gid=$(sed -n '7{s/^reader_gid=//p;}' "$receipt")
receipt_group_uuid=$(sed -n '8{s/^reader_group_uuid=//p;}' "$receipt")
receipt_expected=$(printf '%s\n' \
  "schema=$receipt_schema" \
  "client_user=$receipt_user" \
  "client_uid=$receipt_uid" \
  "client_primary_gid=$receipt_primary_gid" \
  "client_uuid=$receipt_user_uuid" \
  "reader_group=$receipt_group" \
  "reader_gid=$receipt_gid" \
  "reader_group_uuid=$receipt_group_uuid")
test "$(cat "$receipt")" = "$receipt_expected" || fail "reader identity receipt is malformed or has unknown fields"
test "$receipt_schema" = owntransit.macos-client-reader.v1 || fail "reader identity receipt schema is unsupported"
test "$receipt_user" = "$client_user" || fail "--client-user does not match the protected receipt"
valid_positive_id "$receipt_uid" || fail "receipt UID is invalid"
valid_positive_id "$receipt_primary_gid" || fail "receipt primary GID is invalid"
valid_generated_uid "$receipt_user_uuid" || fail "receipt user GeneratedUID is invalid"
test "$receipt_group" = _owntransit || fail "receipt group name is unsupported"
test "$receipt_gid" = "$reader_gid" || fail "--reader-gid does not match the protected receipt"
valid_generated_uid "$receipt_group_uuid" || fail "receipt group GeneratedUID is invalid"

user_records=/Users
read_record . "$user_records/$client_user" "$workspace/local-user.plist"
load_user_record "$workspace/local-user.plist"
client_uid=$loaded_uid
client_primary_gid=$loaded_primary_gid
client_uuid=$loaded_uuid
test "$client_uid" = "$receipt_uid" && test "$client_primary_gid" = "$receipt_primary_gid" && test "$client_uuid" = "$receipt_user_uuid" || fail "local user identity does not match the protected receipt"
read_record /Search "$user_records/$client_user" "$workspace/search-user.plist"
load_user_record "$workspace/search-user.plist"
test "$loaded_uid" = "$client_uid" && test "$loaded_primary_gid" = "$client_primary_gid" && test "$loaded_uuid" = "$client_uuid" || fail "search-policy user does not resolve to the exact local identity"
test "$(/usr/bin/id -u "$client_user")" = "$client_uid" && test "$(/usr/bin/id -un "$client_uid")" = "$client_user" && test "$(/usr/bin/id -g "$client_user")" = "$client_primary_gid" || fail "system user lookup is ambiguous"

read_list . /Users UniqueID "$workspace/local-user-uids"
read_list /Search /Users UniqueID "$workspace/search-user-uids"
read_list . /Users PrimaryGroupID "$workspace/local-user-primary-gids"
read_list /Search /Users PrimaryGroupID "$workspace/search-user-primary-gids"
read_list . /Groups PrimaryGroupID "$workspace/local-group-gids"
read_list /Search /Groups PrimaryGroupID "$workspace/search-group-gids"
assert_unique_numeric_owner "$workspace/local-user-uids" "$client_uid" "$client_user" "local user UID"
assert_unique_numeric_owner "$workspace/search-user-uids" "$client_uid" "$client_user" "search-policy user UID"
assert_unique_numeric_owner "$workspace/local-group-gids" "$reader_gid" _owntransit "local reader GID"
assert_unique_numeric_owner "$workspace/search-group-gids" "$reader_gid" _owntransit "search-policy reader GID"
assert_numeric_unowned "$workspace/local-user-primary-gids" "$reader_gid" "local reader GID"
assert_numeric_unowned "$workspace/search-user-primary-gids" "$reader_gid" "search-policy reader GID"

read_record . /Groups/_owntransit "$workspace/local-group.plist"
verify_group_record "$workspace/local-group.plist"
local_group_uuid=$loaded_group_uuid
read_record /Search /Groups/_owntransit "$workspace/search-group.plist"
verify_group_record "$workspace/search-group.plist"
test "$loaded_group_uuid" = "$local_group_uuid" && test "$local_group_uuid" = "$receipt_group_uuid" || fail "reader group UUID does not match locally, through Search, and in the receipt"
membership_result=$(/usr/bin/dsmemberutil checkmembership -u "$client_uid" -g "$reader_gid" 2>/dev/null) || fail "cannot query client reader membership"
test "$membership_result" = 'user is not a member of the group' || fail "client is unexpectedly an effective reader-group member"
client_group_ids=$(/usr/bin/id -G "$client_user") || fail "cannot resolve client user group vector"
printf '%s\n' "$client_group_ids" | awk -v wanted="$reader_gid" '{ for (i = 1; i <= NF; i++) if ($i == wanted) found = 1 } END { exit found ? 1 : 0 }' || fail "client group vector contains the reader GID"

require_root_reader_directory "$launcher_auth_directory" 750
require_root_reader_directory "$runtime_directory" 750
require_root_reader_directory "$anchor_directory" 750
for protected_file in "$launcher_binding" "$runtime_file" "$anchor_file"; do
  test -f "$protected_file" && test ! -L "$protected_file" || fail "protected reader file is absent or not regular: $protected_file"
  test "$(stat -f %u "$protected_file")" -eq 0 && test "$(stat -f %g "$protected_file")" = "$reader_gid" && test "$(macos_mode "$protected_file")" = 640 || fail "protected reader file is not root:reader 0640: $protected_file"
  test "$(stat -f %l "$protected_file")" -eq 1 || fail "protected reader file has multiple hard links: $protected_file"
  require_no_extended_acl "$protected_file"
done
test "$(wc -l < "$launcher_binding" | tr -d '[:space:]')" -eq 6 || fail "launcher binding has the wrong line count"
binding_schema=$(sed -n '1{s/^schema=//p;}' "$launcher_binding")
binding_uid=$(sed -n '2{s/^client_uid=//p;}' "$launcher_binding")
binding_uuid=$(sed -n '3{s/^client_uuid=//p;}' "$launcher_binding")
binding_gid=$(sed -n '4{s/^reader_gid=//p;}' "$launcher_binding")
binding_release=$(sed -n '5{s/^release_id=//p;}' "$launcher_binding")
binding_client_sha256=$(sed -n '6{s/^client_sha256=//p;}' "$launcher_binding")
binding_expected=$(printf '%s\n' \
  "schema=$binding_schema" \
  "client_uid=$binding_uid" \
  "client_uuid=$binding_uuid" \
  "reader_gid=$binding_gid" \
  "release_id=$binding_release" \
  "client_sha256=$binding_client_sha256")
test "$(cat "$launcher_binding")" = "$binding_expected" || fail "launcher binding is malformed or contains unknown fields"
test "$binding_schema" = owntransit.macos-client-launcher.v1 || fail "launcher binding schema is unsupported"
test "$binding_uid" = "$client_uid" && test "$binding_uuid" = "$client_uuid" || fail "launcher binding does not bind the exact live UID and GeneratedUID"
test "$binding_gid" = "$reader_gid" && test "$binding_release" = "$release_id" || fail "launcher binding selects another reader GID or release"
valid_digest "$binding_client_sha256" || fail "launcher binding client digest is invalid"

test -f "$client_launcher" && test ! -L "$client_launcher" || fail "client launcher is absent or not regular"
test "$(stat -f %u "$client_launcher")" -eq 0 && test "$(stat -f %g "$client_launcher")" = "$reader_gid" && test "$(macos_mode "$client_launcher")" = 2751 || fail "client launcher is not root:reader setgid 2751"
test "$(stat -f %l "$client_launcher")" -eq 1 || fail "client launcher has multiple hard links"
require_no_extended_acl "$client_launcher"
test -f "$client_executable" && test ! -L "$client_executable" || fail "real client is absent or not regular"
test "$(stat -f %u "$client_executable")" -eq 0 && test "$(stat -f %g "$client_executable")" = "$reader_gid" && test "$(macos_mode "$client_executable")" = 750 || fail "real client is not root:reader 0750"
test "$(stat -f %l "$client_executable")" -eq 1 || fail "real client has multiple hard links"
require_no_extended_acl "$client_executable"
test "$(sha256_file "$client_executable")" = "$binding_client_sha256" || fail "real client digest does not match the protected launcher binding"
test -f "$client_frontend" && test ! -L "$client_frontend" || fail "normal client frontend is absent or not regular"
test "$(stat -f %u "$client_frontend")" -eq 0 && test "$(stat -f %g "$client_frontend")" -eq 0 && test "$(macos_mode "$client_frontend")" = 755 || fail "normal client frontend is not root:wheel 0755"
test "$(stat -f %l "$client_frontend")" -eq 1 || fail "normal client frontend has multiple hard links"
require_no_extended_acl "$client_frontend"
test "$(sha256_file "$client_frontend")" = "$binding_client_sha256" || fail "normal client frontend differs from the authenticated client artifact"
test -f "$lifecycle_executable" && test ! -L "$lifecycle_executable" || fail "owntransitctl is absent or not regular"
test "$(stat -f %u "$lifecycle_executable")" -eq 0 && test "$(stat -f %g "$lifecycle_executable")" -eq 0 && test "$(macos_mode "$lifecycle_executable")" = 700 || fail "owntransitctl is not root:wheel 0700"
test "$(stat -f %l "$lifecycle_executable")" -eq 1 || fail "owntransitctl has multiple hard links"
require_no_extended_acl "$lifecycle_executable"
test -f "$release_directory/receipt.json" && test ! -L "$release_directory/receipt.json" || fail "authenticated package receipt is absent"
test "$(stat -f %u "$release_directory/receipt.json")" -eq 0 && test "$(stat -f %g "$release_directory/receipt.json")" -eq 0 && test "$(macos_mode "$release_directory/receipt.json")" = 600 || fail "authenticated package receipt is not root:wheel 0600"
test "$(stat -f %l "$release_directory/receipt.json")" -eq 1 || fail "authenticated package receipt has multiple hard links"
require_no_extended_acl "$release_directory/receipt.json"
for notice in LICENSE THIRD_PARTY_LICENSES.txt; do
  test -f "$release_directory/$notice" && test ! -L "$release_directory/$notice" || fail "installed license notice is absent: $notice"
  test "$(stat -f %u "$release_directory/$notice")" -eq 0 && test "$(stat -f %g "$release_directory/$notice")" -eq 0 && test "$(macos_mode "$release_directory/$notice")" = 644 || fail "installed license notice is not root:wheel 0644: $notice"
  require_no_extended_acl "$release_directory/$notice"
done
test -L "$bin_directory/owntransit" && test "$(readlink "$bin_directory/owntransit")" = "../roles/client/current/owntransit" || fail "client launcher does not select the fixed authenticated current path"
setgid_files="$workspace/setgid-files"
find "$install_root" -type f -perm -2000 -print > "$setgid_files"
test -s "$setgid_files" || fail "installation root has no authenticated setgid launcher"
while IFS= read -r setgid_file; do
  case "$setgid_file" in
    "$release_parent/"*/owntransit) ;;
    *) fail "installation root contains an unexpected setgid file: $setgid_file" ;;
  esac
done < "$setgid_files"
grep -Fqx "$client_launcher" "$setgid_files" || fail "current authenticated client launcher is not setgid"
test -z "$(find "$install_root" -type f -perm -4000 -print)" || fail "installation root contains a setuid file"

run_as_uid() {
  probe_uid=$1
  shift
  /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /usr/bin/sudo -n -u "#$probe_uid" -- "$@"
}

test "$(run_as_uid "$client_uid" /usr/bin/id -u 2>/dev/null)" = "$client_uid" || fail "target-user control command ran under the wrong UID"
for protected_file in "$launcher_binding" "$runtime_file" "$anchor_file"; do
  if run_as_uid "$client_uid" /bin/test -r "$protected_file"; then fail "ordinary target-user process can read protected reader file: $protected_file"; fi
  if run_as_uid "$client_uid" /bin/cat "$protected_file" >/dev/null 2>&1; then fail "ordinary target-user process read protected bytes: $protected_file"; fi
done
if run_as_uid "$client_uid" /bin/test -r "$client_launcher"; then fail "target user can read the setgid launcher"; fi
run_as_uid "$client_uid" /bin/test -x "$client_launcher" || fail "target user cannot execute the setgid launcher"
if run_as_uid "$client_uid" /bin/test -r "$client_executable"; then fail "ordinary target-user process can read the group-protected real client"; fi
if run_as_uid "$client_uid" /bin/test -x "$client_executable"; then fail "ordinary target-user process can execute the group-protected real client"; fi
run_as_uid "$client_uid" "$client_frontend" version >/dev/null 2>&1 || fail "ordinary target user cannot execute the normal client frontend"
if run_as_uid "$client_uid" "$client_frontend" proxy >/dev/null 2>&1; then fail "normal client frontend exposed the protected proxy command"; fi
for immutable_path in "$release_directory" "$client_launcher" "$client_executable" "$client_frontend" "$launcher_auth_directory" "$runtime_directory" "$anchor_directory"; do
  if run_as_uid "$client_uid" /bin/test -w "$immutable_path"; then fail "target user can mutate protected installed path: $immutable_path"; fi
done
launcher_digest_before=$(sha256_file "$client_launcher")
client_digest_before=$(sha256_file "$client_executable")
frontend_digest_before=$(sha256_file "$client_frontend")
swap_probe="$release_directory/.owntransit-swap-probe"
test ! -e "$swap_probe" && test ! -L "$swap_probe" || fail "swap qualification probe path already exists"
if run_as_uid "$client_uid" /usr/bin/touch "$swap_probe" >/dev/null 2>&1; then
  rm -f "$swap_probe"
  fail "target user can create a replacement inode in the release directory"
fi
test ! -e "$swap_probe" && test ! -L "$swap_probe" || fail "failed swap probe left an installed-tree entry"
test "$(sha256_file "$client_launcher")" = "$launcher_digest_before" && test "$(sha256_file "$client_executable")" = "$client_digest_before" && test "$(sha256_file "$client_frontend")" = "$frontend_digest_before" || fail "installed client, frontend, or launcher changed during swap probes"
if run_as_uid "$client_uid" "$client_executable" verify-reader-gid "$reader_gid" >/dev/null 2>&1; then fail "direct real-client execution acquired reader authority"; fi
run_as_uid "$client_uid" "$client_launcher" --qualify-reader-gid >/dev/null 2>&1 || fail "launcher did not grant the exact reader EGID to the bound UID"
for rejected_argument in proxy --config=/var/tmp/attacker --runtime-root=/var/tmp/attacker; do
  if run_as_uid "$client_uid" "$client_launcher" "$rejected_argument" >/dev/null 2>&1; then fail "launcher accepted caller-selected authority: $rejected_argument"; fi
done

unrelated_user=
unrelated_uid=
while IFS=' ' read -r candidate_user candidate_uid candidate_extra; do
  test -z "${candidate_extra:-}" || continue
  case "$candidate_user" in ''|*[!A-Za-z0-9._-]*|-*) continue ;; esac
  valid_positive_id "$candidate_uid" || continue
  test "$candidate_uid" != "$client_uid" || continue
  if ! awk -v wanted="$candidate_uid" -v expected="$candidate_user" '$NF == wanted { count++; if (NF == 2 && $1 == expected) exact++ } END { exit count == 1 && exact == 1 ? 0 : 1 }' "$workspace/local-user-uids"; then continue; fi
  if ! awk -v wanted="$candidate_uid" -v expected="$candidate_user" '$NF == wanted { count++; if (NF == 2 && $1 == expected) exact++ } END { exit count == 1 && exact == 1 ? 0 : 1 }' "$workspace/search-user-uids"; then continue; fi
  test "$(/usr/bin/id -u "$candidate_user" 2>/dev/null || true)" = "$candidate_uid" || continue
  test "$(/usr/bin/id -un "$candidate_uid" 2>/dev/null || true)" = "$candidate_user" || continue
  candidate_control=$(run_as_uid "$candidate_uid" /usr/bin/id -u 2>/dev/null || true)
  test "$candidate_control" = "$candidate_uid" || continue
  unrelated_user=$candidate_user
  unrelated_uid=$candidate_uid
  break
done < "$workspace/local-user-uids"
test -n "$unrelated_uid" || fail "no unrelated unambiguous local user is available for the permission probe"
unrelated_membership=$(/usr/bin/dsmemberutil checkmembership -u "$unrelated_uid" -g "$reader_gid" 2>/dev/null) || fail "cannot query unrelated-user membership"
test "$unrelated_membership" = 'user is not a member of the group' || fail "unrelated user is a reader-group member"
unrelated_group_ids=$(/usr/bin/id -G "$unrelated_user") || fail "cannot resolve unrelated-user group vector"
printf '%s\n' "$unrelated_group_ids" | awk -v wanted="$reader_gid" '{ for (i = 1; i <= NF; i++) if ($i == wanted) found = 1 } END { exit found ? 1 : 0 }' || fail "unrelated-user group vector contains the reader GID"
for protected_file in "$launcher_binding" "$runtime_file" "$anchor_file"; do
  if run_as_uid "$unrelated_uid" /bin/test -r "$protected_file"; then fail "unrelated user can read protected reader file: $protected_file"; fi
done
if run_as_uid "$unrelated_uid" /bin/test -r "$client_launcher"; then fail "unrelated user can read the setgid launcher"; fi
run_as_uid "$unrelated_uid" /bin/test -x "$client_launcher" || fail "launcher cannot perform its internal wrong-UID rejection"
if run_as_uid "$unrelated_uid" "$client_launcher" --qualify-reader-gid >/dev/null 2>&1; then fail "wrong real UID passed launcher authorization"; fi
if run_as_uid "$unrelated_uid" "$client_executable" verify-reader-gid "$reader_gid" >/dev/null 2>&1; then fail "unrelated direct process acquired the reader EGID"; fi

trap - EXIT HUP INT TERM
rm -rf -- "$workspace"
printf '{"schema":"owntransit.qualify.macos-client-launcher-preflight.v1","result":"pass","ship_qualification":false,"release_id":"%s","reader_gid":%s,"setgid_exact":true,"zero_members":true,"ordinary_read_denied":true,"target_egid_exact":true,"wrong_uid_denied":true,"client_swap_denied":true,"live_proxy_exercised":false,"debugger_isolation_exercised":false,"reboot_exercised":false}\n' "$release_id" "$reader_gid"
