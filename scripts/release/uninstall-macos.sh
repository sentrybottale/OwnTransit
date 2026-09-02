#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'uninstall-macos: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: uninstall-macos.sh --role client|provisioner --release-id 52_CHAR_BASE32_ID

Detaches only the selected role's exact public executable. The manager-owned current/previous selectors,
immutable releases, receipts, installed license
notices and external rollback anchors remain intact so exact reinstall/recovery
cannot silently reset a floor. Client launcher binding, reader identity,
credentials and recovery state are also preserved. Destructive package-state
retirement requires a future authenticated lifecycle action.
EOF
}

role=
release_id=
while test "$#" -gt 0; do
  case "$1" in
    --role|--release-id)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --role) role=$value ;;
        --release-id) release_id=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$(uname -s)" = Darwin || fail "this uninstaller supports macOS only"
test "$(id -u)" -eq 0 || fail "uninstall requires root"
for command_name in cat ls readlink sed stat tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

macos_mode() {
  macos_mode_raw=$(stat -f %p -- "$1") || return 1
  case "$macos_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
  printf '%o\n' "$((0$macos_mode_raw & 07777))"
}

case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

require_no_extended_acl() {
  acl_path=$1
  test "$(ls -lde "$acl_path" | wc -l | tr -d '[:space:]')" -eq 1 || fail "installed path has an extended ACL: $acl_path"
}

require_root_directory() {
  directory=$1
  permissions=$2
  test -d "$directory" && test ! -L "$directory" || fail "$directory is absent or not a regular directory"
  test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" -eq 0 || fail "$directory is not root:wheel owned"
  test "$(macos_mode "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
  require_no_extended_acl "$directory"
}

require_root_file() {
  file=$1
  permissions=$2
  test -f "$file" && test ! -L "$file" || fail "$file is absent or not a regular file"
  test "$(stat -f %u "$file")" -eq 0 && test "$(stat -f %g "$file")" -eq 0 || fail "$file is not root:wheel owned"
  test "$(macos_mode "$file")" = "$permissions" || fail "$file mode is not $permissions"
  test "$(stat -f %l "$file")" -eq 1 || fail "$file has multiple hard links"
  require_no_extended_acl "$file"
}

require_root_reader_directory() {
  directory=$1
  permissions=$2
  test -d "$directory" && test ! -L "$directory" || fail "$directory is absent or not a regular directory"
  test "$(stat -f %u "$directory")" -eq 0 && test "$(stat -f %g "$directory")" = "$reader_gid" || fail "$directory is not root:reader owned"
  test "$(macos_mode "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
  require_no_extended_acl "$directory"
}

require_root_reader_file() {
  file=$1
  permissions=$2
  test -f "$file" && test ! -L "$file" || fail "$file is absent or not a regular file"
  test "$(stat -f %u "$file")" -eq 0 && test "$(stat -f %g "$file")" = "$reader_gid" || fail "$file is not root:reader owned"
  test "$(macos_mode "$file")" = "$permissions" || fail "$file mode is not $permissions"
  test "$(stat -f %l "$file")" -eq 1 || fail "$file has multiple hard links"
  require_no_extended_acl "$file"
}

install_root=/Library/OwnTransit
bin_directory="$install_root/bin"
require_root_directory "$install_root" 755
require_root_directory "$bin_directory" 755

case "$role" in
  client)
    current_link="$install_root/roles/client/current"
    release_directory="$install_root/roles/client/releases/$release_id"
    public_launcher="$bin_directory/owntransit"
    public_frontend="$bin_directory/owntransit-cli"
    test -L "$current_link" || fail "client current selector is absent"
    test "$(readlink "$current_link")" = "releases/$release_id" || fail "client current selector identifies another release"
    require_root_directory "$install_root/identity" 700
    require_root_file "$install_root/identity/client-reader.v1" 600
    test "$(wc -l < "$install_root/identity/client-reader.v1" | tr -d '[:space:]')" -eq 8 || fail "protected reader identity receipt is malformed"
    reader_gid=$(sed -n '7{s/^reader_gid=//p;}' "$install_root/identity/client-reader.v1")
    case "$reader_gid" in ''|0|0*|*[!0-9]*) fail "protected reader identity GID is invalid" ;; esac
    require_root_reader_directory "$release_directory" 750
    require_root_reader_file "$release_directory/owntransit" 2751
    require_root_reader_file "$release_directory/owntransit-real" 750
    require_root_file "$release_directory/owntransitctl" 700
    require_root_file "$release_directory/receipt.json" 600
    require_root_file "$release_directory/LICENSE" 644
    require_root_file "$release_directory/THIRD_PARTY_LICENSES.txt" 644
    test -d "$install_root/launcher-auth" && test ! -L "$install_root/launcher-auth" || fail "protected launcher authorization directory is absent"
    require_root_reader_file "$install_root/launcher-auth/client.v1" 640
    test "$(wc -l < "$install_root/launcher-auth/client.v1" | tr -d '[:space:]')" -eq 6 || fail "protected launcher binding is malformed"
    test "$(sed -n '4{s/^reader_gid=//p;}' "$install_root/launcher-auth/client.v1")" = "$reader_gid" || fail "protected launcher binding identifies another reader GID"
    test "$(sed -n '5{s/^release_id=//p;}' "$install_root/launcher-auth/client.v1")" = "$release_id" || fail "protected launcher binding identifies another release"
    ;;
  provisioner)
    current_link="$install_root/roles/provisioner/current"
    release_directory="$install_root/roles/provisioner/releases/$release_id"
    public_launcher="$bin_directory/owntransit-provision"
    test -L "$current_link" || fail "provisioner current selector is absent"
    test "$(readlink "$current_link")" = "releases/$release_id" || fail "provisioner current selector identifies another release"
    require_root_directory "$release_directory" 750
    require_root_file "$release_directory/owntransit-provision" 755
    require_root_file "$release_directory/owntransitctl" 700
    require_root_file "$release_directory/receipt.json" 600
    require_root_file "$release_directory/LICENSE" 644
    require_root_file "$release_directory/THIRD_PARTY_LICENSES.txt" 644
    ;;
  *) fail "role must be client or provisioner" ;;
esac

/usr/bin/env -i \
  HOME=/var/root \
  LANG=C \
  LC_ALL=C \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin \
  "$release_directory/owntransitctl" package-detach --role "$role"

test ! -e "$public_launcher" && test ! -L "$public_launcher" || fail "package detach left the public role entry"
if test "$role" = client; then
  test ! -e "$public_frontend" && test ! -L "$public_frontend" || fail "package detach left the public client frontend"
fi

printf 'detached OwnTransit macOS %s role release %s\n' "$role" "$release_id"
printf '%s\n' 'authenticated selectors, installed license notices, rollback floors, identities, launcher binding, credentials, and recovery material were preserved'
printf '%s\n' 'destructive reader-identity purge is intentionally not implemented'
