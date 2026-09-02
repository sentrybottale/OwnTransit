#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() {
  printf 'uninstall-linux: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: uninstall-linux.sh --role client|connector|relay|provisioner --release-id 52_CHAR_BASE32_ID

Detaches only the selected role's public launcher or systemd unit. Authenticated
role releases, current/previous selectors, receipts, installed license notices,
external rollback anchors, identities, OCI images, credentials and recovery
state remain intact so exact reinstall/recovery cannot silently reset floors.
Destructive package-state retirement requires a future signed lifecycle action.
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
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$(uname -s)" = Linux || fail "this uninstaller supports Linux only"
case "$(uname -m)" in
  x86_64|amd64|aarch64|arm64) ;;
  *) fail "this uninstaller supports Linux amd64 and arm64 only" ;;
esac
test "$(id -u)" -eq 0 || fail "uninstall requires root"
case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

case "$role" in
  client)
    service_name=
    ;;
  connector)
    service_name=owntransit-connector
    ;;
  relay)
    service_name=owntransit-relay
    ;;
  provisioner)
    service_name=
    ;;
  *) fail "role must be client, connector, relay, or provisioner" ;;
esac

install_root=/usr/libexec/owntransit
public_bin=/usr/local/bin

for command_name in awk cat env flock readlink rm stat systemctl uname; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
test -x /usr/bin/flock || fail "flock must be available at /usr/bin/flock"

require_root_directory() {
  directory=$1
  permissions=$2
  test -d "$directory" && test ! -L "$directory" || fail "$directory is not a regular directory"
  test "$(stat -c %u "$directory")" -eq 0 && test "$(stat -c %g "$directory")" -eq 0 || fail "$directory is not root-owned"
  test "$(stat -c %a "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
}

require_mutation_lock_file() {
  lock_path=$1
  lock_label=$2
  test -f "$lock_path" && test ! -L "$lock_path" || fail "$lock_label is not a regular non-symlink file"
  test "$(stat -c %u "$lock_path")" -eq 0 && test "$(stat -c %g "$lock_path")" -eq 0 || fail "$lock_label is not root-owned"
  test "$(stat -c %a "$lock_path")" = 600 || fail "$lock_label mode is not 0600"
  test "$(stat -c %h "$lock_path")" -eq 1 || fail "$lock_label has multiple hard links"
  test "$(stat -c %s "$lock_path")" -eq 0 || fail "$lock_label is not empty"
}

mutation_root=/var/lib/owntransit/package-supervisor
platform_mutation_lock="$mutation_root/platform.v1.lock"
require_root_directory /var/lib/owntransit 755
require_root_directory "$mutation_root" 700
require_mutation_lock_file "$platform_mutation_lock" "Linux package-mutation lock"
exec 9<> "$platform_mutation_lock"
platform_lock_fd_path="/proc/$$/fd/9"
test "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$platform_mutation_lock")" = "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$platform_lock_fd_path")" ||
  fail "opened Linux package-mutation lock differs from its canonical name"
/usr/bin/flock -n 9 || fail "another Linux package install or uninstall is active"
require_root_directory "$mutation_root" 700
require_mutation_lock_file "$platform_mutation_lock" "Linux package-mutation lock"
test "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$platform_mutation_lock")" = "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$platform_lock_fd_path")" ||
  fail "Linux package-mutation lock changed during acquisition"

current_link="$install_root/roles/$role/current"
release_directory="$install_root/roles/$role/releases/$release_id"

assert_selected_release() {
  test -L "$current_link" || fail "role current selector is absent"
  test "$(readlink "$current_link")" = "releases/$release_id" || fail "role current selector identifies another release"
  test -d "$release_directory" && test ! -L "$release_directory" || fail "selected authenticated release directory is absent"
  for notice in LICENSE THIRD_PARTY_LICENSES.txt; do
    test -f "$release_directory/$notice" && test ! -L "$release_directory/$notice" || fail "installed license notice is absent: $notice"
  done
  selected_lifecycle="$release_directory/owntransitctl"
  test -f "$selected_lifecycle" && test ! -L "$selected_lifecycle" || fail "selected lifecycle executable is absent"
  test "$(stat -c %u "$selected_lifecycle")" -eq 0 && test "$(stat -c %g "$selected_lifecycle")" -eq 0 || fail "selected lifecycle executable is not root-owned"
  test "$(stat -c %a "$selected_lifecycle")" = 700 && test "$(stat -c %h "$selected_lifecycle")" -eq 1 || fail "selected lifecycle executable metadata is invalid"
}

require_regular_or_absent() {
  integration_path=$1
  integration_mode=$2
  integration_label=$3
  if test ! -e "$integration_path" && test ! -L "$integration_path"; then
    integration_complete=no
    return
  fi
  test -f "$integration_path" && test ! -L "$integration_path" || fail "$integration_label is not a regular non-symlink file"
  test "$(stat -c %u "$integration_path")" -eq 0 && test "$(stat -c %g "$integration_path")" -eq 0 || fail "$integration_label is not root-owned"
  test "$(stat -c %a "$integration_path")" = "$integration_mode" && test "$(stat -c %h "$integration_path")" -eq 1 || fail "$integration_label metadata is invalid"
}

validate_integration_residue() {
  integration_complete=yes
  if test "$role" = client; then
    for launcher_name in owntransit owntransit-proxy; do
      launcher="$public_bin/$launcher_name"
      expected="$current_link/$launcher_name"
      if test -e "$launcher" || test -L "$launcher"; then
        test -L "$launcher" || fail "client launcher is not a symlink: $launcher"
        test "$(readlink "$launcher")" = "$expected" || fail "client launcher selects another role path: $launcher"
      else
        integration_complete=no
      fi
    done
  elif test "$role" = provisioner; then
    launcher="$public_bin/owntransit-provision"
    expected="$current_link/owntransit-provision"
    if test -e "$launcher" || test -L "$launcher"; then
      test -L "$launcher" || fail "provisioner launcher is not a symlink: $launcher"
      test "$(readlink "$launcher")" = "$expected" || fail "provisioner launcher selects another role path: $launcher"
    else
      integration_complete=no
    fi
  elif test "$role" = connector; then
    require_regular_or_absent /etc/systemd/system/owntransit-connector.service 644 "connector systemd unit"
    require_regular_or_absent /etc/owntransit/connector-runtime.env 600 "connector runtime environment"
  elif test "$role" = relay; then
    require_regular_or_absent /etc/systemd/system/owntransit-relay.service 644 "relay systemd unit"
    require_regular_or_absent /etc/systemd/system/owntransit-relay-exchange@.service 644 "relay exchange systemd unit"
    require_regular_or_absent /etc/owntransit/relay-container.env 600 "relay container environment"
  fi
}

assert_selected_release
validate_integration_residue

if test "$integration_complete" = yes; then
  # The authenticated current lifecycle validates/reconciles complete package
  # state before detach. A retry after partial integration removal skips this
  # step because a missing unit/environment may deliberately be the crash
  # residue being converged, and recovery could try to restart that unit.
  env -i HOME=/root LANG=C LC_ALL=C PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    "$selected_lifecycle" package-recover --role "$role" >/dev/null
  assert_selected_release
fi

if test -n "$service_name"; then
  role_mutation_lock="$mutation_root/$role.lock"
  require_mutation_lock_file "$role_mutation_lock" "Linux $role package-supervisor lock"
  exec 8<> "$role_mutation_lock"
  role_lock_fd_path="/proc/$$/fd/8"
  test "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$role_mutation_lock")" = "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$role_lock_fd_path")" ||
    fail "opened Linux $role package-supervisor lock differs from its canonical name"
  /usr/bin/flock -n 8 || fail "another Linux $role package operation is active"
  require_root_directory "$mutation_root" 700
  require_mutation_lock_file "$role_mutation_lock" "Linux $role package-supervisor lock"
  test "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$role_mutation_lock")" = "$(stat -Lc '%d:%i:%u:%g:%a:%h:%s' "$role_lock_fd_path")" ||
    fail "Linux $role package-supervisor lock changed during acquisition"
  assert_selected_release
fi
validate_integration_residue

if test "$role" = relay; then
  exchange_units=$(systemctl list-units --all --plain --no-legend --no-pager 'owntransit-relay-exchange@*.service' | awk '{print $1}')
  for exchange_unit in $exchange_units; do
    case "$exchange_unit" in
      owntransit-relay-exchange@*.service) ;;
      *) fail "systemd returned an unexpected relay bootstrap exchange unit" ;;
    esac
    systemctl stop "$exchange_unit"
  done
fi

if test -n "$service_name"; then
  if systemctl is-active --quiet "$service_name.service"; then
    systemctl stop "$service_name.service"
  fi
  if systemctl is-enabled --quiet "$service_name.service"; then
    systemctl disable "$service_name.service"
  fi
fi

if test "$role" = client; then
  rm -f -- "$public_bin/owntransit"
  rm -f -- "$public_bin/owntransit-proxy"
  for detached_name in "$public_bin/owntransit" "$public_bin/owntransit-proxy"; do
    test ! -e "$detached_name" && test ! -L "$detached_name" || fail "client launcher remains after detach: $detached_name"
  done
elif test "$role" = provisioner; then
  rm -f -- "$public_bin/owntransit-provision"
  test ! -e "$public_bin/owntransit-provision" && test ! -L "$public_bin/owntransit-provision" || fail "provisioner launcher remains after detach"
fi

if test -n "$service_name"; then
  rm -f -- "/etc/systemd/system/$service_name.service"
  if test "$role" = connector; then
    rm -f -- /etc/owntransit/connector-runtime.env
  elif test "$role" = relay; then
    rm -f -- /etc/systemd/system/owntransit-relay-exchange@.service
    rm -f -- /etc/owntransit/relay-container.env
  fi
  systemctl daemon-reload
  test ! -e "/etc/systemd/system/$service_name.service" && test ! -L "/etc/systemd/system/$service_name.service" || fail "$service_name unit remains after detach"
  if test "$role" = connector; then
    test ! -e /etc/owntransit/connector-runtime.env && test ! -L /etc/owntransit/connector-runtime.env || fail "connector runtime environment remains after detach"
  elif test "$role" = relay; then
    test ! -e /etc/systemd/system/owntransit-relay-exchange@.service && test ! -L /etc/systemd/system/owntransit-relay-exchange@.service || fail "relay exchange unit remains after detach"
    test ! -e /etc/owntransit/relay-container.env && test ! -L /etc/owntransit/relay-container.env || fail "relay container environment remains after detach"
  fi
fi

printf 'detached OwnTransit %s role release %s\n' "$role" "$release_id"
printf '%s\n' 'authenticated package selectors, installed license notices, rollback floors, identities, role workspace, relay image, credentials, and SSH/recovery material were preserved'
