#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

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

current_link="$install_root/roles/$role/current"
release_directory="$install_root/roles/$role/releases/$release_id"
test -L "$current_link" || fail "role current selector is absent"
test "$(readlink "$current_link")" = "releases/$release_id" || fail "role current selector identifies another release"
test -d "$release_directory" && test ! -L "$release_directory" || fail "selected authenticated release directory is absent"
for notice in LICENSE THIRD_PARTY_LICENSES.txt; do
  test -f "$release_directory/$notice" && test ! -L "$release_directory/$notice" || fail "installed license notice is absent: $notice"
done

if test "$role" = client; then
  for launcher_name in owntransit owntransit-proxy; do
    launcher="$public_bin/$launcher_name"
    expected="$current_link/$launcher_name"
    test -L "$launcher" || fail "client launcher is absent: $launcher"
    test "$(readlink "$launcher")" = "$expected" || fail "client launcher selects another role path: $launcher"
  done
elif test "$role" = provisioner; then
  launcher="$public_bin/owntransit-provision"
  expected="$current_link/owntransit-provision"
  test -L "$launcher" || fail "provisioner launcher is absent: $launcher"
  test "$(readlink "$launcher")" = "$expected" || fail "provisioner launcher selects another role path: $launcher"
fi

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
elif test "$role" = provisioner; then
  rm -f -- "$public_bin/owntransit-provision"
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
fi

printf 'detached OwnTransit %s role release %s\n' "$role" "$release_id"
printf '%s\n' 'authenticated package selectors, installed license notices, rollback floors, identities, role workspace, relay image, credentials, and SSH/recovery material were preserved'
