#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() { printf 'owntransit-preview-install: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' 'usage: install-linux.sh --bundle ABSOLUTE_ROOT_OWNED_BUNDLE --role client|connector|relay'
}

bundle=
role=
while test "$#" -gt 0; do
  test "$#" -ge 2 || fail "$1 requires a value"
  case "$1" in
    --bundle) test -z "$bundle" || fail '--bundle specified twice'; bundle=$2 ;;
    --role) test -z "$role" || fail '--role specified twice'; role=$2 ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
case "$role" in client|connector|relay) ;; *) usage >&2; exit 2 ;; esac
test "$(id -u)" -eq 0 || fail 'installation requires root'
test "$(uname -s)" = Linux || fail 'Linux is required'
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail 'supported architectures are amd64 and arm64' ;;
esac
case "$bundle" in /*) ;; *) fail '--bundle must be absolute' ;; esac
test -d "$bundle" && test ! -L "$bundle" || fail 'bundle must be a non-symlink directory'
resolved=$(CDPATH= cd -P -- "$bundle" && pwd) || fail 'cannot resolve bundle'
test "$resolved" = "$bundle" || fail 'bundle path must be canonical without symlink components'

for command_name in awk basename cat chmod chown cmp dirname find id install ln mktemp mv readlink rm sha256sum sort stat tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done

require_protected() {
  path=$1
  test "$(stat -c %u "$path")" -eq 0 && test "$(stat -c %g "$path")" -eq 0 || fail "path is not root:root: $path"
  mode=$(stat -c %a "$path")
  case "$mode" in [0-7][0-7][0-7]) ;; *) fail "path has special mode bits: $path" ;; esac
  test $((0$mode & 022)) -eq 0 || fail "path is group/world writable: $path"
}

ancestor=$bundle
while :; do
  test -d "$ancestor" && test ! -L "$ancestor" || fail "unsafe bundle ancestor: $ancestor"
  require_protected "$ancestor"
  test "$ancestor" = / && break
  ancestor=$(dirname "$ancestor")
done
test "$(stat -c %a "$bundle")" = 700 || fail 'bundle root must be root:root mode 0700'
test -z "$(find "$bundle" -mindepth 1 ! -type f -print)" || fail 'bundle contains a directory, symlink, or special entry'
test "$(find "$bundle" -mindepth 1 -type f -print | wc -l | tr -d '[:space:]')" = 9 || fail 'bundle must contain exactly nine files'

expected_files='CAPSULE
LICENSE
NOTICE
SHA256SUMS
install-linux.sh
owntransit
owntransit-connector
owntransit-relay
owntransit-relay.oci.tar'
actual_files=$(find "$bundle" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort)
test "$actual_files" = "$expected_files" || fail 'bundle file inventory is not exact'
for name in $expected_files; do
  file=$bundle/$name
  test -f "$file" && test ! -L "$file" || fail "bundle member is not regular: $name"
  require_protected "$file"
  test "$(stat -c %h "$file")" = 1 || fail "bundle member has multiple links: $name"
  case "$name" in
    install-linux.sh|owntransit|owntransit-connector|owntransit-relay)
      test "$(stat -c %a "$file")" = 755 || fail "executable mode is not 0755: $name"
      ;;
    *) test "$(stat -c %a "$file")" = 644 || fail "data-file mode is not 0644: $name" ;;
  esac
done
test "$0" = "$bundle/install-linux.sh" || fail 'installer must run from its exact absolute bundle path'

expected_capsule=$(printf 'schema=owntransit.development-capsule.v1\nversion=0.1.1\nos=linux\narch=%s' "$arch")
test "$(cat "$bundle/CAPSULE")" = "$expected_capsule" || fail 'capsule identity does not match this host'

test "$(wc -l < "$bundle/SHA256SUMS" | tr -d '[:space:]')" = 8 || fail 'SHA256SUMS must contain eight records'
awk '
  BEGIN { ok=1; previous="" }
  {
    if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ || $0 != $1 "  " $2 ||
        $2 !~ /^[A-Za-z0-9._+-]+$/ || $2 == "SHA256SUMS" || seen[$2]++ ||
        (previous != "" && previous >= $2)) ok=0
    previous=$2
  }
  END { exit ok ? 0 : 1 }
' "$bundle/SHA256SUMS" || fail 'SHA256SUMS is malformed, duplicated, or unsorted'
listed=$(awk '{print $2}' "$bundle/SHA256SUMS")
expected_listed='CAPSULE
LICENSE
NOTICE
install-linux.sh
owntransit
owntransit-connector
owntransit-relay
owntransit-relay.oci.tar'
test "$listed" = "$expected_listed" || fail 'SHA256SUMS member set is not exact'
(cd "$bundle" && sha256sum -c SHA256SUMS >/dev/null) || fail 'bundle checksum verification failed'

if test "$role" = connector; then
  test -d /run/systemd/system && test -x /usr/bin/systemctl || fail 'connector preview requires systemd'
fi

prefix=/opt/owntransit-preview/0.1.1
case "$role" in
  client) binary=owntransit; alias=owntransit-preview ;;
  connector) binary=owntransit-connector; alias=owntransit-connector-preview ;;
  relay) binary=owntransit-relay; alias=owntransit-relay-preview ;;
esac
alias_path=/usr/local/bin/$alias
alias_target=$prefix/$role/$binary
if test -e "$alias_path" || test -L "$alias_path"; then
  test -L "$alias_path" && test "$(readlink "$alias_path")" = "$alias_target" || fail "refusing to overwrite unmanaged alias: $alias_path"
fi
ensure_directory() {
  directory=$1
  if test -e "$directory" || test -L "$directory"; then
    test -d "$directory" && test ! -L "$directory" || fail "managed directory is unsafe: $directory"
    test "$(stat -c %u "$directory"):$(stat -c %g "$directory"):$(stat -c %a "$directory")" = 0:0:755 ||
      fail "managed directory metadata differs: $directory"
  else
    install -d -o root -g root -m 0755 "$directory"
  fi
}
ensure_directory /opt
ensure_directory /opt/owntransit-preview
ensure_directory "$prefix"
ensure_directory "$prefix/$role"
ensure_directory /usr/local
ensure_directory /usr/local/bin

install_exact() {
  source=$1
  destination=$2
  mode=$3
  if test -e "$destination" || test -L "$destination"; then
    test -f "$destination" && test ! -L "$destination" || fail "managed destination is unsafe: $destination"
    test "$(stat -c %u "$destination"):$(stat -c %g "$destination"):$(stat -c %a "$destination"):$(stat -c %h "$destination")" = "0:0:$mode:1" ||
      fail "managed destination metadata differs: $destination"
    cmp -s "$source" "$destination" || fail "refusing to overwrite different managed bytes: $destination"
    return
  fi
  install -o root -g root -m "$mode" "$source" "$destination"
}

install_exact "$bundle/LICENSE" "$prefix/$role/LICENSE" 644
install_exact "$bundle/NOTICE" "$prefix/$role/NOTICE" 644
if test "$role" = relay; then
  install_exact "$bundle/owntransit-relay.oci.tar" "$prefix/relay/owntransit-relay.oci.tar" 644
fi
install_exact "$bundle/$binary" "$prefix/$role/$binary" 755

if test -e "$alias_path" || test -L "$alias_path"; then
  test -L "$alias_path" && test "$(readlink "$alias_path")" = "$alias_target" || fail "refusing to overwrite unmanaged alias: $alias_path"
else
  alias_stage=$alias_path.$$.new
  test ! -e "$alias_stage" && test ! -L "$alias_stage" || fail 'alias staging name already exists'
  ln -s "$alias_target" "$alias_stage"
  mv -- "$alias_stage" "$alias_path"
fi

if test "$role" = connector; then
  unit_stage=$(mktemp /run/owntransit-connector-pair.service.XXXXXX) || fail 'cannot stage connector unit'
  cleanup_unit() { rm -f -- "$unit_stage"; }
  trap cleanup_unit EXIT HUP INT TERM
  cat > "$unit_stage" <<EOF
[Unit]
Description=OwnTransit 0.1.1 preview receiver pairing broker
After=network-online.target
Wants=network-online.target
ConditionPathIsDirectory=/var/lib/owntransit-pair

[Service]
Type=simple
User=root
Group=root
UMask=0077
ExecStart=$prefix/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair
Restart=on-failure
RestartSec=5s
LimitCORE=0
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID
AmbientCapabilities=
PrivateDevices=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ReadOnlyPaths=$prefix/connector
ReadWritePaths=/var/lib/owntransit-pair
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
TasksMax=64
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF
  chmod 0644 "$unit_stage"
  chown root:root "$unit_stage"
  unit=/etc/systemd/system/owntransit-connector-pair.service
  if test -e "$unit" || test -L "$unit"; then
    test -f "$unit" && test ! -L "$unit" || fail 'existing preview unit is unsafe'
    test "$(stat -c %u "$unit"):$(stat -c %g "$unit"):$(stat -c %a "$unit"):$(stat -c %h "$unit")" = 0:0:644:1 || fail 'existing preview unit metadata differs'
    cmp -s "$unit_stage" "$unit" || fail 'refusing to overwrite a different preview unit'
  else
    install -o root -g root -m 0644 "$unit_stage" "$unit"
    /usr/bin/systemctl daemon-reload
  fi
  cleanup_unit
  trap - EXIT HUP INT TERM
  printf 'Installed OwnTransit development preview 0.1.1 role %s for linux/%s.\n' "$role" "$arch"
  printf '%s\n' 'Connector preview package installed; service was not enabled or started.'
  printf '%s\n' 'Next: sudo owntransit-connector-preview pair setup'
elif test "$role" = client; then
  printf 'Installed OwnTransit development preview 0.1.1 role %s for linux/%s.\n' "$role" "$arch"
  printf '%s\n' 'Client preview package installed without changing accounts, SSH, or legacy OwnTransit state.'
  printf '%s\n' 'Next: owntransit-preview pair setup'
else
  printf 'Installed OwnTransit development preview 0.1.1 role %s for linux/%s.\n' "$role" "$arch"
  printf '%s\n' 'Relay preview package and OCI archive installed; no image, service, listener, or reverse proxy was changed.'
  printf 'Load image: %s\n' "podman load --input $prefix/relay/owntransit-relay.oci.tar"
  printf 'Create private parent: %s\n' 'install -d -m 0700 "$HOME/.local/state/owntransit-pair"'
  printf 'Initialize once: %s\n' 'podman run --rm --network none --cap-drop all --security-opt no-new-privileges --read-only --volume "$HOME/.local/state/owntransit-pair:/state:rw" owntransit-relay-pair:0.1.1 pair init --state /state/relay'
  printf 'Run loopback relay: %s\n' 'podman run --detach --name owntransit-relay-pair --user 0:0 --network bridge --publish 127.0.0.1:9087:9087/tcp --cap-drop all --security-opt no-new-privileges --read-only --volume "$HOME/.local/state/owntransit-pair:/state:rw" --memory 256m --pids-limit 64 --restart unless-stopped owntransit-relay-pair:0.1.1 pair serve --state /state/relay'
  printf 'Register receiver: %s\n' 'podman exec owntransit-relay-pair /owntransit-relay pair register --state /state/relay RECEIVER_ID'
fi
