#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() { printf 'owntransit-preview-install: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' 'usage: install-linux.sh --bundle ABSOLUTE_ROOT_OWNED_BUNDLE --role client|connector|relay [--instance NAME]'
}

bundle=
role=
action=install
next=manual
relay_instance=default
instance_set=no
while test "$#" -gt 0; do
  test "$#" -ge 2 || fail "$1 requires a value"
  case "$1" in
    --bundle) test -z "$bundle" || fail '--bundle specified twice'; bundle=$2 ;;
    --role) test -z "$role" || fail '--role specified twice'; role=$2 ;;
    --action) action=$2 ;;
    --next) next=$2 ;;
    --instance) test "$instance_set" = no || fail '--instance specified twice'; relay_instance=$2; instance_set=yes ;;
    *) fail "unknown argument: $1" ;;
  esac
  shift 2
done
case "$role" in client|connector|relay) ;; *) usage >&2; exit 2 ;; esac
case "$action" in install|uninstall) ;; *) fail 'action must be install or uninstall' ;; esac
case "$next" in manual|automatic) ;; *) fail 'invalid next-step mode' ;; esac
test "$instance_set" = no || test "$role" = relay || fail '--instance applies only to the relay role'
case "$relay_instance" in ''|*[!a-z0-9-]*|[!a-z]*|all) fail 'invalid relay instance name' ;; esac
test "${#relay_instance}" -le 32 || fail 'relay instance names are limited to 32 characters'
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

for command_name in awk basename cat chmod chown cmp dirname find grep id install ln mktemp mv readlink rm sed sha256sum sort stat tr uname wc; do
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

expected_capsule=$(printf 'schema=owntransit.development-capsule.v1\nversion=0.5.0\nos=linux\narch=%s' "$arch")
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

if test "$role" = connector || test "$role" = relay; then
  if test "$role" = connector; then test -d /run/systemd/system && test -x /usr/bin/systemctl || fail 'connector preview requires systemd'; fi
  command -v flock >/dev/null 2>&1 || fail 'service package maintenance requires flock'
  for ancestor in / /var /var/lib; do
    test -d "$ancestor" && test ! -L "$ancestor" || fail 'unsafe service maintenance ancestor'
    require_protected "$ancestor"
  done
  manager=/var/lib/owntransit-$role-manager
  if test ! -e "$manager" && test ! -L "$manager"; then install -d -o root -g root -m 0700 "$manager"; fi
  test -d "$manager" && test ! -L "$manager" && test "$(stat -c %u:%g:%a "$manager")" = 0:0:700 || fail 'unsafe service maintenance directory'
  if test ! -e "$manager/package.lock" && test ! -L "$manager/package.lock"; then
    (set -C; : > "$manager/package.lock") || fail 'maintenance lock creation raced; retry'
  fi
  test -f "$manager/package.lock" && test ! -L "$manager/package.lock" && test "$(stat -c %u:%g:%a:%h:%s "$manager/package.lock")" = 0:0:600:1:0 || fail 'unsafe service maintenance lock'
  exec 9<> "$manager/package.lock"
  flock -n 9 || fail 'a service setup or package operation is active; retry when it completes'
fi

named_units=
collect_named_units() {
  for instance in /etc/systemd/system/owntransit-connector-pair@*.service; do
    if test ! -e "$instance" && test ! -L "$instance"; then continue; fi
    name=${instance#/etc/systemd/system/owntransit-connector-pair@}
    name=${name%.service}
    test "${#name}" -le 32 && test "$name" != default && test "$name" != all || fail 'unrecognized named connector unit'
    printf '%s\n' "$name" | grep -Eq '^[a-z][a-z0-9-]*$' || fail 'invalid named connector unit'
    test -f "$instance" && test ! -L "$instance" && test "$(stat -c %u:%g:%a:%h "$instance")" = 0:0:644:1 || fail 'unsafe named connector unit'
    printf '%s\n' "$instance"
  done
}
named_unit_bytes() {
  name=${1#/etc/systemd/system/owntransit-connector-pair@}
  name=${name%.service}
  sed "s@/var/lib/owntransit-pair@/var/lib/owntransit-tunnels/$name@g" "$2"
}
no_unit_overrides() {
  drops=$(/usr/bin/systemctl show "${1##*/}" --property=DropInPaths --value) || fail 'cannot inspect service overrides'
  test -z "$drops" || fail 'connector service has overrides; automatic modification refused'
}
normalize_previous_unit() {
  sed -e 's/0\.1\.[1235678]/0.5.0/g' \
    -e 's/0\.2\.0/0.5.0/g' \
    -e 's/0\.3\.0/0.5.0/g' \
    -e 's/0\.4\.0/0.5.0/g' \
    -e '/^Type=simple$/c\
Type=notify\
NotifyAccess=main\
TimeoutStartSec=30s' \
    -e 's/^CapabilityBoundingSet=CAP_SETUID CAP_SETGID$/CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL/' \
    -e 's/^AmbientCapabilities=$/AmbientCapabilities=CAP_SETUID/' "$1"
}
if test "$role" = connector; then named_units=$(collect_named_units); fi

prefix=/opt/owntransit-preview/0.5.0
case "$role" in
  client) binary=owntransit; alias=owntransit-preview ;;
  connector) binary=owntransit-connector; alias=owntransit-connector-preview ;;
  relay) binary=owntransit-relay; alias=owntransit-relay-preview ;;
esac
alias_path=/usr/local/bin/$alias
alias_target=$prefix/$role/$binary
normal_alias=/usr/local/bin/$binary
previous_alias=
if test -e "$alias_path" || test -L "$alias_path"; then
  test -L "$alias_path" && test "$(stat -c %u "$alias_path")" = 0 || fail "refusing to overwrite unmanaged alias: $alias_path"
  previous_alias=$(readlink "$alias_path")
  case "$previous_alias" in
    "$alias_target") ;;
    "/opt/owntransit-preview/0.1.1/$role/$binary"|"/opt/owntransit-preview/0.1.2/$role/$binary"|"/opt/owntransit-preview/0.1.3/$role/$binary"|"/opt/owntransit-preview/0.1.5/$role/$binary"|"/opt/owntransit-preview/0.1.6/$role/$binary"|"/opt/owntransit-preview/0.1.7/$role/$binary"|"/opt/owntransit-preview/0.1.8/$role/$binary"|"/opt/owntransit-preview/0.2.0/$role/$binary"|"/opt/owntransit-preview/0.3.0/$role/$binary"|"/opt/owntransit-preview/0.4.0/$role/$binary")
      test -f "$previous_alias" && test ! -L "$previous_alias" || fail 'unsafe previous preview executable'
      test "$(stat -c %u:%g:%a:%h "$previous_alias")" = 0:0:755:1 || fail 'previous preview executable metadata differs'
      ;;
    *) fail "refusing to overwrite unmanaged alias: $alias_path" ;;
  esac
fi
if test "$action" = uninstall; then
  if test -z "$previous_alias" && test ! -e "$prefix/$role" && test ! -L "$prefix/$role"; then
    printf 'OwnTransit %s is not installed at this version. Pairing retained.\n' "$role"
    exit 0
  fi
  test "$previous_alias" = "$alias_target" || fail 'install this version before using its uninstaller; no old package was removed'
  ancestor=$prefix/$role
  while :; do
    test -d "$ancestor" && test ! -L "$ancestor" || fail 'unsafe installed ancestor'
    require_protected "$ancestor"
    test "$ancestor" = / && break
    ancestor=$(dirname "$ancestor")
  done
  for name in LICENSE NOTICE "$binary"; do
    file=$prefix/$role/$name
    test -f "$file" && test ! -L "$file" && test "$(stat -c %h "$file")" = 1 || fail 'unsafe installed member'
    require_protected "$file"
    cmp -s "$file" "$bundle/$name" || fail 'installed bytes differ; uninstall refused'
  done
  count=3
  if test "$role" = relay; then
    file=$prefix/relay/owntransit-relay.oci.tar
    test -f "$file" && test ! -L "$file" && test "$(stat -c %h "$file")" = 1 || fail 'unsafe installed image'
    require_protected "$file"
    cmp -s "$file" "$bundle/owntransit-relay.oci.tar" || fail 'installed image differs'
    count=4
  fi
  test "$role" != connector || count=4
  test "$(find "$prefix/$role" -mindepth 1 -maxdepth 1 | wc -l | tr -d '[:space:]')" = "$count" || fail 'unrecognized package files; uninstall refused'
  if test "$role" = connector; then
    unit=/etc/systemd/system/owntransit-connector-pair.service
    test -f "$unit" && test ! -L "$unit" || fail 'connector unit is absent or unsafe'
    require_protected "$unit"
    test -f "$prefix/$role/service.template" && test ! -L "$prefix/$role/service.template" || fail 'unit receipt missing'
    require_protected "$prefix/$role/service.template"
    cmp -s "$unit" "$prefix/$role/service.template" || fail 'connector unit was modified; uninstall refused'
    no_unit_overrides "$unit"
    for instance in $named_units; do
      named_unit_bytes "$instance" "$prefix/$role/service.template" | cmp -s "$instance" - || fail 'named connector unit was modified; uninstall refused'
      no_unit_overrides "$instance"
    done
    for instance in $named_units; do
      /usr/bin/systemctl disable --now "${instance##*/}"
      rm -- "$instance"
    done
    /usr/bin/systemctl disable --now owntransit-connector-pair.service
    rm -- "$unit"
    /usr/bin/systemctl daemon-reload
  elif test "$role" = relay; then
    if test "$instance_set" = yes; then
      "$alias_target" uninstall-managed --instance "$relay_instance" --package-lock-fd 9
      printf 'Relay instance %s stopped. Shared relay software and all retained instance identities remain installed.\n' "$relay_instance"
      exit 0
    fi
    "$alias_target" uninstall-all-managed --package-lock-fd 9
  fi
  if test -L "$normal_alias" && test "$(stat -c %u "$normal_alias")" = 0 && test "$(readlink "$normal_alias")" = "$alias_target"; then rm -- "$normal_alias"; fi
  rm -- "$alias_path"
  # Exact owned files only; never recurse into pairing or administrator data.
  rm -- "$prefix/$role/LICENSE" "$prefix/$role/NOTICE" "$alias_target"
  if test "$role" = connector; then rm -- "$prefix/$role/service.template"; fi
  if test "$role" = relay; then
    test -f "$prefix/relay/owntransit-relay.oci.tar" && test ! -L "$prefix/relay/owntransit-relay.oci.tar" || fail 'unsafe installed image'
    rm -- "$prefix/relay/owntransit-relay.oci.tar"
  fi
  rmdir "$prefix/$role"
  printf 'OwnTransit %s software removed. Pairing and SSH settings retained.\n' "$role"
  test "$role" != relay || printf '%s\n' 'Relay keys, disabled unit, website route and cached rollback images retained; the container is removed.'
  exit 0
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
  test -L "$alias_path" && test "$(readlink "$alias_path")" = "$previous_alias" || fail "alias changed during installation: $alias_path"
fi
if test "$previous_alias" != "$alias_target"; then
  alias_stage=$alias_path.$$.new
  test ! -e "$alias_stage" && test ! -L "$alias_stage" || fail 'alias staging name already exists'
  ln -s "$alias_target" "$alias_stage"
  mv -- "$alias_stage" "$alias_path"
fi
if test ! -e "$normal_alias" && test ! -L "$normal_alias"; then
  ln -s "$alias_target" "$normal_alias"
elif test -L "$normal_alias" && test "$(stat -c %u "$normal_alias")" = 0 && test "$(readlink "$normal_alias")" = "$previous_alias"; then
  normal_stage=$normal_alias.$$.new
  test ! -e "$normal_stage" && test ! -L "$normal_stage" || fail 'command staging name exists'
  ln -s "$alias_target" "$normal_stage"
  mv -- "$normal_stage" "$normal_alias"
fi
public_command=$alias_path
if test -L "$normal_alias" && test "$(readlink "$normal_alias")" = "$alias_target"; then public_command=$normal_alias; fi

if test "$role" = connector; then
  unit_stage=$(mktemp /run/owntransit-connector-pair.service.XXXXXX) || fail 'cannot stage connector unit'
  cleanup_unit() { rm -f -- "$unit_stage"; }
  trap cleanup_unit EXIT HUP INT TERM
  cat > "$unit_stage" <<EOF
[Unit]
Description=OwnTransit 0.5.0 preview receiver pairing broker
After=network-online.target
Wants=network-online.target
ConditionPathIsDirectory=/var/lib/owntransit-pair

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=30s
User=root
Group=root
UMask=0077
ExecStart=$prefix/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair
Restart=on-failure
RestartSec=5s
LimitCORE=0
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL
AmbientCapabilities=CAP_SETUID
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
  instance_stage=$(mktemp /run/owntransit-connector-instance.XXXXXX) || fail 'cannot stage named connector unit'
  cleanup_unit() { rm -f -- "$unit_stage" "$instance_stage"; }
  for instance in $named_units; do
    named_unit_bytes "$instance" "$unit_stage" > "$instance_stage"
    normalize_previous_unit "$instance" | cmp -s "$instance_stage" - || fail 'refusing to overwrite a modified named connector unit'
    no_unit_overrides "$instance"
  done
  if test -e "$unit" || test -L "$unit"; then
    test -f "$unit" && test ! -L "$unit" || fail 'existing preview unit is unsafe'
    test "$(stat -c %u "$unit"):$(stat -c %g "$unit"):$(stat -c %a "$unit"):$(stat -c %h "$unit")" = 0:0:644:1 || fail 'existing preview unit metadata differs'
    if ! cmp -s "$unit_stage" "$unit"; then
      # Accept only the exact previous managed template, not a locally edited
      # service. Keep all confinement; retain the broker's intended UID-drop
      # capability and its ability to terminate its different-UID worker.
      normalize_previous_unit "$unit" | cmp -s "$unit_stage" - || fail 'refusing to overwrite a different preview unit'
      install -o root -g root -m 0644 "$unit_stage" "$unit"
      /usr/bin/systemctl daemon-reload
    fi
  else
    install -o root -g root -m 0644 "$unit_stage" "$unit"
    /usr/bin/systemctl daemon-reload
  fi
  for instance in $named_units; do
    named_unit_bytes "$instance" "$unit_stage" > "$instance_stage"
    if ! cmp -s "$instance_stage" "$instance"; then
      install -o root -g root -m 0644 "$instance_stage" "$instance"
      /usr/bin/systemctl daemon-reload
    fi
  done
  install_exact "$unit_stage" "$prefix/connector/service.template" 644
  cleanup_unit
  trap - EXIT HUP INT TERM
  printf 'OwnTransit 0.5.0 %s installed for linux/%s.\n' "$role" "$arch"
  if test -d /var/lib/owntransit-pair; then
    printf '%s\n' 'Pairing retained. Activate the upgrade:'
    printf '%s\n' '  sudo systemctl restart owntransit-connector-pair.service'
    printf '%s\n' 'Active tunnels disconnect during restart. Do not re-pair for an upgrade.'
  else
    printf 'Next: sudo %s pair setup\n' "$public_command"
    printf '%s\n' 'Enter your VPS relay URL when asked. Fresh service remains disabled until setup.'
  fi
  for instance in $named_units; do
    printf 'Named tunnel upgrade: sudo systemctl try-restart %s\n' "${instance##*/}"
  done
  printf 'Add another client tunnel: sudo %s pair setup --tunnel laptop\n' "$public_command"
  printf 'List local tunnels: sudo %s pair list\n' "$public_command"
elif test "$role" = client; then
  printf 'OwnTransit 0.5.0 client installed for linux/%s. Pairing and SSH settings preserved.\n' "$arch"
  printf 'Next: %s pair setup\n' "$public_command"
  printf '%s\n' 'Then answer its prompts: your relay URL and the private receiver code (otpair2.).'
  printf 'Select another tunnel: %s pair setup --tunnel office\n' "$public_command"
else
  printf 'OwnTransit 0.5.0 relay package installed for linux/%s.\n' "$arch"
  printf 'Selected relay instance: %s\n' "$relay_instance"
  if test "$next" = manual; then printf 'Next: sudo %s setup --instance %s\n' "$public_command" "$relay_instance"; else printf '%s\n' 'Starting selected relay setup now; answer its prompts below.'; fi
  printf '%s\n' "Use this instance's existing URL for upgrades. To add a separate relay, choose a new --instance NAME and a different HTTPS hostname."
  printf 'List relay instances: sudo %s list\n' "$public_command"
fi
if test "$role" = relay; then
  printf 'Remove only this relay: curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.5.0/install-preview-linux.sh | sudo sh -s -- relay --instance %s --uninstall\n' "$relay_instance"
else
  printf 'Uninstall: curl -fsSL https://github.com/sentrybottale/OwnTransit/releases/download/v0.5.0/install-preview-linux.sh | sudo sh -s -- %s --uninstall\n' "$role"
fi
