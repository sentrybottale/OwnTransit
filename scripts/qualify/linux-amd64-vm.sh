#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

program=linux-amd64-vm
marker=/etc/owntransit-qualification-disposable
qualification_root=/var/lib/owntransit-qualification
service_name=owntransit-connector.service

fail() {
  printf '%s: %s\n' "$program" "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage:
  linux-amd64-vm.sh preflight|prepare \
    --bundle ABSOLUTE_ROOT_OWNED_STAGING_DIRECTORY \
    --checksums-sha256 64_LOWERCASE_HEX \
    --checksums-signature ABSOLUTE_FILE \
    --allowed-signers ABSOLUTE_FILE \
    --signer SAFE_IDENTITY \
    --manifest-signature ABSOLUTE_FILE \
    --release-public-key ABSOLUTE_FILE \
    --policy ABSOLUTE_FILE \
    --policy-signature ABSOLUTE_FILE \
    --policy-public-key ABSOLUTE_FILE

  linux-amd64-vm.sh verify-after-reboot

This harness is destructive only to a brand-new disposable VM. It refuses to
operate unless /etc/owntransit-qualification-disposable is a protected,
root-owned regular file containing exactly:

  OWNTRANSIT_DISPOSABLE_VM=1

prepare installs and enrolls the connector with locally generated throwaway
credentials, points it only at unused loopback port 65535, enables and starts
the unit, writes pre-reboot evidence, and stops. It never invokes reboot.
Reboot the disposable VM yourself, then run verify-after-reboot. The second
phase requires a changed kernel boot ID and emits final JSON evidence.
EOF
}

test "$#" -ge 1 || { usage >&2; exit 2; }
phase=$1
shift
case "$phase" in preflight|prepare|verify-after-reboot) ;; -h|--help) usage; exit 0 ;; *) fail "unknown phase $phase" ;; esac

bundle=
checksums_sha256=
checksums_signature=
allowed_signers=
signer=
manifest_signature=
release_public_key=
policy=
policy_signature=
policy_public_key=
if test "$phase" != verify-after-reboot; then
  while test "$#" -gt 0; do
    case "$1" in
      --bundle|--checksums-sha256|--checksums-signature|--allowed-signers|--signer|--manifest-signature|--release-public-key|--policy|--policy-signature|--policy-public-key)
        test "$#" -ge 2 || fail "$1 requires a value"
        option=$1
        value=$2
        shift 2
        case "$option" in
          --bundle) bundle=$value ;;
          --checksums-sha256) checksums_sha256=$value ;;
          --checksums-signature) checksums_signature=$value ;;
          --allowed-signers) allowed_signers=$value ;;
          --signer) signer=$value ;;
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
else
  test "$#" -eq 0 || fail "verify-after-reboot accepts no arguments"
fi

valid_digest() {
  value=$1
  case "$value" in ''|*[!0-9a-f]*) return 1 ;; esac
  test "${#value}" -eq 64
}

valid_release_id() {
  value=$1
  case "$value" in ''|*[!a-z2-7]*) return 1 ;; esac
  test "${#value}" -eq 52 || return 1
  case "$value" in *[aq]) ;; *) return 1 ;; esac
  test "$value" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

safe_version() {
  case "$1" in ''|*[!A-Za-z0-9._+-]*) return 1 ;; esac
  test "${#1}" -le 128
}

require_root_regular_protected() {
  protected_path=$1
  label=$2
  test -f "$protected_path" && test ! -L "$protected_path" || fail "$label must be a regular non-symlink file"
  test "$(stat -c %u "$protected_path")" -eq 0 || fail "$label must be root-owned"
  test "$(stat -c %h "$protected_path")" -eq 1 || fail "$label must have one hard link"
  protected_mode=$(stat -c %a "$protected_path")
  case "$protected_mode" in [0-7][0-7][0-7]) ;; *) fail "$label has non-canonical mode bits" ;; esac
  protected_permissions=$((0$protected_mode))
  test $((protected_permissions & 022)) -eq 0 || fail "$label is group/world writable"
}

check_host_boundary() {
  test "$(id -u)" -eq 0 || fail "qualification requires root on the disposable VM"
  test "$(uname -s)" = Linux || fail "qualification requires Linux"
  case "$(uname -m)" in x86_64|amd64) ;; *) fail "qualification requires amd64" ;; esac
  test "$(ps -p 1 -o comm= | tr -d '[:space:]')" = systemd || fail "PID 1 is not systemd"
  test -d /run/systemd/system || fail "systemd system manager is not operational"
  require_root_regular_protected "$marker" disposable-marker
  test "$(cat "$marker")" = OWNTRANSIT_DISPOSABLE_VM=1 || fail "disposable marker has the wrong content"
  boot_id=$(cat /proc/sys/kernel/random/boot_id)
  case "$boot_id" in ????????-????-????-????-????????????) ;; *) fail "kernel boot ID is invalid" ;; esac
}

require_commands() {
  for command_name in awk cat chmod chown cmp cp date dirname file find getent grep id install ln mktemp mv ps readlink rm runuser sed sha256sum sleep ss stat strings systemctl systemd-analyze test touch tr uname wc; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
  done
  test "$(command -v runuser)" = /usr/sbin/runuser || fail "runuser must be /usr/sbin/runuser"
  for fixed_command in cat chmod chown cp mv rm test touch; do
    test -x "/usr/bin/$fixed_command" || fail "$fixed_command must be available at /usr/bin/$fixed_command"
  done
}

pristine_host() {
  test ! -e "$qualification_root" && test ! -L "$qualification_root" || fail "qualification state already exists"
  test ! -e /usr/libexec/owntransit && test ! -L /usr/libexec/owntransit || fail "OwnTransit installation root already exists"
  test ! -e /usr/local/bin/owntransit-connector && test ! -L /usr/local/bin/owntransit-connector || fail "OwnTransit connector launcher already exists"
  test ! -e /etc/systemd/system/owntransit-connector.service && test ! -L /etc/systemd/system/owntransit-connector.service || fail "OwnTransit connector unit already exists"
  test ! -e /var/lib/owntransit/connector && test ! -L /var/lib/owntransit/connector || fail "OwnTransit connector workspace already exists"
  ! getent passwd owntransit-connector >/dev/null 2>&1 || fail "OwnTransit connector account already exists"
  ! getent group owntransit-connector >/dev/null 2>&1 || fail "OwnTransit connector group already exists"
  ss -H -ltn 'sport = :65535' | grep . >/dev/null && fail "qualification loopback port 65535 is already listening"
  return 0
}

listed_digest() {
  requested_path=$1
  value=$(awk -v wanted="$requested_path" '$2 == wanted { print $1 }' "$bundle/SHA256SUMS")
  valid_digest "$value" || fail "signed bundle is missing $requested_path"
  printf '%s\n' "$value"
}

check_bundle() {
  valid_digest "$checksums_sha256" || fail "--checksums-sha256 is invalid"
  case "$signer" in ''|*[!A-Za-z0-9._@+-]*) fail "--signer is not a safe identity" ;; esac
  test "$signer" = owntransit-release || fail "release signer identity must be exactly owntransit-release"
  case "$bundle" in /*) ;; *) fail "bundle path must be absolute" ;; esac
  test -d "$bundle" && test ! -L "$bundle" || fail "bundle must be a regular non-symlink directory"
  bundle_resolved=$(CDPATH= cd -P -- "$bundle" && pwd) || fail "cannot resolve bundle"
  test "$bundle_resolved" = "$bundle" || fail "bundle path must be canonical"
  for signed_input in "$manifest_signature" "$release_public_key" "$policy" "$policy_signature" "$policy_public_key"; do
    case "$signed_input" in /*) ;; *) fail "every signed release/policy input must be an absolute path" ;; esac
    require_root_regular_protected "$signed_input" signed-release-policy-input
    signed_parent=$(CDPATH= cd -P -- "$(dirname "$signed_input")" && pwd) || fail "cannot resolve signed input parent"
    test "$signed_parent/$(basename "$signed_input")" = "$signed_input" || fail "signed release/policy input path is not canonical"
    case "$signed_input" in "$bundle"|"$bundle"/*) fail "release/policy trust input must remain outside the candidate bundle" ;; esac
  done

  project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
  "$project_root/packaging/macos/verify-sshsig.sh" \
    --subject "$bundle/SHA256SUMS" \
    --sha256 "$checksums_sha256" \
    --signature "$checksums_signature" \
    --allowed-signers "$allowed_signers" \
    --signer "$signer" \
    --namespace owntransit-release-v1 >/dev/null

  release_id=$(awk -F= '$1 == "release_id" { print $2 }' "$bundle/BUILD-INPUTS")
  valid_release_id "$release_id" || fail "signed BUILD-INPUTS has an invalid canonical release ID"
  version=$(awk -F= '$1 == "version" { print $2 }' "$bundle/BUILD-INPUTS")
  safe_version "$version" || fail "signed BUILD-INPUTS has an unsafe version"
  connector_digest=$(listed_digest artifacts/owntransit-connector-linux-amd64)
  lifecycle_digest=$(listed_digest artifacts/owntransitctl-linux-amd64)
  relay_digest=$(listed_digest artifacts/owntransit-relay-linux-amd64.oci.tar)
  client_digest=$(listed_digest artifacts/owntransit-linux-amd64)
  provision_digest=$(listed_digest artifacts/owntransit-provision-linux-amd64)
  unit_digest=$(listed_digest packaging/systemd/owntransit-connector.service)
  installer_digest=$(listed_digest packaging/scripts/install-linux.sh)

  test "$(sha256sum "$bundle/artifacts/owntransit-connector-linux-amd64" | awk '{print $1}')" = "$connector_digest" || fail "connector artifact checksum mismatch"
  test "$(sha256sum "$bundle/artifacts/owntransitctl-linux-amd64" | awk '{print $1}')" = "$lifecycle_digest" || fail "lifecycle artifact checksum mismatch"
  test "$(sha256sum "$bundle/artifacts/owntransit-provision-linux-amd64" | awk '{print $1}')" = "$provision_digest" || fail "provisioner artifact checksum mismatch"
  file -b "$bundle/artifacts/owntransit-connector-linux-amd64" | grep -Fq 'ELF 64-bit LSB' || fail "connector is not an ELF executable"
  file -b "$bundle/artifacts/owntransit-connector-linux-amd64" | grep -Fq 'x86-64' || fail "connector is not amd64"
  strings "$bundle/artifacts/owntransit-connector-linux-amd64" | grep -Fq 'tcp4 127.0.0.1:22' || fail "connector does not identify the production target"
  if strings "$bundle/artifacts/owntransit-connector-linux-amd64" | grep -Fq '127.0.0.1:2222'; then
    fail "connector contains the POC target"
  fi
  version_json=$("$bundle/artifacts/owntransit-connector-linux-amd64" version)
  printf '%s\n' "$version_json" | grep -Fq '"schema":"owntransit.build.v1"' || fail "connector version schema mismatch"
  printf '%s\n' "$version_json" | grep -Fq '"role":"connector"' || fail "connector version role mismatch"
  printf '%s\n' "$version_json" | grep -Fq '"goos":"linux"' || fail "connector version OS mismatch"
  printf '%s\n' "$version_json" | grep -Fq '"goarch":"amd64"' || fail "connector version architecture mismatch"
  printf '%s\n' "$version_json" | grep -Fq '"connector_target":"tcp4 127.0.0.1:22"' || fail "connector version target mismatch"
  printf '%s\n' "$version_json" | grep -Fq "\"release_id\":\"$release_id\"" || fail "connector version release ID mismatch"
}

systemctl_value() { systemctl show "$service_name" -p "$1" --value; }

assert_service_account() {
  passwd_entry=$(getent passwd owntransit-connector) || fail "connector service account is absent"
  account_home=$(printf '%s\n' "$passwd_entry" | awk -F: '{print $6}')
  account_shell=$(printf '%s\n' "$passwd_entry" | awk -F: '{print $7}')
  test "$account_home" = /nonexistent || fail "connector account has an unexpected home"
  case "$account_shell" in /usr/sbin/nologin|/sbin/nologin) ;; *) fail "connector account has a login shell" ;; esac
  shadow_entry=$(getent shadow owntransit-connector) || fail "connector shadow entry is absent"
  password_field=$(printf '%s\n' "$shadow_entry" | awk -F: '{print $2}')
  case "$password_field" in '!'*|'*'*) ;; *) fail "connector service password is not locked" ;; esac
  connector_uid=$(id -u owntransit-connector)
  connector_reader_gid=$(id -g owntransit-connector)
  test "$connector_uid" -gt 0 && test "$connector_reader_gid" -gt 0 || fail "connector service identity is root"
  test "$(id -G owntransit-connector)" = "$connector_reader_gid" || fail "connector service has an unexpected supplementary group"
  test "$(stat -c %u /var/lib/owntransit/connector)" -eq 0 || fail "connector role parent is not root-owned"
  test "$(stat -c %g /var/lib/owntransit/connector)" -eq 0 || fail "connector role parent is not root-group-owned"
  test "$(stat -c %a /var/lib/owntransit/connector)" = 755 || fail "connector role parent mode is not 0755"
  test "$(stat -c %u /var/lib/owntransit/connector/private)" -eq 0 && test "$(stat -c %g /var/lib/owntransit/connector/private)" -eq 0 && test "$(stat -c %a /var/lib/owntransit/connector/private)" = 700 || fail "private lifecycle root is not root:root 0700"
  test "$(stat -c %u /var/lib/owntransit/connector/authority)" -eq 0 && test "$(stat -c %g /var/lib/owntransit/connector/authority)" -eq 0 && test "$(stat -c %a /var/lib/owntransit/connector/authority)" = 700 || fail "rollback authority root is not root:root 0700"
  test "$(stat -c %u /var/lib/owntransit/connector/runtime)" -eq 0 && test "$(stat -c %g /var/lib/owntransit/connector/runtime)" -eq "$connector_reader_gid" && test "$(stat -c %a /var/lib/owntransit/connector/runtime)" = 750 || fail "runtime view root is not root:reader 0750"
  test "$(stat -c %u /var/lib/owntransit/connector/anchor-view)" -eq 0 && test "$(stat -c %g /var/lib/owntransit/connector/anchor-view)" -eq "$connector_reader_gid" && test "$(stat -c %a /var/lib/owntransit/connector/anchor-view)" = 750 || fail "anchor view root is not root:reader 0750"
  test -z "$(find /var/lib/owntransit/connector -xdev -uid "$connector_uid" -print -quit)" || fail "connector service owns an entry in its role tree"
  env_gid=$(awk -F= '$1 == "OWNTRANSIT_CONNECTOR_READER_GID" { print $2 }' /etc/owntransit/connector-runtime.env)
  test "$env_gid" = "$connector_reader_gid" || fail "connector runtime environment does not bind the exact numeric reader GID"
  test "$(stat -c %u /etc/owntransit/connector-runtime.env)" -eq 0 && test "$(stat -c %g /etc/owntransit/connector-runtime.env)" -eq 0 && test "$(stat -c %a /etc/owntransit/connector-runtime.env)" = 600 || fail "connector runtime environment is not root:root 0600"
}

assert_view_tree() {
  view_root=$1
  view_label=$2
  expected_gid=$(id -g owntransit-connector)
  unexpected=$(find "$view_root" -mindepth 1 ! -type d ! -type f -print -quit)
  test -z "$unexpected" || fail "$view_label contains a non-file/non-directory entry"
  find "$view_root" -mindepth 1 -type d -print |
    while IFS= read -r view_directory; do
      test "$(stat -c %u "$view_directory")" -eq 0 && test "$(stat -c %g "$view_directory")" -eq "$expected_gid" && test "$(stat -c %a "$view_directory")" = 750 || fail "$view_label contains a directory outside root:reader 0750"
    done
  find "$view_root" -mindepth 1 -type f -print |
    while IFS= read -r view_file; do
      test "$(stat -c %u "$view_file")" -eq 0 && test "$(stat -c %g "$view_file")" -eq "$expected_gid" && test "$(stat -c %a "$view_file")" = 640 && test "$(stat -c %h "$view_file")" -eq 1 || fail "$view_label contains a file outside root:reader 0640 single-link policy"
    done
  test -n "$(find "$view_root" -mindepth 1 -type f -print -quit)" || fail "$view_label contains no published material"
}

assert_service_read_only_views() {
  probe_mode=${1:-full}
  expected_gid=$(id -g owntransit-connector)
  for view_root in /var/lib/owntransit/connector/runtime /var/lib/owntransit/connector/anchor-view; do
    /usr/sbin/runuser -u owntransit-connector -- /usr/bin/test -r "$view_root" || fail "connector cannot read a published view root"
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/test -w "$view_root"; then
      fail "connector can write a published view root"
    fi
    probe="$view_root/.owntransit-qualification-write-probe"
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/touch "$probe" >/dev/null 2>&1; then
      rm -f -- "$probe"
      fail "connector created a file in a published view"
    fi
    test ! -e "$probe" && test ! -L "$probe" || fail "failed write probe left an entry"
    readable_file=$(find "$view_root" -type f -print -quit)
    /usr/sbin/runuser -u owntransit-connector -- /usr/bin/cat "$readable_file" >/dev/null || fail "connector cannot read published material"
    test "$probe_mode" = full || continue
    mutation_probe="$view_root/qualification-mutation-probe"
    install -o root -g owntransit-connector -m 0640 /dev/null "$mutation_probe"
    mutation_inode=$(stat -c %i "$mutation_probe")
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/cp /dev/null "$mutation_probe" >/dev/null 2>&1; then
      rm -f -- "$mutation_probe"
      fail "connector replaced published material"
    fi
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/mv "$mutation_probe" "$mutation_probe.renamed" >/dev/null 2>&1; then
      mv -- "$mutation_probe.renamed" "$mutation_probe"
      rm -f -- "$mutation_probe"
      fail "connector renamed published material"
    fi
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/rm -f "$mutation_probe" >/dev/null 2>&1; then
      fail "connector unlinked published material"
    fi
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/chmod 0600 "$mutation_probe" >/dev/null 2>&1; then
      rm -f -- "$mutation_probe"
      fail "connector chmod succeeded on published material"
    fi
    if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/chown "0:$expected_gid" "$mutation_probe" >/dev/null 2>&1; then
      rm -f -- "$mutation_probe"
      fail "connector chown succeeded on published material"
    fi
    test "$(stat -c %i "$mutation_probe")" = "$mutation_inode" && test "$(stat -c %u "$mutation_probe")" -eq 0 && test "$(stat -c %g "$mutation_probe")" -eq "$expected_gid" && test "$(stat -c %a "$mutation_probe")" = 640 || fail "failed mutation probe changed published material"
    rm -f -- "$mutation_probe"
  done
  if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/test -r /var/lib/owntransit/connector/private; then
    fail "connector can read the private lifecycle root"
  fi
  if /usr/sbin/runuser -u owntransit-connector -- /usr/bin/test -r /var/lib/owntransit/connector/authority; then
    fail "connector can read the rollback authority root"
  fi
}

assert_service_hardening() {
  test "$(systemctl_value User)" = owntransit-connector || fail "unit User is not owntransit-connector"
  test "$(systemctl_value Group)" = owntransit-connector || fail "unit Group is not owntransit-connector"
  test "$(systemctl_value NoNewPrivileges)" = yes || fail "NoNewPrivileges is not enabled"
  test "$(systemctl_value PrivateDevices)" = yes || fail "PrivateDevices is not enabled"
  test "$(systemctl_value PrivateTmp)" = yes || fail "PrivateTmp is not enabled"
  test "$(systemctl_value ProtectSystem)" = strict || fail "ProtectSystem is not strict"
  test "$(systemctl_value ProtectHome)" = yes || fail "ProtectHome is not enabled"
  test "$(systemctl_value ProtectKernelTunables)" = yes || fail "ProtectKernelTunables is not enabled"
  test "$(systemctl_value ProtectKernelModules)" = yes || fail "ProtectKernelModules is not enabled"
  test "$(systemctl_value ProtectControlGroups)" = yes || fail "ProtectControlGroups is not enabled"
  test "$(systemctl_value RestrictNamespaces)" = yes || fail "RestrictNamespaces is not enabled"
  test "$(systemctl_value RestrictRealtime)" = yes || fail "RestrictRealtime is not enabled"
  test "$(systemctl_value LockPersonality)" = yes || fail "LockPersonality is not enabled"
  test "$(systemctl_value MemoryDenyWriteExecute)" = yes || fail "MemoryDenyWriteExecute is not enabled"
  test -z "$(systemctl_value CapabilityBoundingSet)" || fail "capability bounding set is not empty"
  test -z "$(systemctl_value AmbientCapabilities)" || fail "ambient capabilities are not empty"
  families=$(systemctl_value RestrictAddressFamilies)
  for family in AF_UNIX AF_INET AF_INET6; do
    printf '%s\n' "$families" | grep -Fq "$family" || fail "address family $family is absent"
  done
  test "$(printf '%s\n' "$families" | wc -w | tr -d '[:space:]')" -eq 3 || fail "unit allows an extra address family"
  test "$(systemctl_value TasksMax)" = 64 || fail "TasksMax is not 64"
  test "$(systemctl_value MemoryMax)" = 268435456 || fail "MemoryMax is not 256M"
  systemd-analyze verify /etc/systemd/system/owntransit-connector.service >/dev/null 2>&1 || fail "systemd unit verification failed"
}

assert_service_running_without_listener() {
  test "$(systemctl_value ActiveState)" = active || fail "connector service is not active"
  test "$(systemctl_value SubState)" = running || fail "connector service is not running"
  main_pid=$(systemctl_value MainPID)
  case "$main_pid" in ''|*[!0-9]*) fail "connector MainPID is invalid" ;; esac
  test "$main_pid" -gt 1 || fail "connector MainPID is not a live service process"
  test -d "/proc/$main_pid" || fail "connector MainPID does not exist"
  if ss -H -lntp | grep -F "pid=$main_pid," >/dev/null; then
    fail "connector process owns a TCP listener"
  fi
}

extract_json_id() {
  summary_file=$1
  value=$(sed -n 's/.*"installation_id":"\([a-z2-7]*\)".*/\1/p' "$summary_file")
  case "$value" in *[!a-z2-7]*|'') fail "bootstrap summary has an invalid installation ID" ;; esac
  test "${#value}" -eq 52 || fail "bootstrap installation ID has the wrong length"
  printf '%s\n' "$value"
}

check_host_boundary
require_commands

if test "$phase" = verify-after-reboot; then
  phase_file="$qualification_root/phase"
  require_root_regular_protected "$phase_file" qualification-phase
  prepared_boot_id=$(awk -F= '$1 == "prepared_boot_id" { print $2 }' "$phase_file")
  recorded_release_id=$(awk -F= '$1 == "release_id" { print $2 }' "$phase_file")
  recorded_checksums=$(awk -F= '$1 == "checksums_sha256" { print $2 }' "$phase_file")
  recorded_connector=$(awk -F= '$1 == "connector_sha256" { print $2 }' "$phase_file")
  recorded_unit=$(awk -F= '$1 == "unit_sha256" { print $2 }' "$phase_file")
  valid_release_id "$recorded_release_id" || fail "recorded release ID is invalid"
  valid_digest "$recorded_checksums" || fail "recorded checksums digest is invalid"
  valid_digest "$recorded_connector" || fail "recorded connector digest is invalid"
  valid_digest "$recorded_unit" || fail "recorded unit digest is invalid"
  test "$prepared_boot_id" != "$boot_id" || fail "kernel boot ID did not change; a real reboot was not observed"
  test "$(sha256sum /usr/libexec/owntransit/roles/connector/current/owntransit-connector | awk '{print $1}')" = "$recorded_connector" || fail "installed connector changed across reboot"
  test "$(sha256sum /etc/systemd/system/owntransit-connector.service | awk '{print $1}')" = "$recorded_unit" || fail "installed unit changed across reboot"
  test "$(systemctl is-enabled "$service_name")" = enabled || fail "connector service is not enabled after reboot"
  assert_service_account
  assert_view_tree /var/lib/owntransit/connector/runtime runtime-view
  assert_view_tree /var/lib/owntransit/connector/anchor-view anchor-view
  assert_service_read_only_views no-root-mutation
  assert_service_hardening
  assert_service_running_without_listener
  restart_count=$(systemctl_value NRestarts)
  case "$restart_count" in ''|*[!0-9]*) fail "service restart count is invalid" ;; esac
  test "$restart_count" -eq 0 || fail "connector restarted unexpectedly after boot"
  active_monotonic=$(systemctl_value ActiveEnterTimestampMonotonic)
  case "$active_monotonic" in ''|*[!0-9]*) fail "service activation timestamp is invalid" ;; esac
  test "$active_monotonic" -gt 0 || fail "service has no current-boot activation timestamp"
  installed_version_json=$(/usr/libexec/owntransit/roles/connector/current/owntransit-connector version)
  printf '%s\n' "$installed_version_json" | grep -Fq "\"release_id\":\"$recorded_release_id\"" || fail "installed release identity changed"
  verified_unix=$(date +%s)
  evidence="$qualification_root/reboot-evidence.json"
  test ! -e "$evidence" && test ! -L "$evidence" || fail "final evidence already exists"
  printf '{"schema":"owntransit.qualify.linux-amd64-reboot.v1","result":"pass","platform":"linux","architecture":"amd64","release_id":"%s","checksums_sha256":"%s","connector_sha256":"%s","unit_sha256":"%s","prepared_boot_id":"%s","verified_boot_id":"%s","verified_unix":%s,"unit_enabled":true,"active_state":"active","sub_state":"running","main_pid":%s,"restart_count":%s,"cold_boot_verified":true,"connector_listener_count":0,"qualification_credentials":"throwaway-local","relay_endpoint":"loopback-refused"}\n' \
    "$recorded_release_id" "$recorded_checksums" "$recorded_connector" "$recorded_unit" "$prepared_boot_id" "$boot_id" "$verified_unix" "$main_pid" "$restart_count" > "$evidence"
  chmod 0644 "$evidence"
  cat "$evidence"
  exit 0
fi

check_bundle
pristine_host
if test "$phase" = preflight; then
  printf '{"schema":"owntransit.qualify.linux-amd64-preflight.v1","result":"pass","platform":"linux","architecture":"amd64","pid1":"systemd","disposable_marker":true,"host_pristine":true,"release_id":"%s","checksums_sha256":"%s","connector_sha256":"%s","unit_sha256":"%s","network_required":false,"reboot_invoked":false}\n' \
    "$release_id" "$checksums_sha256" "$connector_digest" "$unit_digest"
  exit 0
fi

installer="$bundle/packaging/scripts/install-linux.sh"
"$installer" \
  --bundle "$bundle" \
  --role connector \
  --release-id "$release_id" \
  --checksums-sha256 "$checksums_sha256" \
  --artifact-sha256 "$connector_digest" \
  --lifecycle-sha256 "$lifecycle_digest" \
  --manifest-signature "$manifest_signature" \
  --release-public-key "$release_public_key" \
  --policy "$policy" \
  --policy-signature "$policy_signature" \
  --policy-public-key "$policy_public_key" >/dev/null

systemctl is-active --quiet "$service_name" && fail "connector service started before lifecycle work"
for unpublished_root in private authority runtime anchor-view; do
  test ! -e "/var/lib/owntransit/connector/$unpublished_root" && test ! -L "/var/lib/owntransit/connector/$unpublished_root" || fail "installer pre-created bootstrap-owned root $unpublished_root"
done
connector_reader_gid=$(id -g owntransit-connector)
case "$connector_reader_gid" in ''|*[!0-9]*) fail "connector reader GID is invalid" ;; esac
test "$connector_reader_gid" -gt 0 || fail "connector reader GID is root"

install -d -o root -g root -m 0755 "$qualification_root"
private_root="$qualification_root/private"
trust_root="$qualification_root/trust"
relay_parent="$qualification_root/relay"
client_parent="$qualification_root/client"
install -d -o root -g root -m 0700 "$private_root"
install -d -o root -g root -m 0755 "$trust_root"
install -d -o root -g root -m 0755 "$relay_parent"
install -d -o root -g root -m 0755 "$client_parent"
cleanup_sensitive() {
  rm -rf -- "$private_root" "$trust_root" "$relay_parent" "$client_parent"
}
trap cleanup_sensitive EXIT HUP INT TERM

provision="$bundle/artifacts/owntransit-provision-linux-amd64"
ctl="$bundle/artifacts/owntransitctl-linux-amd64"
authority="$private_root/authority"
"$provision" init-authority -out "$authority" > "$private_root/authority-output.json"
route_id=$(sed -n 's/^[[:space:]]*"route_id":[[:space:]]*"\([a-z2-7]*\)",*$/\1/p' "$authority/summary.json")
case "$route_id" in *[!a-z2-7]*|'') fail "authority produced an invalid route ID" ;; esac
test "${#route_id}" -eq 52 || fail "authority route ID has the wrong length"

for trust_file in outer-endpoint-ca-cert.pem inner-connector-ca-cert.pem inner-client-capability-ca-cert.pem deployment-signing-public.pem; do
  install -o root -g root -m 0644 "$authority/$trust_file" "$trust_root/$trust_file"
done
"$ctl" bootstrap \
  --state-root "$relay_parent/private" --rollback-anchor-root "$relay_parent/authority" \
  --runtime-root "$relay_parent/runtime" --runtime-config-root /runtime \
  --anchor-view-root "$relay_parent/anchor-view" --reader-gid "$connector_reader_gid" --role relay \
  --release-id "$release_id" --release-sequence 1 --artifact-sha256 "$relay_digest" --os linux --arch amd64 \
  --outer-ca "$trust_root/outer-endpoint-ca-cert.pem" --inner-connector-ca "$trust_root/inner-connector-ca-cert.pem" \
  --inner-client-ca "$trust_root/inner-client-capability-ca-cert.pem" --deployment-signer "$trust_root/deployment-signing-public.pem" \
  > "$private_root/relay-bootstrap.json"
"$ctl" bootstrap \
  --state-root "$client_parent/private" --rollback-anchor-root "$client_parent/authority" \
  --runtime-root "$client_parent/runtime" --runtime-config-root "$client_parent/runtime" \
  --anchor-view-root "$client_parent/anchor-view" --reader-gid "$connector_reader_gid" --role client \
  --release-id "$release_id" --release-sequence 1 --artifact-sha256 "$client_digest" --os linux --arch amd64 \
  --outer-ca "$trust_root/outer-endpoint-ca-cert.pem" --inner-connector-ca "$trust_root/inner-connector-ca-cert.pem" \
  --inner-client-ca "$trust_root/inner-client-capability-ca-cert.pem" --deployment-signer "$trust_root/deployment-signing-public.pem" \
  > "$private_root/client-bootstrap.json"
/usr/libexec/owntransit/roles/connector/current/owntransitctl bootstrap \
  --state-root /var/lib/owntransit/connector/private --rollback-anchor-root /var/lib/owntransit/connector/authority \
  --runtime-root /var/lib/owntransit/connector/runtime --runtime-config-root /var/lib/owntransit/connector/runtime \
  --anchor-view-root /var/lib/owntransit/connector/anchor-view --reader-gid "$connector_reader_gid" --role connector \
  --release-id "$release_id" --release-sequence 1 --artifact-sha256 "$connector_digest" --os linux --arch amd64 \
  --outer-ca "$trust_root/outer-endpoint-ca-cert.pem" --inner-connector-ca "$trust_root/inner-connector-ca-cert.pem" \
  --inner-client-ca "$trust_root/inner-client-capability-ca-cert.pem" --deployment-signer "$trust_root/deployment-signing-public.pem" \
  --connector-target tcp4/127.0.0.1:22 > "$private_root/connector-bootstrap.json"
connector_id=$(extract_json_id "$private_root/connector-bootstrap.json")

"$ctl" enroll-init --state-root "$relay_parent/private" --out "$private_root/relay-request.otb" > "$private_root/relay-request.json"
/usr/libexec/owntransit/roles/connector/current/owntransitctl enroll-init \
  --state-root /var/lib/owntransit/connector/private --route "$route_id" \
  --out "$private_root/connector-request.otb" > "$private_root/connector-request.json"
"$ctl" enroll-init --state-root "$client_parent/private" --route "$route_id" --connector-id "$connector_id" \
  --out "$private_root/client-request.otb" > "$private_root/client-request.json"

responses="$private_root/responses"
"$provision" approve-initial-route \
  -relay-request "$private_root/relay-request.otb" \
  -connector-request "$private_root/connector-request.otb" \
  -client-request "$private_root/client-request.otb" \
  -outer-ca-cert "$authority/outer-endpoint-ca-cert.pem" -outer-ca-key "$authority/outer-endpoint-ca-key.pem" \
  -inner-connector-ca-cert "$authority/inner-connector-ca-cert.pem" -inner-connector-ca-key "$authority/inner-connector-ca-key.pem" \
  -inner-client-ca-cert "$authority/inner-client-capability-ca-cert.pem" -inner-client-ca-key "$authority/inner-client-capability-ca-key.pem" \
  -deployment-signing-key "$authority/deployment-signing-key.pem" \
  -relay-url wss://127.0.0.1:65535/connects -relay-listen 0.0.0.0:9087 \
  -out "$responses" > "$private_root/approval.json"
/usr/libexec/owntransit/roles/connector/current/owntransitctl apply \
  --state-root /var/lib/owntransit/connector/private \
  --response "$responses/connector-response.otb" > "$private_root/connector-apply.json"
/usr/libexec/owntransit/roles/connector/current/owntransitctl status \
  --state-root /var/lib/owntransit/connector/private | grep -Fq '"active":true' || fail "connector lifecycle state is not active"
/usr/libexec/owntransit/roles/connector/current/owntransitctl verify \
  --state-root /var/lib/owntransit/connector/private >/dev/null

assert_service_account
assert_view_tree /var/lib/owntransit/connector/runtime runtime-view
assert_view_tree /var/lib/owntransit/connector/anchor-view anchor-view
assert_service_read_only_views
/usr/libexec/owntransit/roles/connector/current/owntransitctl verify \
  --state-root /var/lib/owntransit/connector/private >/dev/null
rm -rf -- "$private_root" "$trust_root" "$relay_parent" "$client_parent"
trap - EXIT HUP INT TERM

test "$(sha256sum /etc/systemd/system/owntransit-connector.service | awk '{print $1}')" = "$unit_digest" || fail "installed systemd unit digest mismatch"
assert_service_hardening
systemctl enable "$service_name" >/dev/null
systemctl start "$service_name"
attempt=0
while test "$attempt" -lt 10; do
  test "$(systemctl_value ActiveState)" = active && break
  sleep 1
  attempt=$((attempt + 1))
done
test "$(systemctl is-enabled "$service_name")" = enabled || fail "connector service was not enabled"
assert_service_running_without_listener
restart_count=$(systemctl_value NRestarts)
test "$restart_count" = 0 || fail "connector restarted during initial startup"

prepared_unix=$(date +%s)
phase_file="$qualification_root/phase"
printf '%s\n' \
  'schema=owntransit.qualify.linux-amd64-phase.v1' \
  "release_id=$release_id" \
  "checksums_sha256=$checksums_sha256" \
  "connector_sha256=$connector_digest" \
  "unit_sha256=$unit_digest" \
  "prepared_boot_id=$boot_id" \
  "prepared_unix=$prepared_unix" \
  > "$phase_file"
chmod 0600 "$phase_file"
prepare_evidence="$qualification_root/prepare-evidence.json"
printf '{"schema":"owntransit.qualify.linux-amd64-prepare.v1","result":"awaiting-reboot","platform":"linux","architecture":"amd64","release_id":"%s","checksums_sha256":"%s","connector_sha256":"%s","unit_sha256":"%s","prepared_boot_id":"%s","prepared_unix":%s,"unit_enabled":true,"active_state":"active","sub_state":"running","main_pid":%s,"restart_count":0,"connector_listener_count":0,"qualification_credentials":"throwaway-local","relay_endpoint":"loopback-refused","network_required":false,"reboot_invoked":false}\n' \
  "$release_id" "$checksums_sha256" "$connector_digest" "$unit_digest" "$boot_id" "$prepared_unix" "$main_pid" > "$prepare_evidence"
chmod 0644 "$prepare_evidence"
cat "$prepare_evidence"
printf '%s\n' 'NEXT: reboot this disposable VM, then run scripts/qualify/linux-amd64-vm.sh verify-after-reboot' >&2
