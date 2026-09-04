#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

program=linux-relay-exchange
marker=/etc/owntransit-relay-exchange-qualification-disposable
qualification_root=/var/lib/owntransit-qualification
evidence_path=$qualification_root/relay-exchange-evidence.json

fail() {
  printf '%s: %s\n' "$program" "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: linux-relay-exchange.sh \
  --bundle ABSOLUTE_ROOT_OWNED_STAGING_DIRECTORY \
  --checksums-sha256 AUTHENTICATED_64_LOWERCASE_HEX \
  --native-checksums-signature ABSOLUTE_EXTERNAL_NATIVE_SHA256SUMS_SIGNATURE \
  --allowed-signers ABSOLUTE_EXTERNAL_FILE \
  --manifest-signature ABSOLUTE_EXTERNAL_FILE \
  --release-public-key ABSOLUTE_EXTERNAL_FILE \
  --policy ABSOLUTE_EXTERNAL_FILE \
  --policy-signature ABSOLUTE_EXTERNAL_FILE \
  --policy-public-key ABSOLUTE_EXTERNAL_FILE \
  --exchange-endpoint wss://PUBLIC_DNS_NAME/connects/enrollment \
  --non-loopback-ip EXACT_HOST_IPV4

Destructive qualification for a fresh, disposable supported Linux host
(amd64 or arm64) on which the exact native relay role from the supplied signed
bundle is already installed but not enabled or running. The script infers the
canonical architecture from the machine and requires the protected
disposable-host marker containing OWNTRANSIT_RELAY_EXCHANGE_DISPOSABLE=1. It
consumes that marker before its first package mutation, replays the exact signed
manifest and policy through the installed manager-bound lifecycle, starts only its
generated exchange instance, performs a real public-WSS mailbox allocation and
opaque response write, stops that exact instance, then runs the authenticated
relay uninstaller. It preserves the installed release, image and package
floors, removes generated throwaway material on every handled exit, and writes
non-secret JSON evidence beneath /var/lib/owntransit-qualification.

The public DNS name must resolve to exactly --non-loopback-ip on this host.
The endpoint and IP are deliberately omitted from evidence.
EOF
}

bundle=
checksums_sha256=
native_checksums_signature=
allowed_signers=
manifest_signature=
release_public_key=
policy=
policy_signature=
policy_public_key=
exchange_endpoint=
non_loopback_ip=
while test "$#" -gt 0; do
  case "$1" in
    --bundle|--checksums-sha256|--native-checksums-signature|--allowed-signers|--manifest-signature|--release-public-key|--policy|--policy-signature|--policy-public-key|--exchange-endpoint|--non-loopback-ip)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --bundle) bundle=$value ;;
        --checksums-sha256) checksums_sha256=$value ;;
        --native-checksums-signature) native_checksums_signature=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --manifest-signature) manifest_signature=$value ;;
        --release-public-key) release_public_key=$value ;;
        --policy) policy=$value ;;
        --policy-signature) policy_signature=$value ;;
        --policy-public-key) policy_public_key=$value ;;
        --exchange-endpoint) exchange_endpoint=$value ;;
        --non-loopback-ip) non_loopback_ip=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

valid_digest() {
  digest_value=$1
  case "$digest_value" in ''|*[!0-9a-f]*) return 1 ;; esac
  test "${#digest_value}" -eq 64
}

valid_release_id() {
  id_value=$1
  case "$id_value" in ''|*[!a-z2-7]*) return 1 ;; esac
  test "${#id_value}" -eq 52 || return 1
  case "$id_value" in *[aq]) ;; *) return 1 ;; esac
  test "$id_value" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

require_root_regular_protected() {
  protected_path=$1
  protected_label=$2
  case "$protected_path" in /*) ;; *) fail "$protected_label path must be absolute" ;; esac
  if test ! -f "$protected_path" || test -L "$protected_path"; then
    fail "$protected_label must be a regular non-symlink file"
  fi
  protected_parent=$(CDPATH='' cd -P -- "$(dirname "$protected_path")" && pwd) || fail "cannot resolve $protected_label parent"
  test "$protected_parent/$(basename "$protected_path")" = "$protected_path" || fail "$protected_label path must be canonical"
  test "$(stat -c %u "$protected_path")" -eq 0 || fail "$protected_label must be root-owned"
  test "$(stat -c %h "$protected_path")" -eq 1 || fail "$protected_label must have exactly one hard link"
  protected_mode=$(stat -c %a "$protected_path")
  case "$protected_mode" in [0-7][0-7][0-7]) ;; *) fail "$protected_label has non-canonical mode bits" ;; esac
  protected_permissions=$((0$protected_mode))
  test $((protected_permissions & 022)) -eq 0 || fail "$protected_label is group/world writable"
}

require_root_directory_protected() {
  protected_directory=$1
  directory_label=$2
  if test ! -d "$protected_directory" || test -L "$protected_directory"; then
    fail "$directory_label must be a regular non-symlink directory"
  fi
  test "$(stat -c %u "$protected_directory")" -eq 0 || fail "$directory_label must be root-owned"
  directory_mode=$(stat -c %a "$protected_directory")
  case "$directory_mode" in [0-7][0-7][0-7]) ;; *) fail "$directory_label has non-canonical mode bits" ;; esac
  directory_permissions=$((0$directory_mode))
  test $((directory_permissions & 022)) -eq 0 || fail "$directory_label is group/world writable"
}

require_protected_ancestor_chain() {
  protected_input=$1
  protected_input_label=$2
  protected_ancestor=$(dirname "$protected_input")
  while :; do
    require_root_directory_protected "$protected_ancestor" "$protected_input_label ancestor"
    test "$protected_ancestor" != / || break
    protected_ancestor=$(dirname "$protected_ancestor")
  done
}

require_protected_bundle_descendants() {
  if ! find "$bundle" -type d -exec /bin/sh -c '
    for directory do
      test -d "$directory" && test ! -L "$directory" || exit 1
      test "$(stat -c %u "$directory")" -eq 0 || exit 1
      mode=$(stat -c %a "$directory")
      case "$mode" in [0-7][0-7][0-7]) ;; *) exit 1 ;; esac
      test $((0$mode & 022)) -eq 0 || exit 1
    done
  ' owntransit-bundle-directory-check {} +; then
    fail "bundle contains a non-root-owned or writable directory"
  fi
  if ! find "$bundle" -type f -exec /bin/sh -c '
    for file do
      test -f "$file" && test ! -L "$file" || exit 1
      test "$(stat -c %u "$file")" -eq 0 || exit 1
      test "$(stat -c %h "$file")" -eq 1 || exit 1
      mode=$(stat -c %a "$file")
      case "$mode" in [0-7][0-7][0-7]) ;; *) exit 1 ;; esac
      test $((0$mode & 022)) -eq 0 || exit 1
    done
  ' owntransit-bundle-file-check {} +; then
    fail "bundle contains a non-root-owned, writable, or multiply linked file"
  fi
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

listed_digest() {
  requested_path=$1
  listed_count=$(awk -v wanted="$requested_path" '$2 == wanted { count++ } END { print count + 0 }' "$bundle/SHA256SUMS")
  test "$listed_count" -eq 1 || fail "signed bundle does not contain exactly one checksum for $requested_path"
  listed_value=$(awk -v wanted="$requested_path" '$2 == wanted { print $1 }' "$bundle/SHA256SUMS")
  valid_digest "$listed_value" || fail "signed bundle has an invalid checksum for $requested_path"
  printf '%s\n' "$listed_value"
}

verify_member() {
  member_path=$1
  member_label=$2
  require_root_regular_protected "$bundle/$member_path" "$member_label"
  member_digest=$(listed_digest "$member_path")
  test "$(sha256_file "$bundle/$member_path")" = "$member_digest" || fail "$member_label checksum mismatch"
}

build_input() {
  input_name=$1
  input_count=$(awk -F= -v wanted="$input_name" '$1 == wanted { count++ } END { print count + 0 }' "$bundle/BUILD-INPUTS")
  test "$input_count" -eq 1 || fail "BUILD-INPUTS does not contain exactly one $input_name"
  awk -F= -v wanted="$input_name" '$1 == wanted { print substr($0, length(wanted) + 2) }' "$bundle/BUILD-INPUTS"
}

stage_executable() {
  executable_source=$1
  executable_target=$2
  executable_digest=$3
  test ! -e "$executable_target" && test ! -L "$executable_target" || fail "executable stage already exists"
  install -o root -g root -m 0700 "$executable_source" "$executable_target"
  require_root_regular_protected "$executable_target" staged-executable
  test "$(stat -c %g "$executable_target")" -eq 0 || fail "staged executable must be root-group-owned"
  test "$(stat -c %a "$executable_target")" = 700 || fail "staged executable must be mode 0700"
  test "$(sha256_file "$executable_target")" = "$executable_digest" || fail "staged executable differs from its signed member"
}

verify_native_build_identity() {
  native_executable=$1
  native_role=$2
  native_version_json=$("$native_executable" version) || fail "$native_role version inspection failed on this machine"
  printf '%s\n' "$native_version_json" | grep -Fq '"schema":"owntransit.build.v1"' || fail "$native_role version schema mismatch"
  printf '%s\n' "$native_version_json" | grep -Fq "\"role\":\"$native_role\"" || fail "$native_role version role mismatch"
  printf '%s\n' "$native_version_json" | grep -Fq '"goos":"linux"' || fail "$native_role version OS mismatch"
  printf '%s\n' "$native_version_json" | grep -Fq "\"goarch\":\"$qualification_arch\"" || fail "$native_role version architecture mismatch"
  printf '%s\n' "$native_version_json" | grep -Fq "\"release_id\":\"$release_id\"" || fail "$native_role version release ID mismatch"
}

test "$(uname -s)" = Linux || fail "qualification requires Linux"
case "$(uname -m)" in
  x86_64|amd64) qualification_arch=amd64 ;;
  aarch64|arm64) qualification_arch=arm64 ;;
  *) fail "qualification requires a supported amd64 or arm64 Linux machine" ;;
esac
client_artifact=artifacts/owntransit-linux-$qualification_arch
provisioner_artifact=artifacts/owntransit-provision-linux-$qualification_arch
relay_artifact=artifacts/owntransit-relay-linux-$qualification_arch.oci.tar
lifecycle_artifact=artifacts/owntransitctl-linux-$qualification_arch
test "$(id -u)" -eq 0 || fail "qualification requires root"
test "$(ps -p 1 -o comm= | tr -d '[:space:]')" = systemd || fail "PID 1 is not systemd"
test -d /run/systemd/system || fail "systemd system manager is not operational"
require_root_regular_protected "$marker" disposable-marker
test "$(stat -c %g "$marker")" -eq 0 || fail "disposable marker must be root-group-owned"
test "$(cat "$marker")" = OWNTRANSIT_RELAY_EXCHANGE_DISPOSABLE=1 || fail "disposable marker has the wrong content"

for command_name in awk basename cat chmod cmp curl date dirname find getent grep id install ip mktemp mv podman ps readlink rm sha256sum sleep sort ss ssh-keygen stat systemctl systemd-analyze tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
test "$(command -v podman)" = /usr/bin/podman || fail "qualification requires Podman at /usr/bin/podman"
test "$(command -v ssh-keygen)" = /usr/bin/ssh-keygen || fail "qualification requires OpenSSH ssh-keygen at /usr/bin/ssh-keygen"
unset CONTAINER_HOST CONTAINER_CONNECTION CONTAINER_SSHKEY
test "$(podman info --format '{{.Host.Security.Rootless}}')" = false || fail "qualification requires rootful Podman"
test "$(podman info --format '{{.Host.ServiceIsRemote}}')" = false || fail "qualification requires the local Podman engine"

valid_digest "$checksums_sha256" || fail "--checksums-sha256 is invalid"
case "$bundle" in /*) ;; *) fail "--bundle must be absolute" ;; esac
if test ! -d "$bundle" || test -L "$bundle"; then
  fail "bundle must be a regular non-symlink directory"
fi
bundle_resolved=$(CDPATH='' cd -P -- "$bundle" && pwd) || fail "cannot resolve bundle"
test "$bundle_resolved" = "$bundle" || fail "bundle path must be canonical"
bundle_ancestor=$bundle
while :; do
  require_root_directory_protected "$bundle_ancestor" bundle-ancestor
  test "$bundle_ancestor" != / || break
  bundle_ancestor=$(dirname "$bundle_ancestor")
done
test -z "$(find "$bundle" -type l -print -quit)" || fail "bundle tree contains a symlink"
test -z "$(find "$bundle" ! -type d ! -type f -print -quit)" || fail "bundle tree contains a non-file entry"
require_protected_bundle_descendants
require_root_regular_protected "$bundle/SHA256SUMS" bundle-checksum-record
for trust_input in \
  "$native_checksums_signature" \
  "$allowed_signers" \
  "$manifest_signature" \
  "$release_public_key" \
  "$policy" \
  "$policy_signature" \
  "$policy_public_key"; do
  require_root_regular_protected "$trust_input" independent-trust-input
  require_protected_ancestor_chain "$trust_input" independent-trust-input
  case "$trust_input" in "$bundle"|"$bundle"/*) fail "independent trust input must remain outside the candidate bundle" ;; esac
done
test -s "$native_checksums_signature" || fail "native checksum signature is empty"
test "$(wc -c < "$native_checksums_signature" | tr -d '[:space:]')" -le 16384 || fail "native checksum signature is unexpectedly large"
test -s "$allowed_signers" || fail "allowed signers is empty"
test "$(wc -c < "$allowed_signers" | tr -d '[:space:]')" -le 65536 || fail "allowed signers is unexpectedly large"

test "$(sha256_file "$bundle/SHA256SUMS")" = "$checksums_sha256" || fail "native SHA256SUMS differs from its independently supplied digest"
/usr/bin/ssh-keygen -Y verify \
  -f "$allowed_signers" \
  -I owntransit-release \
  -n owntransit-release-v1 \
  -s "$native_checksums_signature" \
  < "$bundle/SHA256SUMS" >/dev/null 2>&1 || fail "native SHA256SUMS signature did not verify"

for selected_member in \
  BUILD-INPUTS \
  RELEASE-MANIFEST.json \
  "$client_artifact" \
  "$provisioner_artifact" \
  "$relay_artifact" \
  "$lifecycle_artifact" \
  packaging/scripts/uninstall-linux.sh \
  packaging/systemd/owntransit-relay.service \
  packaging/systemd/owntransit-relay-exchange-template.service; do
  verify_member "$selected_member" "$selected_member"
done

release_id=$(build_input release_id)
valid_release_id "$release_id" || fail "BUILD-INPUTS has an invalid release ID"
release_sequence=$(build_input release_sequence)
case "$release_sequence" in ''|*[!0-9]*) fail "BUILD-INPUTS has an invalid release sequence" ;; esac
test "$release_sequence" -gt 0 || fail "BUILD-INPUTS release sequence must be positive"
relay_artifact_digest=$(listed_digest "$relay_artifact")
client_artifact_digest=$(listed_digest "$client_artifact")
provisioner_artifact_digest=$(listed_digest "$provisioner_artifact")
lifecycle_artifact_digest=$(listed_digest "$lifecycle_artifact")
uninstaller_digest=$(listed_digest packaging/scripts/uninstall-linux.sh)
exchange_unit_digest=$(listed_digest packaging/systemd/owntransit-relay-exchange-template.service)
relay_unit_digest=$(listed_digest packaging/systemd/owntransit-relay.service)
manifest_sha256=$(sha256_file "$bundle/RELEASE-MANIFEST.json")
policy_sha256=$(sha256_file "$policy")

case "$exchange_endpoint" in wss://*/connects/enrollment) ;; *) fail "--exchange-endpoint must be one canonical public WSS enrollment URL" ;; esac
endpoint_host=${exchange_endpoint#"wss://"}
endpoint_host=${endpoint_host%"/connects/enrollment"}
case "$endpoint_host" in
  ''|*:*|*/*|*[!a-z0-9.-]*|.*|*.|*..*|-*|*-|*.-*|*-.*) fail "--exchange-endpoint must use one lowercase unadorned DNS name" ;;
  *.*) ;;
  *) fail "--exchange-endpoint must use a qualified public DNS name" ;;
esac
case "$non_loopback_ip" in ''|127.*|0.*|*[!0-9.]*) fail "--non-loopback-ip must be one exact non-loopback host IPv4 address" ;; esac
printf '%s\n' "$non_loopback_ip" | awk -F. '
  NF != 4 { exit 1 }
  { for (i = 1; i <= 4; i++) if ($i == "" || $i !~ /^[0-9]+$/ || $i + 0 > 255) exit 1 }
' || fail "--non-loopback-ip is not valid IPv4"
ip -o -4 address show | awk -v wanted="$non_loopback_ip" '
  { split($4, address, "/"); if (address[1] == wanted) found = 1 }
  END { exit !found }
' || fail "--non-loopback-ip is not assigned to this host"
dns_addresses=$(getent ahosts "$endpoint_host" | awk '{print $1}' | sort -u)
test "$dns_addresses" = "$non_loopback_ip" || fail "public exchange DNS must resolve to exactly --non-loopback-ip on this qualification host"

current_link=/usr/libexec/owntransit/roles/relay/current
installed_release=/usr/libexec/owntransit/roles/relay/releases/$release_id
installed_archive=$installed_release/owntransit-relay.oci.tar
installed_lifecycle=$installed_release/owntransitctl
installed_receipt=$installed_release/receipt.json
installed_selector=/usr/libexec/owntransit/roles/relay/selector.json
installed_anchor=/var/lib/owntransit/package-rollback/relay/anchor.json
installed_unit=/etc/systemd/system/owntransit-relay-exchange@.service
installed_relay_unit=/etc/systemd/system/owntransit-relay.service
relay_environment=/etc/owntransit/relay-container.env
relay_state_root=/var/lib/owntransit/relay
test -L "$current_link" || fail "installed relay current selector is absent"
test "$(readlink "$current_link")" = "releases/$release_id" || fail "installed relay selects another release"
require_root_directory_protected "$installed_release" installed-relay-release
require_root_regular_protected "$installed_archive" installed-relay-archive
test "$(sha256_file "$installed_archive")" = "$relay_artifact_digest" || fail "installed relay archive differs from the authenticated bundle"
require_root_regular_protected "$installed_lifecycle" installed-relay-lifecycle
require_protected_ancestor_chain "$installed_lifecycle" installed-relay-lifecycle
test "$(stat -c %g "$installed_lifecycle")" -eq 0 && test "$(stat -c %a "$installed_lifecycle")" = 700 || fail "installed relay lifecycle metadata is invalid"
test "$(sha256_file "$installed_lifecycle")" = "$lifecycle_artifact_digest" || fail "installed relay lifecycle differs from the authenticated bundle"
require_root_regular_protected "$installed_unit" installed-exchange-template
test "$(sha256_file "$installed_unit")" = "$exchange_unit_digest" || fail "installed exchange template differs from the authenticated bundle"
cmp -s "$bundle/packaging/systemd/owntransit-relay-exchange-template.service" "$installed_unit" || fail "installed exchange template bytes differ from the authenticated bundle"
require_root_regular_protected "$installed_relay_unit" installed-relay-unit
test "$(sha256_file "$installed_relay_unit")" = "$relay_unit_digest" || fail "installed enrolled relay unit differs from the authenticated bundle"
cmp -s "$bundle/packaging/systemd/owntransit-relay.service" "$installed_relay_unit" || fail "installed enrolled relay unit bytes differ from the authenticated bundle"
require_root_regular_protected "$relay_environment" relay-container-environment
test "$(stat -c %a "$relay_environment")" = 600 || fail "relay container environment must be mode 0600"
relay_environment_sha256_before=$(sha256_file "$relay_environment")
test "$(wc -l < "$relay_environment" | tr -d '[:space:]')" -eq 3 || fail "relay container environment has an unexpected field count"
relay_image=$(awk -F= '$1 == "OWNTRANSIT_RELAY_IMAGE" { print $2 }' "$relay_environment")
relay_uid=$(awk -F= '$1 == "OWNTRANSIT_RELAY_UID" { print $2 }' "$relay_environment")
relay_gid=$(awk -F= '$1 == "OWNTRANSIT_RELAY_READER_GID" { print $2 }' "$relay_environment")
case "$relay_image" in sha256:*) ;; *) fail "relay container environment has an invalid image ID" ;; esac
valid_digest "${relay_image#sha256:}" || fail "relay container environment has a noncanonical image ID"
case "$relay_uid:$relay_gid" in *[!0-9:]*|:*|*:) fail "relay container environment has invalid service IDs" ;; esac
if test "$relay_uid" -le 0 || test "$relay_gid" -le 0; then
  fail "relay container environment selects a root service identity"
fi
test "$(grep -c '^OWNTRANSIT_RELAY_IMAGE=' "$relay_environment")" -eq 1 || fail "relay image environment field is ambiguous"
test "$(grep -c '^OWNTRANSIT_RELAY_UID=' "$relay_environment")" -eq 1 || fail "relay UID environment field is ambiguous"
test "$(grep -c '^OWNTRANSIT_RELAY_READER_GID=' "$relay_environment")" -eq 1 || fail "relay GID environment field is ambiguous"
podman image exists "$relay_image" || fail "installed relay image is absent"
installed_image_arch=$(podman image inspect --format '{{.Architecture}}' "$relay_image") || fail "cannot inspect the installed relay image architecture"
test "$installed_image_arch" = "$qualification_arch" || fail "installed relay image architecture does not match the qualification machine"
systemd-analyze verify "$installed_unit" >/dev/null 2>&1 || fail "installed exchange template failed systemd verification"
systemd-analyze verify "$installed_relay_unit" >/dev/null 2>&1 || fail "installed enrolled relay unit failed systemd verification"

require_root_directory_protected "$relay_state_root" relay-state-root
test "$(stat -c %g "$relay_state_root")" -eq 0 && test "$(stat -c %a "$relay_state_root")" = 755 || fail "relay state root is not root:root mode 0755"
test -z "$(find "$relay_state_root" -mindepth 1 -print -quit)" || fail "relay endpoint state already exists; qualification requires a pristine un-enrolled role"
for supervisor_record in relay.intent relay.restart; do
  test ! -e "/var/lib/owntransit/package-supervisor/$supervisor_record" && test ! -L "/var/lib/owntransit/package-supervisor/$supervisor_record" || fail "a relay package mutation or restart is already active"
done

if systemctl is-active --quiet owntransit-relay.service; then
  fail "enrolled relay is active; qualification will not disrupt it"
fi
if systemctl is-enabled --quiet owntransit-relay.service; then
  fail "enrolled relay is enabled; qualification requires an unactivated disposable install"
fi
existing_exchange_units=$(systemctl list-units --all --plain --no-legend --no-pager 'owntransit-relay-exchange@*.service' | awk '{print $1}')
test -z "$existing_exchange_units" || fail "an exchange instance is already loaded"
if podman container exists owntransit-relay-exchange; then
  fail "the reserved exchange container name is already present"
fi
if ss -H -ltn 'sport = :9087' | grep . >/dev/null; then
  fail "host TCP port 9087 is already listening"
fi

if test -e "$qualification_root" || test -L "$qualification_root"; then
  if test ! -d "$qualification_root" || test -L "$qualification_root"; then
    fail "qualification root is not a regular directory"
  fi
  if test "$(stat -c %u "$qualification_root")" -ne 0 || test "$(stat -c %g "$qualification_root")" -ne 0 || test "$(stat -c %a "$qualification_root")" != 755; then
    fail "qualification root is not root:root mode 0755"
  fi
else
  install -d -o root -g root -m 0755 "$qualification_root"
fi
if test -e "$evidence_path" || test -L "$evidence_path"; then
  fail "relay exchange qualification evidence already exists"
fi
workspace=$(mktemp -d "$qualification_root/.relay-exchange.XXXXXX") || fail "cannot create qualification workspace"
workspace=$(CDPATH='' cd -P -- "$workspace" && pwd) || fail "cannot resolve qualification workspace"
case "$workspace" in "$qualification_root/.relay-exchange."*) ;; *) fail "qualification workspace escaped its fixed root" ;; esac
exchange_unit=
cleanup() {
  set +e
  if test -n "$exchange_unit"; then
    systemctl stop "$exchange_unit" >/dev/null 2>&1
    systemctl reset-failed "$exchange_unit" >/dev/null 2>&1
  fi
  rm -rf -- "$workspace"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

staged_executables=$workspace/executables
install -d -o root -g root -m 0700 "$staged_executables"
client=$staged_executables/owntransit
provisioner=$staged_executables/owntransit-provision
uninstaller=$staged_executables/uninstall-linux.sh
stage_executable "$bundle/$client_artifact" "$client" "$client_artifact_digest"
stage_executable "$bundle/$provisioner_artifact" "$provisioner" "$provisioner_artifact_digest"
stage_executable "$bundle/packaging/scripts/uninstall-linux.sh" "$uninstaller" "$uninstaller_digest"
verify_native_build_identity "$client" client
verify_native_build_identity "$provisioner" provisioner

rm -f -- "$marker"
test ! -e "$marker" && test ! -L "$marker" || fail "one-time disposable marker was not consumed"

package_apply_result=$workspace/package-apply.json
env -i \
  HOME=/root \
  LANG=C \
  LC_ALL=C \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  "$installed_lifecycle" package-apply \
    --role relay \
    --bundle "$bundle" \
    --manifest "$bundle/RELEASE-MANIFEST.json" \
    --manifest-signature "$manifest_signature" \
    --release-public-key "$release_public_key" \
    --policy "$policy" \
    --policy-signature "$policy_signature" \
    --policy-public-key "$policy_public_key" \
    > "$package_apply_result" || fail "installed lifecycle rejected the exact signed relay release or policy"
test "$(wc -l < "$package_apply_result" | tr -d '[:space:]')" -eq 1 || fail "manager-bound package result is not one canonical record"
grep -Fq '"schema":"owntransit.ctl.package-lifecycle.v1"' "$package_apply_result" || fail "manager-bound package result has the wrong schema"
grep -Fq '"action":"apply"' "$package_apply_result" || fail "manager-bound package result did not apply the signed decision"
grep -Fq '"role":"relay"' "$package_apply_result" || fail "manager-bound package result selected another role"
grep -Fq "\"current_release_id\":\"$release_id\"" "$package_apply_result" || fail "manager-bound package result selected another release"
grep -Fq '"idempotent":true' "$package_apply_result" || fail "manager-bound package replay was not an exact idempotent verification"
test "$(sha256_file "$relay_environment")" = "$relay_environment_sha256_before" || fail "idempotent manager verification changed the relay image environment"
for supervisor_record in relay.intent relay.restart; do
  test ! -e "/var/lib/owntransit/package-supervisor/$supervisor_record" && test ! -L "/var/lib/owntransit/package-supervisor/$supervisor_record" || fail "manager-bound package verification left a supervisor record"
done

for lifecycle_record in "$installed_receipt" "$installed_selector" "$installed_anchor"; do
  require_root_regular_protected "$lifecycle_record" manager-bound-lifecycle-record
  test "$(stat -c %g "$lifecycle_record")" -eq 0 && test "$(stat -c %a "$lifecycle_record")" = 600 || fail "manager-bound lifecycle record metadata is invalid"
done
receipt_sha256=$(sha256_file "$installed_receipt")
selector_sha256=$(sha256_file "$installed_selector")
anchor_sha256=$(sha256_file "$installed_anchor")

credential_store=$workspace/courier-credential
allocation_hash=$("$client" courier-credential-init --store "$credential_store") || fail "cannot create throwaway courier credential"
valid_digest "$allocation_hash" || fail "courier credential command returned an invalid allocation hash"
exchange_unit=owntransit-relay-exchange@$allocation_hash.service

systemctl start "$exchange_unit"
attempt=0
while test "$attempt" -lt 10; do
  test "$(systemctl show "$exchange_unit" -p ActiveState --value)" = active &&
    test "$(systemctl show "$exchange_unit" -p SubState --value)" = running && break
  sleep 1
  attempt=$((attempt + 1))
done
test "$(systemctl show "$exchange_unit" -p ActiveState --value)" = active || fail "exchange unit did not become active"
test "$(systemctl show "$exchange_unit" -p SubState --value)" = running || fail "exchange unit did not remain running"
test "$(systemctl show "$exchange_unit" -p FragmentPath --value)" = "$installed_unit" || fail "exchange instance did not load the authenticated installed template"
systemctl show "$exchange_unit" -p Conflicts --value | tr ' ' '\n' | grep -Fxq owntransit-relay.service || fail "exchange instance does not conflict with the enrolled relay"
if systemctl is-enabled --quiet "$exchange_unit"; then
  fail "temporary exchange instance became enabled"
fi

published_port=$(podman port owntransit-relay-exchange 9087/tcp)
test "$published_port" = 127.0.0.1:9087 || fail "live exchange container is not published on exact host IPv4 loopback"
network_mode=$(podman inspect --format '{{.HostConfig.NetworkMode}}' owntransit-relay-exchange)
test "$network_mode" = bridge || fail "live exchange container is not on the explicit Podman bridge"
mount_count=$(podman inspect --format '{{len .Mounts}}' owntransit-relay-exchange)
test "$mount_count" = 0 || fail "temporary exchange container has an unexpected mount"
running_image=$(podman inspect --format '{{.Image}}' owntransit-relay-exchange)
valid_digest "${running_image#sha256:}" || fail "live exchange container has a noncanonical image ID"
test "${running_image#sha256:}" = "${relay_image#sha256:}" || fail "temporary exchange container runs another image"

attempt=0
while test "$attempt" -lt 10; do
  if curl --noproxy '*' --silent --output /dev/null --connect-timeout 1 --max-time 2 http://127.0.0.1:9087/connects/enrollment; then
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done
test "$attempt" -lt 10 || fail "loopback-published exchange did not accept HTTP"
set +e
curl --noproxy '*' --silent --show-error --output /dev/null --connect-timeout 2 --max-time 3 "http://$non_loopback_ip:9087/connects/enrollment" >/dev/null 2>&1
non_loopback_result=$?
set -e
test "$non_loopback_result" -eq 7 || fail "host non-loopback port 9087 was not refused"

authority=$workspace/authority
recipient_record=$workspace/recipient.json
invitation_root=$workspace/invitation
"$provisioner" init-authority --out "$authority" > "$workspace/authority-summary.json"
printf '%s\n' '{"schema":"owntransit.recipient-record.v1","intended_recipient":"Disposable relay exchange qualification","identity_contact_reference":"Disposable host operator record"}' > "$recipient_record"
chmod 0600 "$recipient_record"
"$provisioner" issue-invitation \
  --authority "$authority" \
  --role relay \
  --release-id "$release_id" \
  --release-sequence "$release_sequence" \
  --artifact-sha256 "$relay_artifact_digest" \
  --os linux \
  --arch "$qualification_arch" \
  --exchange-endpoint "$exchange_endpoint" \
  --recipient-record "$recipient_record" \
  --out "$invitation_root" > "$workspace/invitation-summary.json"
registration=$invitation_root/courier-registration.otreg
require_root_regular_protected "$registration" throwaway-courier-registration
"$client" courier-register --registration "$registration" --credential-store "$credential_store" >/dev/null

response_a=$workspace/opaque-response-a.otb
response_b=$workspace/opaque-response-b.otb
printf '%s\n' 'OwnTransit disposable qualification opaque response A' > "$response_a"
printf '%s\n' 'OwnTransit disposable qualification opaque response B' > "$response_b"
chmod 0600 "$response_a" "$response_b"
"$client" courier-upload-response --registration "$registration" --response "$response_a" >/dev/null
"$client" courier-upload-response --registration "$registration" --response "$response_a" >/dev/null
if "$client" courier-upload-response --registration "$registration" --response "$response_b" >/dev/null 2>&1; then
  fail "mailbox accepted a conflicting second opaque response"
fi

systemctl stop "$exchange_unit"
if systemctl is-active --quiet "$exchange_unit"; then
  fail "exact exchange instance remained active after stop"
fi
if podman container exists owntransit-relay-exchange; then
  fail "exchange container remained after exact instance stop"
fi
loaded_exchange_units=$(systemctl list-units --all --plain --no-legend --no-pager 'owntransit-relay-exchange@*.service' | awk '{print $1}')
for loaded_exchange_unit in $loaded_exchange_units; do
  test "$loaded_exchange_unit" = "$exchange_unit" || fail "another exchange instance appeared during qualification"
done

"$uninstaller" --role relay --release-id "$release_id" >/dev/null
if test -e "$installed_unit" || test -L "$installed_unit"; then
  fail "relay uninstaller retained the exchange template"
fi
if test -e /etc/systemd/system/owntransit-relay.service || test -L /etc/systemd/system/owntransit-relay.service; then
  fail "relay uninstaller retained the enrolled relay unit"
fi
if test -e "$relay_environment" || test -L "$relay_environment"; then
  fail "relay uninstaller retained the relay environment"
fi
if test ! -L "$current_link" || test "$(readlink "$current_link")" != "releases/$release_id"; then
  fail "relay uninstaller changed the authenticated package selector"
fi
require_root_regular_protected "$installed_archive" preserved-relay-archive
test "$(sha256_file "$installed_archive")" = "$relay_artifact_digest" || fail "relay uninstaller changed the preserved image archive"
test "$(sha256_file "$installed_receipt")" = "$receipt_sha256" || fail "relay uninstaller changed the authenticated package receipt"
test "$(sha256_file "$installed_selector")" = "$selector_sha256" || fail "relay uninstaller changed the authenticated package selector record"
test "$(sha256_file "$installed_anchor")" = "$anchor_sha256" || fail "relay uninstaller changed the external package anchor"
test -z "$(find "$relay_state_root" -mindepth 1 -print -quit)" || fail "temporary exchange or uninstall created endpoint state or authority material"
podman image exists "$relay_image" || fail "relay uninstaller removed the preserved relay image"
if podman container exists owntransit-relay-exchange; then
  fail "relay uninstaller left the exchange container present"
fi
active_exchange_units=$(systemctl list-units --state=active --plain --no-legend --no-pager 'owntransit-relay-exchange@*.service' | awk '{print $1}')
test -z "$active_exchange_units" || fail "an exchange instance remained active after uninstall"

verified_unix=$(date +%s)
evidence_stage=$workspace/evidence.json
printf '{"schema":"owntransit.qualify.linux-%s-relay-exchange.v1","result":"pass","platform":"linux","architecture":"%s","release_id":"%s","native_checksums_sha256":"%s","manifest_sha256":"%s","policy_sha256":"%s","package_receipt_sha256":"%s","package_selector_sha256":"%s","package_anchor_sha256":"%s","relay_artifact_sha256":"%s","client_artifact_sha256":"%s","exchange_unit_sha256":"%s","verified_unix":%s,"manager_bound_signed_release":true,"idempotent_package_apply":true,"one_time_marker_consumed":true,"pristine_relay_state":true,"rootful_podman":true,"oci_architecture_verified":true,"explicit_bridge":true,"zero_container_mounts":true,"podman_port":"127.0.0.1:9087","enrolled_relay_conflict":true,"host_non_loopback_refused":true,"public_wss_mailbox_created":true,"opaque_response_written":true,"idempotent_response_retry":true,"conflicting_response_rejected":true,"target_response_read_qualified":false,"target_response_read_limitation":"no public courier read-response command","template_removed":true,"exchange_container_absent":true,"authenticated_selector_preserved":true,"package_anchor_preserved":true,"relay_image_preserved":true,"qualification_credentials":"throwaway-local","endpoint_recorded":false,"network_required":true}\n' \
  "$qualification_arch" "$qualification_arch" "$release_id" "$checksums_sha256" "$manifest_sha256" "$policy_sha256" "$receipt_sha256" "$selector_sha256" "$anchor_sha256" "$relay_artifact_digest" "$client_artifact_digest" "$exchange_unit_digest" "$verified_unix" > "$evidence_stage"
chmod 0644 "$evidence_stage"
install -o root -g root -m 0644 "$evidence_stage" "$evidence_path"
cat "$evidence_path"
