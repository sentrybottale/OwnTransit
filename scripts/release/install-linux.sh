#!/bin/sh
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() {
  printf 'install-linux: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: install-linux.sh \
  --bundle ABSOLUTE_STAGING_DIRECTORY \
  --role client|connector|relay|provisioner \
  --release-id 52_CHAR_BASE32_ID \
  --checksums-sha256 64_HEX \
  --artifact-sha256 64_HEX \
  [--lifecycle-sha256 64_HEX] \
  [--manifest-signature ABSOLUTE_FILE] \
  [--release-public-key ABSOLUTE_FILE] \
  [--policy ABSOLUTE_FILE] \
  [--policy-signature ABSOLUTE_FILE] \
  [--policy-public-key ABSOLUTE_FILE] \
  [--client-user EXISTING_NON_ROOT_USER]

The checksum-file digest and selected artifact digests must come from an
independently authenticated release/package. The client role requires one exact
existing --client-user. This installer never downloads, enrolls, imports trust,
creates endpoint credentials, edits SSH, enables a service, or starts a service.
For client, connector, and relay, the signed manifest and signed monotonic
policy inputs are mandatory. The authenticated candidate owntransitctl performs
the per-role package transaction; exact reinstall resumes/idempotently verifies
the same selector. Roles coexist under separate current selectors. The script
does not bootstrap trust: verify this installer and every supplied public key
through the documented independent release channel before running it as root.
EOF
}

bundle=
role=
release_id=
checksums_sha256=
artifact_sha256=
lifecycle_sha256=
client_user=
manifest_signature=
release_public_key=
policy=
policy_signature=
policy_public_key=

while test "$#" -gt 0; do
  case "$1" in
    --bundle|--role|--release-id|--checksums-sha256|--artifact-sha256|--lifecycle-sha256|--client-user|--manifest-signature|--release-public-key|--policy|--policy-signature|--policy-public-key)
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
        --lifecycle-sha256) lifecycle_sha256=$value ;;
        --client-user) client_user=$value ;;
        --manifest-signature) manifest_signature=$value ;;
        --release-public-key) release_public_key=$value ;;
        --policy) policy=$value ;;
        --policy-signature) policy_signature=$value ;;
        --policy-public-key) policy_public_key=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$(uname -s)" = Linux || fail "this installer supports Linux only"
case "$(uname -m)" in
  x86_64|amd64) ;;
  *) fail "this installer supports amd64 only" ;;
esac
test "$(id -u)" -eq 0 || fail "installation requires root"

valid_digest() {
  digest_value=$1
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest_value}" -eq 64
}

case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
valid_digest "$checksums_sha256" || fail "--checksums-sha256 is invalid"
valid_digest "$artifact_sha256" || fail "--artifact-sha256 is invalid"

case "$role" in
  client)
    artifact_name=owntransit-linux-amd64
    installed_name=owntransit
    needs_lifecycle=yes
    service_name=
    reader_group=owntransit-client
    ;;
  connector)
    artifact_name=owntransit-connector-linux-amd64
    installed_name=owntransit-connector
    needs_lifecycle=yes
    service_name=owntransit-connector
    reader_group=owntransit-connector
    ;;
  relay)
    artifact_name=owntransit-relay-linux-amd64.oci.tar
    installed_name=
    needs_lifecycle=yes
    service_name=owntransit-relay
    reader_group=owntransit-relay
    ;;
  provisioner)
    artifact_name=owntransit-provision-linux-amd64
    installed_name=owntransit-provision
    needs_lifecycle=no
    service_name=
    reader_group=
    ;;
  *)
    fail "role must be client, connector, relay, or provisioner"
    ;;
esac

if test "$role" = client; then
  case "$client_user" in
    ''|-*|*[!A-Za-z0-9_-]*) fail "--client-user must name one existing account using only letters, digits, underscore, or hyphen" ;;
  esac
  test "${#client_user}" -le 32 || fail "--client-user is too long"
else
  test -z "$client_user" || fail "--client-user is valid only for the client role"
fi

if test "$needs_lifecycle" = yes; then
  valid_digest "$lifecycle_sha256" || fail "--lifecycle-sha256 is required and must be canonical"
  for signed_input in "$manifest_signature" "$release_public_key" "$policy" "$policy_signature" "$policy_public_key"; do
    case "$signed_input" in
      /*) ;;
      *) fail "runtime roles require every signed release/policy input as an absolute path" ;;
    esac
  done
elif test -n "$lifecycle_sha256"; then
  fail "--lifecycle-sha256 is invalid for the provisioner role"
elif test -n "$manifest_signature$release_public_key$policy$policy_signature$policy_public_key"; then
  fail "signed lifecycle inputs are valid only for client, connector, and relay"
fi

case "$bundle" in
  /*) ;;
  *) fail "bundle path must be absolute" ;;
esac
test -d "$bundle" && test ! -L "$bundle" || fail "bundle must be a regular directory, not a symlink"
bundle_resolved=$(CDPATH= cd -P -- "$bundle" && pwd) || fail "cannot resolve bundle"
test "$bundle_resolved" = "$bundle" || fail "bundle path must be canonical and contain no symlinked component"

for command_name in awk basename cat chmod chown cmp dirname env find grep id install ln mktemp mv readlink rm rmdir sha256sum stat tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command is unavailable: $command_name"
done
if test "$needs_lifecycle" = yes; then
  for command_name in getent groupadd usermod; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required identity command is unavailable: $command_name"
  done
fi
if test -n "$service_name"; then
  for command_name in systemctl useradd; do
    command -v "$command_name" >/dev/null 2>&1 || fail "required service command is unavailable: $command_name"
  done
fi

require_root_owned_protected() {
  protected_path=$1
  test "$(stat -c %u "$protected_path")" -eq 0 || fail "bundle path is not root-owned: $protected_path"
  protected_mode=$(stat -c %a "$protected_path")
  case "$protected_mode" in
    [0-7][0-7][0-7]) ;;
    *) fail "bundle path has special or non-canonical mode bits: $protected_path" ;;
  esac
  protected_permissions=$((0$protected_mode))
  test $((protected_permissions & 022)) -eq 0 || fail "bundle path is group/world writable: $protected_path"
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
  test "$(stat -c %h "$regular_path")" -eq 1 || fail "bundle member has multiple hard links: $regular_path"
  require_root_owned_protected "$regular_path"
}

sha256_file() {
  sha256sum "$1" | awk '{print $1}'
}

checksums="$bundle/SHA256SUMS"
require_root_owned_regular "$checksums"
test "$(sha256_file "$checksums")" = "$checksums_sha256" || fail "SHA256SUMS does not match its independently supplied digest"

verification_directory=$(mktemp -d /var/tmp/owntransit-install.XXXXXX) || fail "cannot create checksum workspace"
test "$(stat -c %u "$verification_directory")" -eq 0 && test "$(stat -c %a "$verification_directory")" = 700 || fail "checksum workspace is not private and root-owned"
seen_paths="$verification_directory/seen-paths"
cleanup_seen() {
  rm -rf -- "$verification_directory"
}
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

bundled_installer="$bundle/packaging/scripts/install-linux.sh"
test "$(listed_digest packaging/scripts/install-linux.sh)" = "$(sha256_file "$bundled_installer")" || fail "Linux installer is not authenticated by SHA256SUMS"
case "$0" in
  /*) ;;
  *) fail "installer must be invoked by its absolute protected bundle path" ;;
esac
test ! -L "$0" || fail "installer entry point must not be a symlink"
test "$0" = "$bundled_installer" || fail "installer must run directly from the selected protected bundle"
require_root_owned_regular "$bundled_installer"
cmp -s "$0" "$bundled_installer" || fail "running installer is not the checksummed bundle copy"

test "$(listed_digest BUILD-INPUTS)" = "$(sha256_file "$bundle/BUILD-INPUTS")" || fail "BUILD-INPUTS is not authenticated by SHA256SUMS"
build_release_id=$(awk -F= '$1 == "release_id" { print $2 }' "$bundle/BUILD-INPUTS")
test "$build_release_id" = "$release_id" || fail "bundle release ID does not match --release-id"
project_license_path=LICENSE
third_party_licenses_path=evidence/THIRD_PARTY_LICENSES.txt
test "$(listed_digest "$project_license_path")" = "$(sha256_file "$bundle/$project_license_path")" || fail "project license is not authenticated by SHA256SUMS"
test "$(listed_digest "$third_party_licenses_path")" = "$(sha256_file "$bundle/$third_party_licenses_path")" || fail "third-party licenses are not authenticated by SHA256SUMS"

if test "$needs_lifecycle" = yes; then
  manifest_path="$bundle/RELEASE-MANIFEST.json"
  test "$(listed_digest RELEASE-MANIFEST.json)" = "$(sha256_file "$manifest_path")" || fail "release manifest is not authenticated by SHA256SUMS"
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

artifact_path="artifacts/$artifact_name"
test "$(listed_digest "$artifact_path")" = "$artifact_sha256" || fail "selected artifact digest does not match the authenticated release"
if test "$needs_lifecycle" = yes; then
  lifecycle_path=artifacts/owntransitctl-linux-amd64
  test "$(listed_digest "$lifecycle_path")" = "$lifecycle_sha256" || fail "lifecycle artifact digest does not match the authenticated release"
fi
if test "$role" = connector; then
  unit_bundle_path=packaging/systemd/owntransit-connector.service
  test "$(listed_digest "$unit_bundle_path")" = "$(sha256_file "$bundle/$unit_bundle_path")" || fail "connector unit is not authenticated by SHA256SUMS"
elif test "$role" = relay; then
  unit_bundle_path=packaging/systemd/owntransit-relay.service
  test "$(listed_digest "$unit_bundle_path")" = "$(sha256_file "$bundle/$unit_bundle_path")" || fail "relay unit is not authenticated by SHA256SUMS"
fi

ensure_root_directory() {
  directory=$1
  permissions=$2
  if test -e "$directory" || test -L "$directory"; then
    test -d "$directory" && test ! -L "$directory" || fail "$directory is not a regular directory"
    test "$(stat -c %u "$directory")" -eq 0 && test "$(stat -c %g "$directory")" -eq 0 || fail "$directory is not root-owned"
    test "$(stat -c %a "$directory")" = "$permissions" || fail "$directory mode is not $permissions"
  else
    install -d -o root -g root -m "$permissions" "$directory"
  fi
}

require_local_account_database() {
  account_file=$1
  test -f "$account_file" && test ! -L "$account_file" || fail "$account_file is not a local regular account database"
  test "$(stat -c %u "$account_file")" -eq 0 && test "$(stat -c %h "$account_file")" -eq 1 || fail "$account_file is not an exact root-owned account database"
  account_mode=$(stat -c %a "$account_file")
  test $((0$account_mode & 022)) -eq 0 || fail "$account_file is group/world writable"
}

install_root=/usr/libexec/owntransit
roles_root="$install_root/roles"
public_bin=/usr/local/bin

ensure_root_directory /usr/local 755
ensure_root_directory "$public_bin" 755
ensure_root_directory /usr/libexec 755
ensure_root_directory "$install_root" 755
ensure_root_directory "$roles_root" 755

if test "$needs_lifecycle" = yes; then
  ensure_root_directory /var/lib/owntransit 755
  ensure_root_directory /var/lib/owntransit/package-rollback 700
  ensure_root_directory /var/lib/owntransit/package-supervisor 700
  workspace="/var/lib/owntransit/$role"
  ensure_root_directory "$workspace" 755
fi
if test "$role" = client; then
  client_passwd=$(getent passwd "$client_user") || fail "--client-user does not identify an existing account"
  test "$(printf '%s\n' "$client_passwd" | wc -l | tr -d '[:space:]')" -eq 1 || fail "--client-user does not resolve uniquely"
  test "$(printf '%s\n' "$client_passwd" | awk -F: '{print $1}')" = "$client_user" || fail "--client-user resolved to a different account name"
  client_uid=$(printf '%s\n' "$client_passwd" | awk -F: '{print $3}')
  client_primary_gid=$(printf '%s\n' "$client_passwd" | awk -F: '{print $4}')
  case "$client_uid:$client_primary_gid" in *[!0-9:]*) fail "--client-user has a non-numeric UID or primary GID" ;; esac
  test "$client_uid" -gt 0 || fail "--client-user must be non-root"
  test "$client_primary_gid" -gt 0 || fail "--client-user must not retain the root primary group"
  client_primary_group_record=$(getent group "$client_primary_gid") || fail "--client-user primary group is unavailable"
  test "$(printf '%s\n' "$client_primary_group_record" | wc -l | tr -d '[:space:]')" -eq 1 || fail "--client-user primary group is ambiguous"
  client_primary_group=$(printf '%s\n' "$client_primary_group_record" | awk -F: '{print $1}')
  case "$client_primary_group" in ''|-*|*[!A-Za-z0-9_-]*) fail "--client-user primary group name is unsafe" ;; esac
  test "$(printf '%s\n' "$client_primary_group_record" | awk -F: '{print $3}')" = "$client_primary_gid" || fail "--client-user primary group is cross-wired"
fi
if test -n "$service_name"; then
  unit_path="/etc/systemd/system/$service_name.service"
  ensure_root_directory /etc/owntransit 755
  if test "$role" = connector; then
    runtime_env_path=/etc/owntransit/connector-runtime.env
  else
    runtime_env_path=/etc/owntransit/relay-container.env
  fi
fi
if test "$role" = relay; then
  command -v podman >/dev/null 2>&1 || fail "relay installation requires Podman"
  test "$(command -v podman)" = /usr/bin/podman || fail "relay unit requires Podman at /usr/bin/podman"
fi

ensure_exact_regular() {
  exact_target=$1
  exact_source=$2
  exact_mode=$3
  if test -e "$exact_target" || test -L "$exact_target"; then
    test -f "$exact_target" && test ! -L "$exact_target" || fail "installed file is not regular: $exact_target"
    test "$(stat -c %u "$exact_target")" -eq 0 && test "$(stat -c %g "$exact_target")" -eq 0 || fail "installed file is not root-owned: $exact_target"
    test "$(stat -c %a "$exact_target")" = "$exact_mode" || fail "installed file has the wrong mode: $exact_target"
    test "$(stat -c %h "$exact_target")" -eq 1 || fail "installed file has multiple hard links: $exact_target"
    cmp -s "$exact_source" "$exact_target" || fail "installed file differs from the authenticated bundle: $exact_target"
  else
    install -o root -g root -m "$exact_mode" "$exact_source" "$exact_target"
  fi
}

ensure_exact_symlink() {
  exact_link=$1
  exact_target=$2
  if test -e "$exact_link" || test -L "$exact_link"; then
    test -L "$exact_link" || fail "launcher exists and is not a symlink: $exact_link"
    test "$(readlink "$exact_link")" = "$exact_target" || fail "launcher selects an unexpected target: $exact_link"
    return
  fi
  exact_stage="${exact_link}.$$.new"
  test ! -e "$exact_stage" && test ! -L "$exact_stage" || fail "launcher stage already exists: $exact_stage"
  ln -s "$exact_target" "$exact_stage"
  mv -- "$exact_stage" "$exact_link"
}

if test "$needs_lifecycle" = no; then
  provisioner_path="$public_bin/owntransit-provision"
  ensure_exact_regular "$provisioner_path" "$bundle/$artifact_path" 755
  trap - EXIT HUP INT TERM
  rm -rf -- "$verification_directory"
  printf 'installed exact OwnTransit provisioner %s at %s\n' "$release_id" "$provisioner_path"
  exit 0
fi

if ! getent group "$reader_group" >/dev/null 2>&1; then
  groupadd --system "$reader_group"
fi
reader_record=$(getent group "$reader_group") || fail "cannot resolve dedicated runtime reader group"
test "$(printf '%s\n' "$reader_record" | wc -l | tr -d '[:space:]')" -eq 1 || fail "runtime reader group is ambiguous"
test "$(printf '%s\n' "$reader_record" | awk -F: '{print $1}')" = "$reader_group" || fail "runtime reader group resolved to another name"
reader_gid=$(printf '%s\n' "$reader_record" | awk -F: '{print $3}')
case "$reader_gid" in ''|*[!0-9]*) fail "runtime reader group has a non-numeric GID" ;; esac
test "$reader_gid" -gt 0 || fail "runtime reader group must be non-root"

if test "$role" = client; then
  group_members=$(printf '%s\n' "$reader_record" | awk -F: '{print $4}')
  if test -z "$group_members"; then
    usermod --append --groups "$reader_group" "$client_user"
    group_members=$(getent group "$reader_group" | awk -F: '{print $4}')
  fi
  test "$group_members" = "$client_user" || fail "dedicated client reader group must contain exactly --client-user"
  require_local_account_database /etc/passwd
  require_local_account_database /etc/group
  awk -F: -v name="$client_user" -v uid="$client_uid" -v gid="$client_primary_gid" '
    $1 == name { names++; if ($3 == uid && $4 == gid) exact++ }
    $3 == uid { uids++; if ($1 == name) owned++ }
    END { exit names == 1 && exact == 1 && uids == 1 && owned == 1 ? 0 : 1 }
  ' /etc/passwd || fail "--client-user must be one exact local /etc/passwd identity"
  awk -F: -v primary="$client_primary_group" -v pgid="$client_primary_gid" -v reader="$reader_group" -v rgid="$reader_gid" -v user="$client_user" '
    $1 == primary && $3 == pgid { primary_exact++ }
    $3 == pgid { primary_gids++; if ($1 == primary) primary_owned++ }
    $1 == reader && $3 == rgid && $4 == user { reader_exact++ }
    $3 == rgid { reader_gids++; if ($1 == reader) reader_owned++ }
    END { exit primary_exact == 1 && primary_gids == 1 && primary_owned == 1 && reader_exact == 1 && reader_gids == 1 && reader_owned == 1 ? 0 : 1 }
  ' /etc/group || fail "client primary/reader groups must be exact local /etc/group identities"

  client_identity_root=/var/lib/owntransit/client/identity
  client_identity_receipt="$client_identity_root/client-reader.v1"
  ensure_root_directory "$client_identity_root" 700
  expected_client_identity=$(printf '%s\n' \
    'schema=owntransit.linux-client-reader.v1' \
    "client_user=$client_user" \
    "client_uid=$client_uid" \
    "primary_group=$client_primary_group" \
    "primary_gid=$client_primary_gid" \
    'reader_group=owntransit-client' \
    "reader_gid=$reader_gid")
  if test -e "$client_identity_receipt" || test -L "$client_identity_receipt"; then
    test -f "$client_identity_receipt" && test ! -L "$client_identity_receipt" || fail "protected client identity receipt is not regular"
    test "$(stat -c %u "$client_identity_receipt")" -eq 0 && test "$(stat -c %g "$client_identity_receipt")" -eq 0 || fail "protected client identity receipt is not root-owned"
    test "$(stat -c %a "$client_identity_receipt")" = 600 && test "$(stat -c %h "$client_identity_receipt")" -eq 1 || fail "protected client identity receipt metadata is invalid"
    test "$(cat "$client_identity_receipt")" = "$expected_client_identity" || fail "protected client identity receipt identifies another account"
  else
    client_identity_stage=$(mktemp "$client_identity_root/.client-reader.v1.XXXXXX") || fail "cannot stage protected client identity receipt"
    printf '%s\n' "$expected_client_identity" > "$client_identity_stage"
    chown root:root "$client_identity_stage"
    chmod 0600 "$client_identity_stage"
    mv -- "$client_identity_stage" "$client_identity_receipt"
  fi
else
  if ! getent passwd "$service_name" >/dev/null 2>&1; then
    useradd --system --gid "$reader_group" --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home "$service_name"
  fi
  service_record=$(getent passwd "$service_name") || fail "cannot resolve service identity"
  test "$(printf '%s\n' "$service_record" | wc -l | tr -d '[:space:]')" -eq 1 || fail "service identity is ambiguous"
  service_uid=$(printf '%s\n' "$service_record" | awk -F: '{print $3}')
  service_gid=$(printf '%s\n' "$service_record" | awk -F: '{print $4}')
  service_home=$(printf '%s\n' "$service_record" | awk -F: '{print $6}')
  service_shell=$(printf '%s\n' "$service_record" | awk -F: '{print $7}')
  case "$service_uid:$service_gid" in *[!0-9:]*) fail "service identity has a non-numeric UID or GID" ;; esac
  test "$service_uid" -gt 0 && test "$service_gid" -eq "$reader_gid" || fail "service identity does not use the dedicated non-root reader GID as primary"
  test "$service_home" = /nonexistent && test "$service_shell" = /usr/sbin/nologin || fail "service identity has an unexpected home or shell"
  usermod --lock "$service_name"
  test "$(id -G "$service_name")" = "$reader_gid" || fail "service identity has an unexpected supplementary group"
fi

if test "$role" = connector; then
  connector_environment="OWNTRANSIT_CONNECTOR_READER_GID=$reader_gid"
  if test -e "$runtime_env_path" || test -L "$runtime_env_path"; then
    test -f "$runtime_env_path" && test ! -L "$runtime_env_path" || fail "connector environment is not a regular file"
    test "$(cat "$runtime_env_path")" = "$connector_environment" || fail "connector environment differs from the dedicated reader group"
  else
    printf '%s\n' "$connector_environment" > "$runtime_env_path"
  fi
  chown root:root "$runtime_env_path"
  chmod 0600 "$runtime_env_path"
fi

if test -n "$service_name"; then
  if test -e "$unit_path" || test -L "$unit_path"; then
    test -f "$unit_path" && test ! -L "$unit_path" || fail "systemd unit is not a regular file"
    test "$(stat -c %u "$unit_path")" -eq 0 && test "$(stat -c %g "$unit_path")" -eq 0 && test "$(stat -c %a "$unit_path")" = 644 || fail "systemd unit metadata is invalid"
    cmp -s "$bundle/$unit_bundle_path" "$unit_path" || fail "installed systemd unit differs from the authenticated v1 unit"
  else
    install -o root -g root -m 0644 "$bundle/$unit_bundle_path" "$unit_path"
  fi
  systemctl daemon-reload
fi

lifecycle_candidate="$bundle/$lifecycle_path"
lifecycle_runner=$lifecycle_candidate
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
  test "$(stat -c %u "$lifecycle_runner")" -eq 0 && test "$(stat -c %g "$lifecycle_runner")" -eq 0 || fail "selected lifecycle executable is not root-owned"
  test "$(stat -c %a "$lifecycle_runner")" = 700 && test "$(stat -c %h "$lifecycle_runner")" -eq 1 || fail "selected lifecycle executable metadata is invalid"
fi
env -i \
  HOME=/root \
  LANG=C \
  LC_ALL=C \
  PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  "$lifecycle_runner" package-apply \
    --role "$role" \
    --bundle "$bundle" \
    --manifest "$manifest_path" \
    --manifest-signature "$manifest_signature" \
    --release-public-key "$release_public_key" \
    --policy "$policy" \
    --policy-signature "$policy_signature" \
    --policy-public-key "$policy_public_key"

test -L "$current_link" || fail "package transaction did not publish the role current selector"
test "$(readlink "$current_link")" = "releases/$release_id" || fail "package transaction selected another release"

if test "$role" = client; then
  ensure_exact_symlink "$public_bin/owntransit" "$current_link/owntransit"
  ensure_exact_symlink "$public_bin/owntransit-proxy" "$current_link/owntransit-proxy"
elif test "$role" = relay; then
  test -f "$runtime_env_path" && test ! -L "$runtime_env_path" || fail "relay activation did not publish its protected image environment"
  test "$(stat -c %u "$runtime_env_path")" -eq 0 && test "$(stat -c %g "$runtime_env_path")" -eq 0 && test "$(stat -c %a "$runtime_env_path")" = 600 || fail "relay image environment metadata is invalid"
fi

trap - EXIT HUP INT TERM
rm -rf -- "$verification_directory"

printf 'installed OwnTransit role %s release %s under selector %s\n' "$role" "$release_id" "$current_link"
printf 'installed license evidence: %s/LICENSE and %s/THIRD_PARTY_LICENSES.txt\n' "$current_link" "$current_link"
printf 'dedicated numeric runtime reader GID: %s\n' "$reader_gid"
if test -n "$service_name"; then
  printf 'service enablement remains an explicit operator action: %s.service\n' "$service_name"
else
  printf 'native client: %s; SSH proxy: %s\n' "$public_bin/owntransit" "$public_bin/owntransit-proxy"
  printf '%s\n' 'start a new login session before use; existing sessions do not acquire the dedicated group'
fi
