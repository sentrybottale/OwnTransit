#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd) || {
  printf '%s\n' 'sign-candidate: cannot resolve project root' >&2
  exit 1
}

fail() {
  printf 'sign-candidate: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: sign-candidate.sh \
  --bundle ABSOLUTE_PROTECTED_UNSIGNED_BUNDLE \
  --candidate ABSOLUTE_CANDIDATE_LEDGER \
  --releasectl ABSOLUTE_EXECUTABLE \
  --release-private-key ABSOLUTE_ED25519_PKCS8_PEM \
  --release-public-key ABSOLUTE_ED25519_PUBLIC_PEM \
  --policy-private-key ABSOLUTE_ED25519_PKCS8_PEM \
  --policy-public-key ABSOLUTE_ED25519_PUBLIC_PEM \
  --distribution-key ABSOLUTE_ED25519_OPENSSH_PRIVATE_KEY \
  --distribution-public-key ABSOLUTE_ED25519_OPENSSH_PUBLIC_KEY \
  --allowed-signers ABSOLUTE_FILE \
  --source-root ABSOLUTE_CLEAN_GIT_ROOT \
  --version VERSION \
  --source-commit 40_OR_64_LOWERCASE_HEX \
  --policy-sequence POSITIVE_INTEGER \
  --release-floor POSITIVE_INTEGER \
  --lifecycle-floor POSITIVE_INTEGER \
  [--anchor-policy-sequence NONNEGATIVE_INTEGER] \
  [--anchor-release-floor NONNEGATIVE_INTEGER] \
  [--anchor-lifecycle-floor NONNEGATIVE_INTEGER] \
  [--anchor-policy-key-id KEY_ID] \
  [--anchor-tombstones none] \
  --output ABSOLUTE_NEW_DIRECTORY

Creates one offline, atomically published candidate handoff. The fixed output
contains trust/ plus downloadable assets: deterministic native/source archives,
detached release/policy/native-checksum signatures, an outer signed checksum
inventory, and a rendered Homebrew formula. It never generates a key, downloads,
publishes, installs, tags, or changes the input bundle.

Without anchor flags, this helper verifies a sequence-1 policy against the
empty anchor. A later policy must supply all three exact values from the
independently persisted previous anchor; the candidate policy is then proved
to advance that anchor without weakening either floor. This scalar transition
supports only an anchor whose tombstone list is empty and requires the pinned
policy-key ID explicitly; a tombstoned anchor needs a future canonical
anchor-file ceremony and is rejected by this helper.
EOF
}

bundle=
candidate_ledger=
releasectl=
release_private_key=
release_public_key=
policy_private_key=
policy_public_key=
distribution_key=
distribution_public_key=
allowed_signers=
source_root=
version=
source_commit=
policy_sequence=
release_floor=
lifecycle_floor=
anchor_policy_sequence=0
anchor_release_floor=0
anchor_lifecycle_floor=0
anchor_policy_key_id=
anchor_tombstones=
output=

while test "$#" -gt 0; do
  case "$1" in
    --bundle|--candidate|--releasectl|--release-private-key|--release-public-key|--policy-private-key|--policy-public-key|--distribution-key|--distribution-public-key|--allowed-signers|--source-root|--version|--source-commit|--policy-sequence|--release-floor|--lifecycle-floor|--anchor-policy-sequence|--anchor-release-floor|--anchor-lifecycle-floor|--anchor-policy-key-id|--anchor-tombstones|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --bundle) bundle=$value ;;
        --candidate) candidate_ledger=$value ;;
        --releasectl) releasectl=$value ;;
        --release-private-key) release_private_key=$value ;;
        --release-public-key) release_public_key=$value ;;
        --policy-private-key) policy_private_key=$value ;;
        --policy-public-key) policy_public_key=$value ;;
        --distribution-key) distribution_key=$value ;;
        --distribution-public-key) distribution_public_key=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --source-root) source_root=$value ;;
        --version) version=$value ;;
        --source-commit) source_commit=$value ;;
        --policy-sequence) policy_sequence=$value ;;
        --release-floor) release_floor=$value ;;
        --lifecycle-floor) lifecycle_floor=$value ;;
        --anchor-policy-sequence) anchor_policy_sequence=$value ;;
        --anchor-release-floor) anchor_release_floor=$value ;;
        --anchor-lifecycle-floor) anchor_lifecycle_floor=$value ;;
        --anchor-policy-key-id) anchor_policy_key_id=$value ;;
        --anchor-tombstones) anchor_tombstones=$value ;;
        --output) output=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

for required_value in \
  "$bundle" "$candidate_ledger" "$releasectl" "$release_private_key" "$release_public_key" \
  "$policy_private_key" "$policy_public_key" "$distribution_key" \
  "$distribution_public_key" "$allowed_signers" "$source_root" "$version" \
  "$source_commit" "$policy_sequence" "$release_floor" "$lifecycle_floor" "$output"; do
  test -n "$required_value" || fail "all documented arguments are required"
done

canonical_directory() {
  input=$1
  label=$2
  case "$input" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -d "$input" && test ! -L "$input" || fail "$label must be an existing non-symlink directory"
  resolved=$(CDPATH= cd -P -- "$input" && pwd) || fail "cannot resolve $label"
  test "$resolved" = "$input" || fail "$label path must be canonical and contain no symlink"
}

canonical_file() {
  input=$1
  label=$2
  case "$input" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -f "$input" && test ! -L "$input" || fail "$label must be an existing regular non-symlink file"
  resolved_parent=$(CDPATH= cd -P -- "$(dirname "$input")" && pwd) || fail "cannot resolve $label parent"
  resolved="$resolved_parent/$(basename "$input")"
  test "$resolved_parent" != / || resolved="/$(basename "$input")"
  test "$resolved" = "$input" || fail "$label path must be canonical and contain no symlinked parent"
}

path_is_equal_or_within() {
  candidate=$1
  root=$2
  test "$candidate" = "$root" && return 0
  test "$root" = / && return 0
  case "$candidate" in "$root"/*) return 0 ;; esac
  return 1
}

canonical_positive_decimal() {
  decimal=$1
  case "$decimal" in ''|*[!0-9]*|0|0*) return 1 ;; esac
  test "${#decimal}" -le 20
}

canonical_nonnegative_decimal() {
  decimal=$1
  case "$decimal" in
    0) return 0 ;;
    ''|*[!0-9]*|0*) return 1 ;;
  esac
  test "${#decimal}" -le 20
}

decimal_is_at_most() {
  left=$1
  right=$2
  test "${#left}" -lt "${#right}" && return 0
  test "${#left}" -gt "${#right}" && return 1
  test "$left" = "$right" && return 0
  test "$left" \< "$right"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

file_metadata() {
  if test "$(uname -s)" = Darwin; then
    stat -f '%HT|%l|%Lp' -- "$1"
  else
    stat -c '%F|%h|%a' -- "$1"
  fi
}

directory_metadata() {
  if test "$(uname -s)" = Darwin; then
    stat -f '%HT|%u|%Lp' -- "$1"
  else
    stat -c '%F|%u|%a' -- "$1"
  fi
}

canonical_directory "$bundle" bundle
canonical_directory "$source_root" source-root
canonical_file "$candidate_ledger" candidate-ledger
canonical_file "$releasectl" releasectl
canonical_file "$release_private_key" release-private-key
canonical_file "$release_public_key" release-public-key
canonical_file "$policy_private_key" policy-private-key
canonical_file "$policy_public_key" policy-public-key
canonical_file "$distribution_key" distribution-key
canonical_file "$distribution_public_key" distribution-public-key
canonical_file "$allowed_signers" allowed-signers
test -x "$releasectl" || fail "releasectl must be executable"

for signing_or_trust_input in \
  "$release_private_key" "$release_public_key" \
  "$policy_private_key" "$policy_public_key" \
  "$distribution_key" "$distribution_public_key" "$allowed_signers"; do
  path_is_equal_or_within "$signing_or_trust_input" "$bundle" &&
    fail "every signing/trust input must remain outside the unsigned bundle"
  path_is_equal_or_within "$signing_or_trust_input" "$source_root" &&
    fail "every signing/trust input must remain outside the source tree"
done

case "$version" in ''|*[!A-Za-z0-9._+-]*) fail "version contains an unsafe character" ;; esac
case "$version" in [A-Za-z0-9]*) ;; *) fail "version must begin with an alphanumeric character" ;; esac
test "${#version}" -le 128 || fail "version is too long"
case "$source_commit" in ''|*[!0-9a-f]*) fail "source commit must be lowercase hexadecimal" ;; esac
case "${#source_commit}" in 40|64) ;; *) fail "source commit must contain 40 or 64 hexadecimal characters" ;; esac
canonical_positive_decimal "$policy_sequence" || fail "policy sequence must be a canonical positive decimal integer"
canonical_positive_decimal "$release_floor" || fail "release floor must be a canonical positive decimal integer"
canonical_positive_decimal "$lifecycle_floor" || fail "lifecycle floor must be a canonical positive decimal integer"
canonical_nonnegative_decimal "$anchor_policy_sequence" || fail "anchor policy sequence must be a canonical nonnegative decimal integer"
canonical_nonnegative_decimal "$anchor_release_floor" || fail "anchor release floor must be a canonical nonnegative decimal integer"
canonical_nonnegative_decimal "$anchor_lifecycle_floor" || fail "anchor lifecycle floor must be a canonical nonnegative decimal integer"
if test "$anchor_policy_sequence" = 0; then
  test "$anchor_release_floor" = 0 && test "$anchor_lifecycle_floor" = 0 ||
    fail "an empty anchor requires all three anchor values to be zero"
  test -z "$anchor_policy_key_id" && test -z "$anchor_tombstones" ||
    fail "an empty anchor must not supply persisted key or tombstone claims"
  test "$policy_sequence" = 1 || fail "the empty-anchor first-release path requires policy sequence 1"
else
  canonical_positive_decimal "$anchor_release_floor" || fail "a persisted anchor requires a positive release floor"
  canonical_positive_decimal "$anchor_lifecycle_floor" || fail "a persisted anchor requires a positive lifecycle floor"
  decimal_is_at_most "$anchor_policy_sequence" "$policy_sequence" && test "$anchor_policy_sequence" != "$policy_sequence" ||
    fail "candidate policy sequence must advance the persisted anchor"
  decimal_is_at_most "$anchor_release_floor" "$release_floor" || fail "candidate policy weakens the persisted release floor"
  decimal_is_at_most "$anchor_lifecycle_floor" "$lifecycle_floor" || fail "candidate policy weakens the persisted lifecycle floor"
  test -n "$anchor_policy_key_id" || fail "a persisted anchor requires its pinned policy-key ID"
  test "$anchor_tombstones" = none || fail "this policy-advance helper requires an explicitly empty persisted tombstone list"
fi

case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test "$output" != / || fail "output cannot be the filesystem root"
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "output parent must be an existing directory"
output_base=$(basename "$output")
case "$output_base" in ''|.|..|*[!A-Za-z0-9._+-]*) fail "output basename contains an unsafe character" ;; esac
resolved_output="$output_parent/$output_base"
test "$output_parent" != / || resolved_output="/$output_base"
test "$resolved_output" = "$output" || fail "output path must be canonical and contain no symlinked parent"

parent_metadata=$(directory_metadata "$output_parent") || fail "cannot inspect output parent"
parent_kind=${parent_metadata%%|*}
parent_rest=${parent_metadata#*|}
parent_owner=${parent_rest%%|*}
parent_mode=${parent_rest#*|}
case "$parent_kind" in Directory|directory) ;; *) fail "output parent must be a directory" ;; esac
test "$parent_owner" -eq "$(id -u)" || fail "output parent must be owned by the effective user"
case "$parent_mode" in [0-7][0-7][0-7]|[0-7][0-7][0-7][0-7]) ;; *) fail "output parent mode is invalid" ;; esac
parent_permissions=$((0$parent_mode))
test $((parent_permissions & 022)) -eq 0 || fail "output parent must not be group- or world-writable"

path_is_equal_or_within "$output" "$bundle" && fail "output must remain outside the unsigned bundle"
path_is_equal_or_within "$output" "$source_root" && fail "output must remain outside the source tree"
for protected_file in \
  "$release_private_key" "$release_public_key" "$policy_private_key" "$policy_public_key" \
  "$distribution_key" "$distribution_public_key" "$allowed_signers"; do
  protected_parent=$(CDPATH= cd -P -- "$(dirname "$protected_file")" && pwd)
  path_is_equal_or_within "$output" "$protected_parent" && fail "output must remain outside every signing/trust input parent"
done

release_key_id=$("$releasectl" public-key-id --public-key "$release_public_key") || fail "cannot parse release public key"
policy_key_id=$("$releasectl" public-key-id --public-key "$policy_public_key") || fail "cannot parse policy public key"
test -n "$release_key_id" && test -n "$policy_key_id" || fail "public key ID is empty"
test "$(printf '%s\n' "$release_key_id" | wc -l | tr -d '[:space:]')" -eq 1 || fail "release public key ID is malformed"
test "$(printf '%s\n' "$policy_key_id" | wc -l | tr -d '[:space:]')" -eq 1 || fail "policy public key ID is malformed"
test "$release_key_id" != "$policy_key_id" || fail "release and policy public key IDs must be different"
if test "$anchor_policy_sequence" != 0; then
  test "$policy_key_id" = "$anchor_policy_key_id" || fail "policy public key differs from the persisted anchor"
fi

key_prompt_input=/dev/null
if /usr/bin/tty 2>/dev/null </dev/tty >/dev/null; then
  key_prompt_input=/dev/tty
fi
derived_distribution_public=$(ssh-keygen -y -f "$distribution_key" <"$key_prompt_input") || fail "cannot derive the distribution public key"
test "$(printf '%s\n' "$derived_distribution_public" | wc -l | tr -d '[:space:]')" -eq 1 || fail "distribution private key produced a malformed public key"
set -- $derived_distribution_public
test "$#" -ge 2 && test "$1" = ssh-ed25519 || fail "distribution private key must be Ed25519"
derived_type=$1
derived_data=$2
test "$(wc -l < "$distribution_public_key" | tr -d '[:space:]')" -eq 1 || fail "distribution public key must contain exactly one line"
read -r public_type public_data public_comment < "$distribution_public_key" || fail "cannot read distribution public key"
test "$public_type" = "$derived_type" && test "$public_data" = "$derived_data" || fail "distribution private and public keys do not match"
ssh-keygen -l -f "$distribution_public_key" >/dev/null 2>&1 || fail "distribution public key is invalid"
expected_release_signer="owntransit-release $public_type $public_data"
expected_source_signer="owntransit-source $public_type $public_data"
test "$(wc -l < "$allowed_signers" | tr -d '[:space:]')" -eq 2 ||
  fail "allowed-signers must contain exactly the two canonical v1 principals"
test "$(sed -n '1p' "$allowed_signers")" = "$expected_release_signer" ||
  fail "allowed-signers release principal is not bound to the distribution public key"
test "$(sed -n '2p' "$allowed_signers")" = "$expected_source_signer" ||
  fail "allowed-signers source principal is not bound to the distribution public key"
expected_allowed_signers_size=$(printf '%s\n%s\n' "$expected_release_signer" "$expected_source_signer" | wc -c | tr -d '[:space:]')
test "$(wc -c < "$allowed_signers" | tr -d '[:space:]')" -eq "$expected_allowed_signers_size" ||
  fail "allowed-signers is not the exact canonical v1 byte representation"
derived_distribution_public=
derived_data=
expected_release_signer=
expected_source_signer=

build_inputs="$bundle/BUILD-INPUTS"
canonical_file "$build_inputs" BUILD-INPUTS
{
  IFS= read -r version_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r release_id_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r release_sequence_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_commit_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_date_epoch_line || fail "BUILD-INPUTS is incomplete"
  IFS= read -r source_manifest_line || fail "BUILD-INPUTS is incomplete"
  if IFS= read -r extra_line; then fail "BUILD-INPUTS contains an unexpected extra line"; fi
} < "$build_inputs"
case "$version_line" in version=*) build_version=${version_line#version=} ;; *) fail "BUILD-INPUTS version field is invalid" ;; esac
case "$release_id_line" in release_id=*) release_id=${release_id_line#release_id=} ;; *) fail "BUILD-INPUTS release ID field is invalid" ;; esac
case "$release_sequence_line" in release_sequence=*) release_sequence=${release_sequence_line#release_sequence=} ;; *) fail "BUILD-INPUTS release sequence field is invalid" ;; esac
case "$source_commit_line" in source_commit=*) build_commit=${source_commit_line#source_commit=} ;; *) fail "BUILD-INPUTS source commit field is invalid" ;; esac
case "$source_date_epoch_line" in source_date_epoch=*) source_date_epoch=${source_date_epoch_line#source_date_epoch=} ;; *) fail "BUILD-INPUTS source date field is invalid" ;; esac
case "$source_manifest_line" in source_manifest_sha256=*) source_manifest_sha256=${source_manifest_line#source_manifest_sha256=} ;; *) fail "BUILD-INPUTS source manifest field is invalid" ;; esac
test "$build_version" = "$version" || fail "--version does not match BUILD-INPUTS"
test "$build_commit" = "$source_commit" || fail "--source-commit does not match BUILD-INPUTS"
case "$release_id" in ''|*[!a-z2-7]*) fail "release ID must be lowercase unpadded base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical trailing base32 bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
canonical_positive_decimal "$release_sequence" || fail "release sequence must be a canonical positive decimal integer"
canonical_positive_decimal "$source_date_epoch" || fail "source date epoch must be a canonical positive decimal integer"
test "${#source_date_epoch}" -le 10 || fail "source date epoch is out of range"
case "$source_manifest_sha256" in ''|*[!0-9a-f]*) fail "source manifest digest must be lowercase hexadecimal" ;; esac
test "${#source_manifest_sha256}" -eq 64 || fail "source manifest digest must contain 64 hexadecimal characters"
decimal_is_at_most "$release_floor" "$release_sequence" || fail "release floor cannot exceed the candidate release sequence"
test "$(sha256_file "$bundle/SOURCE-MANIFEST.txt")" = "$source_manifest_sha256" || fail "BUILD-INPUTS source manifest digest does not match SOURCE-MANIFEST.txt"

workspace=$(mktemp -d "$output_parent/.owntransit-sign-candidate.XXXXXX") || fail "cannot create private candidate workspace"
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve private candidate workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM

validate_bundle() {
  candidate_bundle=$1
  label=$2
  special=$(find "$candidate_bundle" -mindepth 1 ! -type f ! -type d -print)
  test -z "$special" || fail "$label contains a symlink or special entry"
  linked=$(find "$candidate_bundle" -type f -links +1 -print)
  test -z "$linked" || fail "$label contains a multiply linked file"
  checksum_file="$candidate_bundle/SHA256SUMS"
  test -s "$checksum_file" && test -f "$checksum_file" && test ! -L "$checksum_file" || fail "$label SHA256SUMS is absent, empty, or not a regular file"
  checksum_metadata=$(file_metadata "$checksum_file") || fail "cannot inspect $label SHA256SUMS"
  checksum_kind=${checksum_metadata%%|*}
  checksum_rest=${checksum_metadata#*|}
  checksum_links=${checksum_rest%%|*}
  checksum_mode=${checksum_rest#*|}
  case "$checksum_kind" in "Regular File"|"regular file") ;; *) fail "$label SHA256SUMS is not a regular file" ;; esac
  test "$checksum_links" -eq 1 || fail "$label SHA256SUMS has multiple hard links"
  checksum_permissions=$((0$checksum_mode))
  test $((checksum_permissions & 022)) -eq 0 || fail "$label SHA256SUMS is group- or world-writable"
  directories="$workspace/$label.directories"
  find "$candidate_bundle" -type d -print > "$directories"
  while IFS= read -r directory; do
    metadata=$(directory_metadata "$directory") || fail "cannot inspect $label directory"
    kind=${metadata%%|*}; rest=${metadata#*|}; mode=${rest#*|}
    case "$kind" in Directory|directory) ;; *) fail "$label contains a non-directory entry" ;; esac
    permissions=$((0$mode))
    test $((permissions & 022)) -eq 0 || fail "$label contains a group- or world-writable directory"
  done < "$directories"
  actual_paths="$workspace/$label.actual-paths"
  checksum_paths="$workspace/$label.checksum-paths"
  (
    cd "$candidate_bundle"
    find . -type f ! -path './SHA256SUMS' -print | sed 's|^\./||' | LC_ALL=C sort
  ) > "$actual_paths"
  : > "$checksum_paths"
  while IFS= read -r checksum_line; do
    digest=${checksum_line%%  *}
    relative=${checksum_line#"$digest  "}
    test "$checksum_line" = "$digest  $relative" || fail "$label SHA256SUMS contains a non-canonical line"
    case "$digest" in ''|*[!0-9a-f]*) fail "$label SHA256SUMS contains a non-canonical digest" ;; esac
    test "${#digest}" -eq 64 || fail "$label SHA256SUMS digest length is invalid"
    case "$relative" in ''|/*|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*[!A-Za-z0-9._/+:-]*) fail "$label SHA256SUMS contains an unsafe path" ;; esac
    printf '%s\n' "$relative" >> "$checksum_paths"
    member="$candidate_bundle/$relative"
    test -f "$member" && test ! -L "$member" || fail "$label checksum member is not a regular file: $relative"
    metadata=$(file_metadata "$member") || fail "cannot inspect $label member: $relative"
    kind=${metadata%%|*}; rest=${metadata#*|}; links=${rest%%|*}; mode=${rest#*|}
    case "$kind" in "Regular File"|"regular file") ;; *) fail "$label member is not a regular file: $relative" ;; esac
    test "$links" -eq 1 || fail "$label member has multiple hard links: $relative"
    permissions=$((0$mode))
    test $((permissions & 022)) -eq 0 || fail "$label member is group- or world-writable: $relative"
    test "$(sha256_file "$member")" = "$digest" || fail "$label checksum mismatch: $relative"
  done < "$candidate_bundle/SHA256SUMS"
  cmp -s "$actual_paths" "$checksum_paths" || fail "$label SHA256SUMS does not describe its exact sorted file inventory"
}

validate_bundle "$bundle" input-bundle

publish="$workspace/publish"
mkdir -m 0700 "$publish" "$publish/assets" "$publish/trust"
cp -Rp -- "$bundle" "$publish/assets/native" || fail "cannot copy the validated native bundle"
validate_bundle "$publish/assets/native" copied-bundle

cp -- "$release_public_key" "$publish/trust/release-public.pem"
cp -- "$policy_public_key" "$publish/trust/policy-public.pem"
cp -- "$distribution_public_key" "$publish/trust/distribution-public.key"
cp -- "$allowed_signers" "$publish/trust/allowed_signers"
candidate_snapshot="$publish/assets/RELEASE-CANDIDATE.json"
cp -- "$candidate_ledger" "$candidate_snapshot"
trusted_release_public="$publish/trust/release-public.pem"
trusted_policy_public="$publish/trust/policy-public.pem"
trusted_distribution_public="$publish/trust/distribution-public.key"
trusted_allowed_signers="$publish/trust/allowed_signers"
cmp -s "$release_public_key" "$trusted_release_public" || fail "release public-key snapshot changed bytes"
cmp -s "$policy_public_key" "$trusted_policy_public" || fail "policy public-key snapshot changed bytes"
cmp -s "$distribution_public_key" "$trusted_distribution_public" || fail "distribution public-key snapshot changed bytes"
cmp -s "$allowed_signers" "$trusted_allowed_signers" || fail "allowed-signers snapshot changed bytes"
cmp -s "$candidate_ledger" "$candidate_snapshot" || fail "candidate-ledger snapshot changed bytes"
snapshot_release_key_id=$("$releasectl" public-key-id --public-key "$trusted_release_public") || fail "cannot parse snapshotted release public key"
snapshot_policy_key_id=$("$releasectl" public-key-id --public-key "$trusted_policy_public") || fail "cannot parse snapshotted policy public key"
test "$snapshot_release_key_id" = "$release_key_id" || fail "release public-key identity changed during snapshot"
test "$snapshot_policy_key_id" = "$policy_key_id" || fail "policy public-key identity changed during snapshot"
release_key_id=$snapshot_release_key_id
policy_key_id=$snapshot_policy_key_id

candidate_verify_output=$("$releasectl" candidate-verify \
  --candidate "$candidate_snapshot" \
  --bundle "$publish/assets/native" \
  --source-root "$source_root" \
  --policy-sequence "$policy_sequence" \
  --release-floor "$release_floor" \
  --lifecycle-floor "$lifecycle_floor") || fail "candidate ledger does not match the native bundle and policy inputs"
expected_candidate_verify="verified qualification-only candidate version=$version release_id=$release_id release_sequence=$release_sequence policy_sequence=$policy_sequence minimum_release_sequence=$release_floor minimum_lifecycle=$lifecycle_floor source_commit=$source_commit source_date_epoch=$source_date_epoch"
test "$candidate_verify_output" = "$expected_candidate_verify" || fail "candidate verification returned unexpected identity"

manifest="$publish/assets/native/RELEASE-MANIFEST.json"
signature="$publish/assets/RELEASE-MANIFEST.sig"
grep -Fq -- "\"version\":\"$version\"" "$manifest" || fail "release manifest version does not match BUILD-INPUTS"
grep -Fq -- "\"release_id\":\"$release_id\"" "$manifest" || fail "release manifest ID does not match BUILD-INPUTS"
grep -Fq -- "\"sequence\":$release_sequence,\"created_unix\":$source_date_epoch," "$manifest" || fail "release manifest sequence/time do not match BUILD-INPUTS"
grep -Fq -- "\"source\":{\"repository\":\"https://github.com/sentrybottale/owntransit\",\"commit\":\"$source_commit\",\"dirty\":false,\"source_manifest_sha256\":\"$source_manifest_sha256\"}" "$manifest" || fail "release manifest source identity does not match BUILD-INPUTS"
grep -Fq -- '"toolchain":{"go_version":"go1.26.7"' "$manifest" || fail "release manifest does not use the pinned Go toolchain"

"$releasectl" sign-manifest --manifest "$manifest" --release-private-key "$release_private_key" --out "$signature" || fail "release manifest signing failed"
verify_output=$("$releasectl" verify-bundle --bundle "$publish/assets/native" --manifest "$manifest" --signature "$signature" --release-public-key "$trusted_release_public") || fail "signed release bundle verification failed"
test "$verify_output" = "verified release $release_id sequence $release_sequence key $release_key_id" || fail "release verification returned unexpected identity"

policy="$publish/assets/RELEASE-POLICY.json"
policy_signature="$publish/assets/RELEASE-POLICY.sig"
"$releasectl" policy --out "$policy" --release-public-key "$trusted_release_public" \
  --sequence "$policy_sequence" --created-unix "$source_date_epoch" \
  --release-floor "$release_floor" --lifecycle-floor "$lifecycle_floor" || fail "release policy construction failed"
"$releasectl" sign-policy --policy "$policy" --policy-private-key "$policy_private_key" --out "$policy_signature" || fail "release policy signing failed"
"$releasectl" verify-policy --policy "$policy" --signature "$policy_signature" --policy-public-key "$trusted_policy_public" \
  --anchor-policy-sequence "$anchor_policy_sequence" \
  --anchor-release-floor "$anchor_release_floor" \
  --anchor-lifecycle-floor "$anchor_lifecycle_floor" \
  > "$workspace/policy-anchor.json" || fail "release policy verification failed"
expected_policy_anchor="{\"schema\":\"owntransit.release-policy-anchor.v1\",\"highest_policy_sequence\":$policy_sequence,\"minimum_release_sequence\":$release_floor,\"minimum_lifecycle\":$lifecycle_floor,\"tombstoned_release_ids\":null}"
test "$(cat "$workspace/policy-anchor.json")" = "$expected_policy_anchor" || fail "verified policy anchor does not match the candidate sequences and floors"

"$project_root/packaging/macos/sign-checksums.sh" \
  --subject "$publish/assets/native/SHA256SUMS" \
  --signing-key "$distribution_key" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --output "$publish/assets/NATIVE-SHA256SUMS.sig" >/dev/null || fail "native checksum signing failed"

source_archive="$publish/assets/owntransit-$version-source.tar.gz"
"$project_root/packaging/homebrew/build-source-archive.sh" \
  --source "$source_root" \
  --version "$version" \
  --commit "$source_commit" \
  --signing-key "$distribution_key" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-source \
  --output "$source_archive" >/dev/null || fail "signed source archive construction failed"
source_archive_sha256=$(sha256_file "$source_archive")
"$project_root/packaging/homebrew/render-formula.sh" \
  --github-owner sentrybottale \
  --source-repository owntransit \
  --license Apache-2.0 \
  --version "$version" \
  --source-sha256 "$source_archive_sha256" \
  --release-id "$release_id" \
  --source-commit "$source_commit" \
  --go-version go1.26.7 \
  --signer-public-key "$trusted_distribution_public" \
  --output "$publish/assets/owntransit.rb" >/dev/null || fail "Homebrew formula rendering failed"

validate_bundle "$publish/assets/native" final-bundle
verify_output=$("$releasectl" verify-bundle --bundle "$publish/assets/native" --manifest "$manifest" --signature "$signature" --release-public-key "$trusted_release_public") || fail "final signed release bundle verification failed"
test "$verify_output" = "verified release $release_id sequence $release_sequence key $release_key_id" || fail "final release verification returned unexpected identity"
"$releasectl" verify-policy --policy "$policy" --signature "$policy_signature" --policy-public-key "$trusted_policy_public" \
  --anchor-policy-sequence "$anchor_policy_sequence" \
  --anchor-release-floor "$anchor_release_floor" \
  --anchor-lifecycle-floor "$anchor_lifecycle_floor" \
  > "$workspace/final-policy-anchor.json" || fail "final release policy verification failed"
cmp -s "$workspace/policy-anchor.json" "$workspace/final-policy-anchor.json" || fail "policy verification result changed"
test "$(cat "$workspace/final-policy-anchor.json")" = "$expected_policy_anchor" || fail "final verified policy anchor does not match the candidate sequences and floors"
checksum_digest=$(sha256_file "$publish/assets/native/SHA256SUMS")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$publish/assets/native/SHA256SUMS" \
  --sha256 "$checksum_digest" \
  --signature "$publish/assets/NATIVE-SHA256SUMS.sig" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "final checksum signature verification failed"

native_archive="$publish/assets/owntransit-$version-native.tar.gz"
PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin \
  "$project_root/scripts/release/archive-native.sh" \
  --bundle "$publish/assets/native" \
  --output "$native_archive" >/dev/null || fail "deterministic native archive construction failed"

cp -- "$manifest" "$publish/assets/RELEASE-MANIFEST.json"
cmp -s "$manifest" "$publish/assets/RELEASE-MANIFEST.json" || fail "external manifest copy changed bytes"

verified_native="$workspace/verified-native"
mv -- "$publish/assets/native" "$verified_native" || fail "cannot retire private native staging copy"

expected_assets="$workspace/expected-assets"
printf '%s\n' \
  NATIVE-SHA256SUMS.sig \
  RELEASE-CANDIDATE.json \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  "owntransit-$version-native.tar.gz" \
  "owntransit-$version-source.tar.gz" \
  owntransit.rb | LC_ALL=C sort > "$expected_assets"
actual_assets="$workspace/actual-assets"
(
  cd "$publish/assets"
  find . -type f ! -path './SHA256SUMS' -print | sed 's|^\./||' | LC_ALL=C sort
) > "$actual_assets"
cmp -s "$expected_assets" "$actual_assets" || fail "candidate asset inventory is not the fixed first-release set"

(
  cd "$publish/assets"
  while IFS= read -r relative; do
    printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
  done < "$expected_assets"
) > "$publish/assets/SHA256SUMS"
validate_bundle "$publish/assets" outer-assets

"$project_root/packaging/macos/sign-checksums.sh" \
  --subject "$publish/assets/SHA256SUMS" \
  --signing-key "$distribution_key" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --output "$publish/trust/SHA256SUMS.sig" >/dev/null || fail "outer asset checksum signing failed"

verify_output=$("$releasectl" verify-bundle --bundle "$verified_native" --manifest "$publish/assets/RELEASE-MANIFEST.json" --signature "$signature" --release-public-key "$trusted_release_public") || fail "archived native bundle verification failed"
test "$verify_output" = "verified release $release_id sequence $release_sequence key $release_key_id" || fail "archived native release verification returned unexpected identity"
outer_checksum_digest=$(sha256_file "$publish/assets/SHA256SUMS")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$publish/assets/SHA256SUMS" \
  --sha256 "$outer_checksum_digest" \
  --signature "$publish/trust/SHA256SUMS.sig" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "outer asset checksum verification failed"

trust_statement="$publish/trust/TRUST-STATEMENT.txt"
printf '%s\n' \
  'schema=owntransit.release-trust.v1' \
  'product=owntransit' \
  "version=$version" \
  "release_id=$release_id" \
  "source_commit=$source_commit" \
  "distribution_public_sha256=$(sha256_file "$trusted_distribution_public")" \
  "release_public_sha256=$(sha256_file "$trusted_release_public")" \
  "policy_public_sha256=$(sha256_file "$trusted_policy_public")" \
  "allowed_signers_sha256=$(sha256_file "$trusted_allowed_signers")" \
  "outer_sha256sums_sha256=$outer_checksum_digest" \
  > "$trust_statement"
ssh-keygen -q -Y sign \
  -f "$distribution_key" \
  -n owntransit-trust-v1 \
  "$trust_statement" <"$key_prompt_input" || fail "trust statement signing failed"
trust_statement_digest=$(sha256_file "$trust_statement")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$trust_statement" \
  --sha256 "$trust_statement_digest" \
  --signature "$trust_statement.sig" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-trust-v1 >/dev/null || fail "trust statement verification failed"

find "$publish" -type d -exec chmod 0755 {} +
find "$publish/trust" -type f -exec chmod 0644 {} +
chmod 0644 \
  "$publish/assets/NATIVE-SHA256SUMS.sig" \
  "$publish/assets/RELEASE-CANDIDATE.json" \
  "$publish/assets/RELEASE-MANIFEST.json" \
  "$publish/assets/RELEASE-MANIFEST.sig" \
  "$publish/assets/RELEASE-POLICY.json" \
  "$publish/assets/RELEASE-POLICY.sig" \
  "$publish/assets/SHA256SUMS" \
  "$native_archive" \
  "$source_archive" \
  "$publish/assets/owntransit.rb"
validate_bundle "$publish/assets" published-assets
outer_checksum_digest=$(sha256_file "$publish/assets/SHA256SUMS")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$publish/assets/SHA256SUMS" \
  --sha256 "$outer_checksum_digest" \
  --signature "$publish/trust/SHA256SUMS.sig" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "published asset checksum verification failed"
trust_statement_digest=$(sha256_file "$publish/trust/TRUST-STATEMENT.txt")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$publish/trust/TRUST-STATEMENT.txt" \
  --sha256 "$trust_statement_digest" \
  --signature "$publish/trust/TRUST-STATEMENT.txt.sig" \
  --allowed-signers "$trusted_allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-trust-v1 >/dev/null || fail "published trust statement verification failed"
test ! -e "$output" && test ! -L "$output" || fail "output appeared before atomic publication"
mv -- "$publish" "$output" || fail "cannot atomically publish candidate handoff"
trap - EXIT HUP INT TERM
rm -rf -- "$workspace"

printf 'created signed candidate handoff: %s\n' "$output"
printf 'release_id=%s\n' "$release_id"
printf 'release_sequence=%s\n' "$release_sequence"
printf 'source_archive_sha256=%s\n' "$source_archive_sha256"
printf 'trust_statement_sha256=%s\n' "$trust_statement_digest"
