#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd) || {
  printf '%s\n' 'sign-qualification-record: cannot resolve project root' >&2
  exit 1
}

fail() {
  printf 'sign-qualification-record: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: sign-qualification-record.sh \
  --release-id 52_CHARACTER_CANONICAL_BASE32 \
  --source-commit 40_OR_64_LOWERCASE_HEX \
  --outer-checksums ABSOLUTE_SIGNED_ASSETS_SHA256SUMS \
  --outer-signature ABSOLUTE_SHA256SUMS_SIGNATURE \
  --allowed-signers ABSOLUTE_INDEPENDENTLY_AUTHENTICATED_FILE \
  --distribution-key ABSOLUTE_ED25519_OPENSSH_PRIVATE_KEY \
  --results ABSOLUTE_CANONICAL_RESULTS_FILE \
  --unresolved-critical NONNEGATIVE_INTEGER \
  --unresolved-high NONNEGATIVE_INTEGER \
  --output ABSOLUTE_NEW_DIRECTORY_OUTSIDE_ASSETS

Authenticates the exact outer asset inventory, validates the fixed v1 results
set, derives PASS only when every fixed gate passes and both unresolved counts
are zero, then creates QUALIFICATION.txt and QUALIFICATION.txt.sig in the
owntransit-qualification-v1 SSHSIG namespace. It does not execute tests or
invent evidence. The output is separate post-test evidence and may not be put
inside the signed asset inventory.
EOF
}

release_id=
source_commit=
outer_checksums=
outer_signature=
allowed_signers=
distribution_key=
results=
unresolved_critical=
unresolved_high=
output=

while test "$#" -gt 0; do
  case "$1" in
    --release-id|--source-commit|--outer-checksums|--outer-signature|--allowed-signers|--distribution-key|--results|--unresolved-critical|--unresolved-high|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --release-id) release_id=$value ;;
        --source-commit) source_commit=$value ;;
        --outer-checksums) outer_checksums=$value ;;
        --outer-signature) outer_signature=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --distribution-key) distribution_key=$value ;;
        --results) results=$value ;;
        --unresolved-critical) unresolved_critical=$value ;;
        --unresolved-high) unresolved_high=$value ;;
        --output) output=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

for required in "$release_id" "$source_commit" "$outer_checksums" "$outer_signature" \
  "$allowed_signers" "$distribution_key" "$results" "$unresolved_critical" \
  "$unresolved_high" "$output"; do
  test -n "$required" || fail "all documented arguments are required"
done

canonical_file() {
  selected=$1
  label=$2
  case "$selected" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -f "$selected" && test ! -L "$selected" || fail "$label must be a regular non-symlink file"
  selected_parent=$(CDPATH= cd -P -- "$(dirname "$selected")" && pwd) || fail "cannot resolve $label parent"
  test "$selected_parent/$(basename "$selected")" = "$selected" || fail "$label path must be canonical"
}

canonical_file "$outer_checksums" outer-checksums
canonical_file "$outer_signature" outer-signature
canonical_file "$allowed_signers" allowed-signers
canonical_file "$distribution_key" distribution-key
canonical_file "$results" results

output_parent=$(dirname "$output")
output_name=$(basename "$output")
case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test -d "$output_parent" && test ! -L "$output_parent" || fail "output parent must be an existing non-symlink directory"
resolved_output_parent=$(CDPATH= cd -P -- "$output_parent" && pwd) || fail "cannot resolve output parent"
test "$resolved_output_parent/$output_name" = "$output" || fail "output path must be canonical"
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
outer_parent=$(dirname "$outer_checksums")
case "$output/" in "$outer_parent/"*) fail "qualification output must remain outside the signed asset inventory" ;; esac

workspace=$(mktemp -d "$resolved_output_parent/.owntransit-qualification.XXXXXX") || fail "cannot create output workspace"
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve output workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM
cp -- "$outer_checksums" "$workspace/outer-SHA256SUMS" || fail "cannot snapshot outer checksums"
cp -- "$outer_signature" "$workspace/outer-SHA256SUMS.sig" || fail "cannot snapshot outer signature"
cp -- "$allowed_signers" "$workspace/allowed_signers" || fail "cannot snapshot allowed-signers"
cp -- "$results" "$workspace/results" || fail "cannot snapshot qualification results"
outer_checksums="$workspace/outer-SHA256SUMS"
outer_signature="$workspace/outer-SHA256SUMS.sig"
allowed_signers="$workspace/allowed_signers"
results="$workspace/results"

case "$release_id" in ''|*[!a-z2-7]*) fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
case "$source_commit" in ''|*[!0-9a-f]*) fail "source commit must be lowercase hexadecimal" ;; esac
case "${#source_commit}" in 40|64) ;; *) fail "source commit must contain 40 or 64 hexadecimal characters" ;; esac

canonical_nonnegative() {
  selected_decimal=$1
  case "$selected_decimal" in ''|*[!0-9]*) return 1 ;; esac
  case "$selected_decimal" in 0|[1-9]*) ;; *) return 1 ;; esac
  test "${#selected_decimal}" -le 9
}
canonical_nonnegative "$unresolved_critical" || fail "unresolved Critical count must be a canonical nonnegative integer"
canonical_nonnegative "$unresolved_high" || fail "unresolved High count must be a canonical nonnegative integer"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

file_mode() {
  if test "$(uname -s)" = Darwin; then
    file_mode_raw=$(stat -f %p -- "$1") || return 1
    case "$file_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
    printf '%o\n' "$((0$file_mode_raw & 07777))"
  else
    stat -c %a -- "$1"
  fi
}
file_owner() {
  if test "$(uname -s)" = Darwin; then stat -f %u -- "$1"; else stat -c %u -- "$1"; fi
}
file_links() {
  if test "$(uname -s)" = Darwin; then stat -f %l -- "$1"; else stat -c %h -- "$1"; fi
}

test "$(file_owner "$distribution_key")" -eq "$(id -u)" || fail "distribution key must be owned by the current effective UID"
test "$(file_mode "$distribution_key")" = 600 || fail "distribution key mode must be 0600"
test "$(file_links "$distribution_key")" -eq 1 || fail "distribution key must have exactly one hard link"
if test "$(uname -s)" = Darwin; then
  test "$(ls -lde -- "$distribution_key" | wc -l | tr -d '[:space:]')" -eq 1 || fail "distribution key has an extended ACL"
fi
protected_ancestor=$(dirname "$distribution_key")
while :; do
  test -d "$protected_ancestor" && test ! -L "$protected_ancestor" || fail "distribution key ancestor is not a regular directory: $protected_ancestor"
  ancestor_mode=$(file_mode "$protected_ancestor")
  if test "$(uname -s)" = Darwin; then
    case "$ancestor_mode" in [0-7][0-7][0-7]) ;; *) fail "distribution key ancestor has special or invalid mode bits: $protected_ancestor" ;; esac
  fi
  ancestor_permissions=$((0$ancestor_mode))
  test $((ancestor_permissions & 022)) -eq 0 || fail "distribution key ancestor is group- or world-writable: $protected_ancestor"
  ancestor_owner=$(file_owner "$protected_ancestor")
  test "$ancestor_owner" -eq 0 || test "$ancestor_owner" -eq "$(id -u)" || fail "distribution key ancestor has an unexpected owner: $protected_ancestor"
  if test "$(uname -s)" = Darwin; then
    test "$(ls -lde -- "$protected_ancestor" | wc -l | tr -d '[:space:]')" -eq 1 || fail "distribution key ancestor has an extended ACL: $protected_ancestor"
  fi
  test "$protected_ancestor" = / && break
  protected_ancestor=$(dirname "$protected_ancestor")
done

key_prompt_input=/dev/null
if /usr/bin/tty 2>/dev/null </dev/tty >/dev/null; then key_prompt_input=/dev/tty; fi
derived_public=$(ssh-keygen -y -f "$distribution_key" <"$key_prompt_input") || fail "cannot derive distribution public key"
set -- $derived_public
test "$#" -ge 2 && test "$1" = ssh-ed25519 || fail "distribution private key must be Ed25519"
public_type=$1
public_data=$2
expected_release_signer="owntransit-release $public_type $public_data"
expected_source_signer="owntransit-source $public_type $public_data"
test "$(wc -l < "$allowed_signers" | tr -d '[:space:]')" -eq 2 || fail "allowed-signers must contain exactly the two canonical v1 principals"
test "$(sed -n '1p' "$allowed_signers")" = "$expected_release_signer" || fail "allowed-signers release principal is not bound to the distribution key"
test "$(sed -n '2p' "$allowed_signers")" = "$expected_source_signer" || fail "allowed-signers source principal is not bound to the distribution key"
expected_allowed_size=$(printf '%s\n%s\n' "$expected_release_signer" "$expected_source_signer" | wc -c | tr -d '[:space:]')
test "$(wc -c < "$allowed_signers" | tr -d '[:space:]')" -eq "$expected_allowed_size" || fail "allowed-signers is not the exact canonical v1 byte representation"

outer_digest=$(sha256_file "$outer_checksums")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$outer_checksums" \
  --sha256 "$outer_digest" \
  --signature "$outer_signature" \
  --allowed-signers "$allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "outer asset inventory authentication failed"

test -s "$results" || fail "results file is empty"
test "$(wc -c < "$results" | tr -d '[:space:]')" -le 8192 || fail "results file is unexpectedly large"
all_pass=yes
exec 3< "$results"
for expected_test in \
  connector-client-ssh-boundary \
  hostile-relay-resource-exhaustion \
  linux-amd64-clean-host-lifecycle \
  linux-amd64-relay-exchange \
  macos-arm64-clean-host-lifecycle \
  public-history-clean-export \
  public-tree-source-gates \
  release-signatures; do
  IFS= read -r result_line <&3 || fail "results file is incomplete"
  test_id=${result_line%%|*}
  result_rest=${result_line#*|}
  test "$result_rest" != "$result_line" || fail "result line is malformed: $expected_test"
  result_status=${result_rest%%|*}
  evidence_digest=${result_rest#*|}
  test "$evidence_digest" != "$result_rest" || fail "result line is malformed: $expected_test"
  test "$test_id" = "$expected_test" || fail "results file does not contain the exact fixed sorted v1 test set"
  test "$result_line" = "$test_id|$result_status|$evidence_digest" || fail "result line is not canonical: $expected_test"
  case "$result_status" in
    PASS|FAIL)
      case "$evidence_digest" in ''|*[!0-9a-f]*) fail "result evidence digest is invalid: $expected_test" ;; esac
      test "${#evidence_digest}" -eq 64 || fail "result evidence digest is invalid: $expected_test"
      ;;
    NOT-PERFORMED)
      test "$evidence_digest" = - || fail "NOT-PERFORMED result must use '-' evidence: $expected_test"
      ;;
    *) fail "result status is invalid: $expected_test" ;;
  esac
  test "$result_status" = PASS || all_pass=no
done
if IFS= read -r extra_result <&3; then fail "results file contains an unexpected extra line"; fi
exec 3<&-

qualification_status=BLOCKED
if test "$all_pass" = yes && test "$unresolved_critical" -eq 0 && test "$unresolved_high" -eq 0; then
  qualification_status=PASS
fi

publish="$workspace/publish"
mkdir -m 0700 "$publish"
record="$publish/QUALIFICATION.txt"
{
  printf '%s\n' \
    'schema=owntransit.qualification.v1' \
    'product=owntransit' \
    "release_id=$release_id" \
    "source_commit=$source_commit" \
    "outer_sha256sums_sha256=$outer_digest" \
    "status=$qualification_status" \
    "unresolved_critical=$unresolved_critical" \
    "unresolved_high=$unresolved_high"
  while IFS= read -r result_line; do printf 'test=%s\n' "$result_line"; done < "$results"
} > "$record"
ssh-keygen -q -Y sign -f "$distribution_key" -n owntransit-qualification-v1 "$record" <"$key_prompt_input" || fail "qualification record signing failed"
record_digest=$(sha256_file "$record")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$record" \
  --sha256 "$record_digest" \
  --signature "$record.sig" \
  --allowed-signers "$allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-qualification-v1 >/dev/null || fail "qualification record verification failed"
chmod 0755 "$publish"
chmod 0644 "$record" "$record.sig"
test ! -e "$output" && test ! -L "$output" || fail "output appeared before atomic publication"
mv -- "$publish" "$output" || fail "cannot atomically publish qualification record"
trap - EXIT HUP INT TERM
rm -rf -- "$workspace"

printf 'created %s qualification record: %s\n' "$qualification_status" "$output"
printf 'qualification_sha256=%s\n' "$record_digest"
