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
  --native-checksums ABSOLUTE_EXTRACTED_NATIVE_SHA256SUMS \
  --trust-root ABSOLUTE_AUTHENTICATED_HANDOFF_TRUST_DIRECTORY \
  --allowed-signers ABSOLUTE_INDEPENDENTLY_AUTHENTICATED_FILE \
  --distribution-key ABSOLUTE_ED25519_OPENSSH_PRIVATE_KEY \
  --results ABSOLUTE_CANONICAL_RESULTS_FILE \
  --evidence-root ABSOLUTE_CANONICAL_EVIDENCE_DIRECTORY \
  --unresolved-critical NONNEGATIVE_INTEGER \
  --unresolved-high NONNEGATIVE_INTEGER \
  --output ABSOLUTE_NEW_DIRECTORY_OUTSIDE_ASSETS

Authenticates the exact outer and extracted-native inventories plus the handoff
trust statement, validates every PASS/FAIL gate's canonical evidence record,
derives PASS only when every fixed gate passes and both unresolved counts are
zero, then creates QUALIFICATION.txt, its SSHSIG, and the digest-bound canonical
evidence records. It does not execute tests or invent evidence. The output is
separate post-test evidence and may not be put inside the signed asset inventory.
EOF
}

release_id=
source_commit=
outer_checksums=
outer_signature=
native_checksums=
trust_root=
allowed_signers=
distribution_key=
results=
evidence_root=
unresolved_critical=
unresolved_high=
output=

while test "$#" -gt 0; do
  case "$1" in
    --release-id|--source-commit|--outer-checksums|--outer-signature|--native-checksums|--trust-root|--allowed-signers|--distribution-key|--results|--evidence-root|--unresolved-critical|--unresolved-high|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --release-id) release_id=$value ;;
        --source-commit) source_commit=$value ;;
        --outer-checksums) outer_checksums=$value ;;
        --outer-signature) outer_signature=$value ;;
        --native-checksums) native_checksums=$value ;;
        --trust-root) trust_root=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --distribution-key) distribution_key=$value ;;
        --results) results=$value ;;
        --evidence-root) evidence_root=$value ;;
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
  "$native_checksums" "$trust_root" "$allowed_signers" "$distribution_key" \
  "$results" "$evidence_root" "$unresolved_critical" "$unresolved_high" "$output"; do
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

canonical_directory() {
  selected=$1
  label=$2
  case "$selected" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -d "$selected" && test ! -L "$selected" || fail "$label must be an existing non-symlink directory"
  resolved_selected=$(CDPATH= cd -P -- "$selected" && pwd) || fail "cannot resolve $label"
  test "$resolved_selected" = "$selected" || fail "$label path must be canonical"
}

canonical_file "$outer_checksums" outer-checksums
canonical_file "$outer_signature" outer-signature
canonical_file "$native_checksums" native-checksums
canonical_directory "$trust_root" trust-root
canonical_file "$allowed_signers" allowed-signers
canonical_file "$distribution_key" distribution-key
canonical_file "$results" results
canonical_directory "$evidence_root" evidence-root

outer_assets_root=$(dirname "$outer_checksums")
native_root=$(dirname "$native_checksums")
canonical_directory "$outer_assets_root" outer-assets-root
canonical_directory "$native_root" native-root
for trust_name in \
  allowed_signers \
  distribution-public.key \
  release-public.pem \
  policy-public.pem \
  SHA256SUMS.sig \
  TRUST-STATEMENT.txt \
  TRUST-STATEMENT.txt.sig; do
  canonical_file "$trust_root/$trust_name" "trust/$trust_name"
done
cmp -s "$outer_signature" "$trust_root/SHA256SUMS.sig" ||
  fail "outer signature does not match the authenticated handoff trust copy"
cmp -s "$allowed_signers" "$trust_root/allowed_signers" ||
  fail "allowed-signers does not match the authenticated handoff trust copy"

output_parent=$(dirname "$output")
output_name=$(basename "$output")
case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test -d "$output_parent" && test ! -L "$output_parent" || fail "output parent must be an existing non-symlink directory"
resolved_output_parent=$(CDPATH= cd -P -- "$output_parent" && pwd) || fail "cannot resolve output parent"
test "$resolved_output_parent/$output_name" = "$output" || fail "output path must be canonical"
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
outer_parent=$(dirname "$outer_checksums")
case "$output/" in "$outer_parent/"*) fail "qualification output must remain outside the signed asset inventory" ;; esac
for protected_input_root in "$native_root" "$trust_root" "$evidence_root"; do
  case "$output/" in "$protected_input_root/"*) fail "qualification output must remain outside its authenticated inputs" ;; esac
done

workspace=$(mktemp -d "$resolved_output_parent/.owntransit-qualification.XXXXXX") || fail "cannot create output workspace"
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve output workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM
mkdir -m 0700 "$workspace/trust" "$workspace/evidence"
cp -- "$outer_checksums" "$workspace/outer-SHA256SUMS" || fail "cannot snapshot outer checksums"
cp -- "$outer_signature" "$workspace/outer-SHA256SUMS.sig" || fail "cannot snapshot outer signature"
cp -- "$native_checksums" "$workspace/native-SHA256SUMS" || fail "cannot snapshot native checksums"
cp -- "$allowed_signers" "$workspace/allowed_signers" || fail "cannot snapshot allowed-signers"
cp -- "$results" "$workspace/results" || fail "cannot snapshot qualification results"
for trust_name in \
  allowed_signers \
  distribution-public.key \
  release-public.pem \
  policy-public.pem \
  SHA256SUMS.sig \
  TRUST-STATEMENT.txt \
  TRUST-STATEMENT.txt.sig; do
  cp -- "$trust_root/$trust_name" "$workspace/trust/$trust_name" ||
    fail "cannot snapshot trust/$trust_name"
done
outer_checksums="$workspace/outer-SHA256SUMS"
outer_signature="$workspace/outer-SHA256SUMS.sig"
native_checksums="$workspace/native-SHA256SUMS"
allowed_signers="$workspace/allowed_signers"
trust_root="$workspace/trust"
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

outer_inventory_digest_for() {
  selected_relative=$1
  selected_count=0
  selected_digest=
  while IFS= read -r checksum_line; do
    checksum_digest=${checksum_line%%  *}
    checksum_relative=${checksum_line#"$checksum_digest  "}
    test "$checksum_line" = "$checksum_digest  $checksum_relative" ||
      fail "outer asset inventory contains a non-canonical line"
    case "$checksum_digest" in ''|*[!0-9a-f]*) fail "outer asset inventory contains an invalid digest" ;; esac
    test "${#checksum_digest}" -eq 64 || fail "outer asset inventory contains an invalid digest"
    if test "$checksum_relative" = "$selected_relative"; then
      selected_count=$((selected_count + 1))
      selected_digest=$checksum_digest
    fi
  done < "$outer_checksums"
  test "$selected_count" -eq 1 || fail "outer asset inventory does not contain exactly one $selected_relative record"
}

outer_inventory_digest_for NATIVE-SHA256SUMS.sig
native_signature_input="$outer_assets_root/NATIVE-SHA256SUMS.sig"
canonical_file "$native_signature_input" native-checksum-signature
test "$(sha256_file "$native_signature_input")" = "$selected_digest" ||
  fail "native checksum signature does not match the authenticated outer inventory"
cp -- "$native_signature_input" "$workspace/NATIVE-SHA256SUMS.sig" ||
  fail "cannot snapshot native checksum signature"
native_signature="$workspace/NATIVE-SHA256SUMS.sig"
native_digest=$(sha256_file "$native_checksums")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$native_checksums" \
  --sha256 "$native_digest" \
  --signature "$native_signature" \
  --allowed-signers "$allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "native asset inventory authentication failed"

distribution_public="$trust_root/distribution-public.key"
test "$(wc -l < "$distribution_public" | tr -d '[:space:]')" -eq 1 ||
  fail "distribution public key must contain exactly one line"
set -- $(cat "$distribution_public")
test "$#" -ge 2 && test "$1" = "$public_type" && test "$2" = "$public_data" ||
  fail "distribution public key does not match the qualification signing key"

trust_statement="$trust_root/TRUST-STATEMENT.txt"
trust_statement_signature="$trust_root/TRUST-STATEMENT.txt.sig"
trust_statement_digest=$(sha256_file "$trust_statement")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$trust_statement" \
  --sha256 "$trust_statement_digest" \
  --signature "$trust_statement_signature" \
  --allowed-signers "$allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-trust-v1 >/dev/null || fail "handoff trust statement authentication failed"

expected_trust_statement="$workspace/expected-TRUST-STATEMENT.txt"
printf '%s\n' \
  'schema=owntransit.release-trust.v1' \
  'product=owntransit' \
  'version=0.1.0' \
  "release_id=$release_id" \
  "source_commit=$source_commit" \
  "distribution_public_sha256=$(sha256_file "$trust_root/distribution-public.key")" \
  "release_public_sha256=$(sha256_file "$trust_root/release-public.pem")" \
  "policy_public_sha256=$(sha256_file "$trust_root/policy-public.pem")" \
  "allowed_signers_sha256=$(sha256_file "$trust_root/allowed_signers")" \
  "outer_sha256sums_sha256=$outer_digest" > "$expected_trust_statement"
cmp -s "$expected_trust_statement" "$trust_statement" ||
  fail "handoff trust statement does not exactly bind the qualification inputs"

test -s "$results" || fail "results file is empty"
test "$(wc -c < "$results" | tr -d '[:space:]')" -le 8192 || fail "results file is unexpectedly large"
test "$(LC_ALL=C tr -d '\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789|-' < "$results" | wc -c | tr -d '[:space:]')" -eq 0 ||
  fail "results file contains a non-canonical byte"
all_pass=yes
exec 3< "$results"
for expected_test in \
  live-ssh-scp-path \
  release-signatures \
  source-security-publication \
  supported-artifact-execution; do
  IFS= read -r result_line <&3 || fail "results file is incomplete"
  test_id=${result_line%%|*}
  result_rest=${result_line#*|}
  test "$result_rest" != "$result_line" || fail "result line is malformed: $expected_test"
  result_status=${result_rest%%|*}
  evidence_digest=${result_rest#*|}
  test "$evidence_digest" != "$result_rest" || fail "result line is malformed: $expected_test"
  test "$test_id" = "$expected_test" || fail "results file does not contain the exact fixed sorted stable 0.1.0 gate set"
  test "$result_line" = "$test_id|$result_status|$evidence_digest" || fail "result line is not canonical: $expected_test"
  case "$result_status" in
    PASS|FAIL)
      case "$evidence_digest" in ''|*[!0-9a-f]*) fail "result evidence digest is invalid: $expected_test" ;; esac
      test "${#evidence_digest}" -eq 64 || fail "result evidence digest is invalid: $expected_test"
      evidence_input="$evidence_root/$expected_test.txt"
      canonical_file "$evidence_input" "$expected_test evidence"
      evidence_snapshot="$workspace/evidence/$expected_test.txt"
      cp -- "$evidence_input" "$evidence_snapshot" || fail "cannot snapshot $expected_test evidence"
      evidence_validation=$("$project_root/scripts/release/validate-qualification-evidence.sh" \
        --file "$evidence_snapshot" \
        --gate "$expected_test" \
        --release-id "$release_id" \
        --source-commit "$source_commit" \
        --outer-sha256sums "$outer_checksums" \
        --outer-assets-root "$outer_assets_root" \
        --native-sha256sums "$native_checksums" \
        --native-root "$native_root" \
        --trust-root "$trust_root" \
        --status "$result_status") || fail "$expected_test canonical evidence validation failed"
      test "$evidence_validation" = "evidence_sha256=$evidence_digest" ||
        fail "$expected_test validated evidence digest does not match the results file"
      ;;
    NOT-PERFORMED)
      test "$evidence_digest" = - || fail "NOT-PERFORMED result must use '-' evidence: $expected_test"
      test ! -e "$evidence_root/$expected_test.txt" && test ! -L "$evidence_root/$expected_test.txt" ||
        fail "NOT-PERFORMED result must not have a canonical evidence record: $expected_test"
      ;;
    *) fail "result status is invalid: $expected_test" ;;
  esac
  test "$result_status" = PASS || all_pass=no
done
extra_result=
if IFS= read -r extra_result <&3 || test -n "$extra_result"; then
  fail "results file contains an unexpected extra line"
fi
exec 3<&-

for evidence_entry in \
  "$evidence_root"/* \
  "$evidence_root"/.[!.]* \
  "$evidence_root"/..?*; do
  if test ! -e "$evidence_entry" && test ! -L "$evidence_entry"; then
    continue
  fi
  evidence_name=${evidence_entry##*/}
  test -f "$workspace/evidence/$evidence_name" ||
    fail "evidence root contains an unexpected entry"
done

live_evidence="$workspace/evidence/live-ssh-scp-path.txt"
supported_evidence="$workspace/evidence/supported-artifact-execution.txt"
if test -f "$live_evidence" && test -f "$supported_evidence"; then
  live_client_digest=$(sed -n 's/^client_artifact_sha256=//p' "$live_evidence")
  supported_client_digest=$(sed -n 's/^artifact_client_darwin_arm64_sha256=//p' "$supported_evidence")
  test -n "$live_client_digest" && test "$live_client_digest" = "$supported_client_digest" ||
    fail "live client digest does not match supported-artifact evidence"
  live_connector_id=$(sed -n 's/^connector_artifact_id=//p' "$live_evidence")
  live_connector_digest=$(sed -n 's/^connector_artifact_sha256=//p' "$live_evidence")
  case "$live_connector_id" in
    connector-linux-amd64)
      supported_connector_digest=$(sed -n 's/^artifact_connector_linux_amd64_sha256=//p' "$supported_evidence")
      ;;
    connector-linux-arm64)
      supported_connector_digest=$(sed -n 's/^artifact_connector_linux_arm64_sha256=//p' "$supported_evidence")
      ;;
    *) fail "live connector artifact identity is invalid after evidence validation" ;;
  esac
  test -n "$live_connector_digest" && test "$live_connector_digest" = "$supported_connector_digest" ||
    fail "live connector digest does not match supported-artifact evidence"
fi

qualification_status=BLOCKED
if test "$all_pass" = yes && test "$unresolved_critical" -eq 0 && test "$unresolved_high" -eq 0; then
  qualification_status=PASS
fi

publish="$workspace/publish"
mkdir -m 0700 "$publish" "$publish/evidence"
for evidence_snapshot in "$workspace/evidence"/*.txt; do
  test -f "$evidence_snapshot" || continue
  cp -- "$evidence_snapshot" "$publish/evidence/$(basename "$evidence_snapshot")" ||
    fail "cannot stage canonical evidence record"
done
record="$publish/QUALIFICATION.txt"
{
  printf '%s\n' \
    'schema=owntransit.qualification.v1' \
    'gate_set=owntransit-0.1.0-minimal.v1' \
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
chmod 0755 "$publish" "$publish/evidence"
chmod 0644 "$record" "$record.sig"
find "$publish/evidence" -type f -exec chmod 0644 {} \;
test ! -e "$output" && test ! -L "$output" || fail "output appeared before atomic publication"
mv -- "$publish" "$output" || fail "cannot atomically publish qualification record"
trap - EXIT HUP INT TERM
rm -rf -- "$workspace"

printf 'created %s qualification record: %s\n' "$qualification_status" "$output"
printf 'qualification_sha256=%s\n' "$record_digest"
