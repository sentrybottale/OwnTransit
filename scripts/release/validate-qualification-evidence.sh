#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL

fail() {
  printf 'validate-qualification-evidence: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: validate-qualification-evidence.sh \
  --file ABSOLUTE_CANONICAL_EVIDENCE_FILE \
  --gate FIXED_0.1.0_GATE \
  --release-id 52_CHARACTER_CANONICAL_BASE32 \
  --source-commit 40_OR_64_LOWERCASE_HEX \
  --outer-sha256sums ABSOLUTE_AUTHENTICATED_OUTER_SHA256SUMS \
  --outer-assets-root ABSOLUTE_EXACT_ASSETS_DIRECTORY \
  --native-sha256sums ABSOLUTE_AUTHENTICATED_NATIVE_SHA256SUMS \
  --native-root ABSOLUTE_EXTRACTED_NATIVE_DIRECTORY \
  --trust-root ABSOLUTE_AUTHENTICATED_TRUST_DIRECTORY \
  --status PASS_OR_FAIL

Validates one already-created canonical OwnTransit 0.1.0 qualification-evidence
record. The record has a fixed field order and a gate-specific closed schema.
The helper creates no keys or files and prints only the record's SHA-256.
EOF
}

evidence_file=
expected_gate=
expected_release_id=
expected_source_commit=
outer_checksums=
outer_assets_root=
native_checksums=
native_root=
trust_root=
expected_status=

while test "$#" -gt 0; do
  case "$1" in
    --file|--gate|--release-id|--source-commit|--outer-sha256sums|--outer-assets-root|--native-sha256sums|--native-root|--trust-root|--status)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --file) evidence_file=$value ;;
        --gate) expected_gate=$value ;;
        --release-id) expected_release_id=$value ;;
        --source-commit) expected_source_commit=$value ;;
        --outer-sha256sums) outer_checksums=$value ;;
        --outer-assets-root) outer_assets_root=$value ;;
        --native-sha256sums) native_checksums=$value ;;
        --native-root) native_root=$value ;;
        --trust-root) trust_root=$value ;;
        --status) expected_status=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

for required in "$evidence_file" "$expected_gate" "$expected_release_id" \
  "$expected_source_commit" "$outer_checksums" "$outer_assets_root" \
  "$native_checksums" "$native_root" "$trust_root" "$expected_status"; do
  test -n "$required" || fail "all documented arguments are required"
done

case "$evidence_file" in /*) ;; *) fail "file path must be absolute" ;; esac
test -f "$evidence_file" && test ! -L "$evidence_file" ||
  fail "file must be a regular non-symlink file"
evidence_parent=$(CDPATH= cd -P -- "$(dirname "$evidence_file")" && pwd) ||
  fail "cannot resolve file parent"
resolved_evidence="$evidence_parent/$(basename "$evidence_file")"
test "$evidence_parent" != / || resolved_evidence="/$(basename "$evidence_file")"
test "$resolved_evidence" = "$evidence_file" ||
  fail "file path must be canonical and contain no symlinked parent"
test -s "$evidence_file" || fail "evidence file is empty"
test "$(wc -c < "$evidence_file" | tr -d '[:space:]')" -le 32768 ||
  fail "evidence file is unexpectedly large"
test "$(LC_ALL=C tr -d '\nABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.=-' < "$evidence_file" | wc -c | tr -d '[:space:]')" -eq 0 ||
  fail "evidence file contains a non-canonical byte"

canonical_file() {
  selected=$1
  label=$2
  case "$selected" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -f "$selected" && test ! -L "$selected" ||
    fail "$label must be a regular non-symlink file"
  selected_parent=$(CDPATH= cd -P -- "$(dirname "$selected")" && pwd) ||
    fail "cannot resolve $label parent"
  resolved_selected="$selected_parent/$(basename "$selected")"
  test "$selected_parent" != / || resolved_selected="/$(basename "$selected")"
  test "$resolved_selected" = "$selected" ||
    fail "$label path must be canonical and contain no symlinked parent"
}

canonical_directory() {
  selected=$1
  label=$2
  case "$selected" in /*) ;; *) fail "$label path must be absolute" ;; esac
  test -d "$selected" && test ! -L "$selected" ||
    fail "$label must be an existing non-symlink directory"
  resolved_selected=$(CDPATH= cd -P -- "$selected" && pwd) || fail "cannot resolve $label"
  test "$resolved_selected" = "$selected" ||
    fail "$label path must be canonical and contain no symlinked parent"
}

canonical_file "$outer_checksums" outer-sha256sums
canonical_directory "$outer_assets_root" outer-assets-root
canonical_file "$native_checksums" native-sha256sums
canonical_directory "$native_root" native-root
canonical_directory "$trust_root" trust-root

canonical_release_id() {
  selected=$1
  case "$selected" in ''|*[!a-z2-7]*) return 1 ;; esac
  test "${#selected}" -eq 52 || return 1
  case "$selected" in *[aq]) ;; *) return 1 ;; esac
  test "$selected" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
}

canonical_commit() {
  selected=$1
  case "$selected" in ''|*[!0-9a-f]*) return 1 ;; esac
  case "${#selected}" in 40|64) ;; *) return 1 ;; esac
}

canonical_sha256() {
  selected=$1
  case "$selected" in ''|*[!0-9a-f]*) return 1 ;; esac
  test "${#selected}" -eq 64
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

for checked_root in "$outer_assets_root" "$native_root" "$trust_root"; do
  test -z "$(find "$checked_root" -type l -print -quit)" ||
    fail "validated asset and trust roots may not contain symlinks"
done

validate_inventory_shape() {
  inventory_file=$1
  inventory_label=$2
  test -s "$inventory_file" || fail "$inventory_label is empty"
  test "$(LC_ALL=C tr -d '\n ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/+:-' < "$inventory_file" | wc -c | tr -d '[:space:]')" -eq 0 ||
    fail "$inventory_label contains a non-canonical byte"
  inventory_newlines=$(wc -l < "$inventory_file" | tr -d '[:space:]')
  inventory_records=$(awk 'END { print NR + 0 }' "$inventory_file")
  test "$inventory_newlines" = "$inventory_records" ||
    fail "$inventory_label must end with exactly one complete canonical line"
  previous_path=
  while IFS= read -r inventory_line; do
    inventory_line_digest=${inventory_line%%  *}
    inventory_line_path=${inventory_line#"$inventory_line_digest  "}
    test "$inventory_line" = "$inventory_line_digest  $inventory_line_path" ||
      fail "$inventory_label contains a non-canonical line"
    canonical_sha256 "$inventory_line_digest" ||
      fail "$inventory_label contains a non-canonical SHA-256"
    case "$inventory_line_path" in
      ''|/*|./*|../*|*/./*|*/../*|*/.|*/..|*//*|*[!A-Za-z0-9._/+:-]*)
        fail "$inventory_label contains an unsafe path"
        ;;
    esac
    if test -n "$previous_path"; then
      awk -v previous="$previous_path" -v current="$inventory_line_path" \
        'BEGIN { exit !(previous < current) }' ||
        fail "$inventory_label paths are duplicated or not C-sorted"
    fi
    previous_path=$inventory_line_path
  done < "$inventory_file"
}

validate_inventory_shape "$outer_checksums" outer-sha256sums
validate_inventory_shape "$native_checksums" native-sha256sums
outer_digest=$(sha256_file "$outer_checksums")
canonical_sha256 "$outer_digest" || fail "outer SHA256SUMS digest is not canonical"

lookup_inventory_file() {
  selected_inventory=$1
  selected_root=$2
  selected_relative=$3
  selected_label=$4
  inventory_match_count=0
  inventory_digest=
  while IFS= read -r inventory_line; do
    candidate_digest=${inventory_line%%  *}
    candidate_path=${inventory_line#"$candidate_digest  "}
    if test "$candidate_path" = "$selected_relative"; then
      inventory_match_count=$((inventory_match_count + 1))
      inventory_digest=$candidate_digest
    fi
  done < "$selected_inventory"
  test "$inventory_match_count" -eq 1 ||
    fail "$selected_label inventory does not contain exactly one $selected_relative record"
  selected_actual="$selected_root/$selected_relative"
  test -f "$selected_actual" && test ! -L "$selected_actual" ||
    fail "$selected_label file is missing or not a regular file: $selected_relative"
  actual_digest=$(sha256_file "$selected_actual")
  test "$actual_digest" = "$inventory_digest" ||
    fail "$selected_label file digest does not match its authenticated inventory: $selected_relative"
}

canonical_release_id "$expected_release_id" ||
  fail "expected release ID is not canonical"
canonical_commit "$expected_source_commit" ||
  fail "expected source commit is not canonical"
case "$expected_status" in PASS|FAIL) ;; *) fail "expected status must be PASS or FAIL" ;; esac
case "$expected_gate" in
  live-ssh-scp-path|release-signatures|source-security-publication|supported-artifact-execution) ;;
  *) fail "gate is not in the fixed OwnTransit 0.1.0 gate set" ;;
esac

exec 3< "$evidence_file"
read_field() {
  expected_name=$1
  IFS= read -r evidence_line <&3 || fail "evidence is missing field $expected_name"
  case "$evidence_line" in
    "$expected_name="*) evidence_value=${evidence_line#*=} ;;
    *) fail "expected field $expected_name in fixed canonical order" ;;
  esac
  test "$evidence_line" = "$expected_name=$evidence_value" ||
    fail "field $expected_name is not canonical"
  test -n "$evidence_value" || fail "field $expected_name is empty"
}

expect_literal() {
  literal_name=$1
  literal_value=$2
  read_field "$literal_name"
  test "$evidence_value" = "$literal_value" ||
    fail "$literal_name does not match the required binding"
}

require_sha256_field() {
  sha_name=$1
  read_field "$sha_name"
  canonical_sha256 "$evidence_value" || fail "$sha_name is not a canonical SHA-256"
}

all_required_pass=yes
require_result_field() {
  result_name=$1
  read_field "$result_name"
  case "$evidence_value" in
    PASS) ;;
    FAIL) all_required_pass=no ;;
    *) fail "$result_name must be PASS or FAIL" ;;
  esac
}

require_not_claimed() {
  claim_name=$1
  expect_literal "$claim_name" NOT-CLAIMED
}

expect_literal schema owntransit.qualification-evidence.v1
expect_literal gate_set owntransit-0.1.0-minimal.v1
expect_literal gate "$expected_gate"
expect_literal release_id "$expected_release_id"
expect_literal source_commit "$expected_source_commit"
expect_literal outer_sha256sums_sha256 "$outer_digest"
read_field status
record_status=$evidence_value
test "$record_status" = "$expected_status" || fail "status does not match the required binding"
require_sha256_field transcript_sha256

require_inventory_sha256_field() {
  binding_name=$1
  binding_inventory=$2
  binding_root=$3
  binding_relative=$4
  binding_label=$5
  require_sha256_field "$binding_name"
  recorded_inventory_digest=$evidence_value
  lookup_inventory_file "$binding_inventory" "$binding_root" "$binding_relative" "$binding_label"
  test "$recorded_inventory_digest" = "$inventory_digest" ||
    fail "$binding_name does not match the authenticated inventory"
}

require_file_sha256_field() {
  binding_name=$1
  binding_file=$2
  binding_label=$3
  test -f "$binding_file" && test ! -L "$binding_file" ||
    fail "$binding_label is missing or not a regular file"
  require_sha256_field "$binding_name"
  recorded_file_digest=$evidence_value
  actual_file_digest=$(sha256_file "$binding_file")
  test "$recorded_file_digest" = "$actual_file_digest" ||
    fail "$binding_name does not match $binding_label"
}

case "$expected_gate" in
  live-ssh-scp-path)
    expect_literal macos_arm64_system_mutation NONE
    require_result_field client_configuration_unchanged
    require_result_field operator_ssh_key_unchanged
    require_result_field connector_configuration_unchanged
    require_result_field connector_endpoint_credentials_unchanged
    expect_literal client_artifact_id client-darwin-arm64
    require_inventory_sha256_field \
      client_artifact_sha256 "$native_checksums" "$native_root" \
      artifacts/owntransit-darwin-arm64 native
    client_artifact_sha256=$evidence_value
    read_field connector_artifact_id
    connector_artifact_id=$evidence_value
    case "$connector_artifact_id" in
      connector-linux-amd64|connector-linux-arm64) ;;
      *) fail "connector_artifact_id is not a supported connector artifact" ;;
    esac
    case "$connector_artifact_id" in
      connector-linux-amd64) connector_artifact_path=artifacts/owntransit-connector-linux-amd64 ;;
      connector-linux-arm64) connector_artifact_path=artifacts/owntransit-connector-linux-arm64 ;;
    esac
    require_inventory_sha256_field \
      connector_artifact_sha256 "$native_checksums" "$native_root" \
      "$connector_artifact_path" native
    connector_artifact_sha256=$evidence_value
    require_sha256_field connector_running_binary_sha256
    connector_running_binary_sha256=$evidence_value
    test "$connector_running_binary_sha256" = "$connector_artifact_sha256" ||
      fail "running connector digest does not match the signed connector artifact"
    require_result_field ssh_session_result
    require_result_field scp_upload_result
    expect_literal scp_payload_size 65536
    require_sha256_field scp_source_sha256
    scp_source_sha256=$evidence_value
    require_sha256_field scp_remote_sha256
    scp_remote_sha256=$evidence_value
    require_result_field scp_roundtrip_result
    require_sha256_field scp_roundtrip_sha256
    scp_roundtrip_sha256=$evidence_value
    require_result_field scp_digest_equality
    digest_equality_result=$evidence_value
    if test "$scp_source_sha256" = "$scp_remote_sha256" &&
       test "$scp_source_sha256" = "$scp_roundtrip_sha256"; then
      test "$digest_equality_result" = PASS ||
        fail "equal SCP digests must record scp_digest_equality=PASS"
    else
      test "$digest_equality_result" = FAIL ||
        fail "unequal SCP digests must record scp_digest_equality=FAIL"
    fi
    ;;
  release-signatures)
    require_file_sha256_field allowed_signers_sha256 \
      "$trust_root/allowed_signers" trust/allowed_signers
    require_file_sha256_field distribution_public_key_sha256 \
      "$trust_root/distribution-public.key" trust/distribution-public.key
    require_file_sha256_field release_public_key_sha256 \
      "$trust_root/release-public.pem" trust/release-public.pem
    require_file_sha256_field policy_public_key_sha256 \
      "$trust_root/policy-public.pem" trust/policy-public.pem
    require_file_sha256_field trust_statement_sha256 \
      "$trust_root/TRUST-STATEMENT.txt" trust/TRUST-STATEMENT.txt
    require_file_sha256_field trust_statement_signature_sha256 \
      "$trust_root/TRUST-STATEMENT.txt.sig" trust/TRUST-STATEMENT.txt.sig
    require_file_sha256_field outer_sha256sums_signature_sha256 \
      "$trust_root/SHA256SUMS.sig" trust/SHA256SUMS.sig
    require_file_sha256_field native_sha256sums_sha256 \
      "$native_checksums" native/SHA256SUMS
    require_inventory_sha256_field native_sha256sums_signature_sha256 \
      "$outer_checksums" "$outer_assets_root" NATIVE-SHA256SUMS.sig outer
    require_inventory_sha256_field release_manifest_sha256 \
      "$outer_checksums" "$outer_assets_root" RELEASE-MANIFEST.json outer
    require_inventory_sha256_field release_manifest_signature_sha256 \
      "$outer_checksums" "$outer_assets_root" RELEASE-MANIFEST.sig outer
    require_inventory_sha256_field release_policy_sha256 \
      "$outer_checksums" "$outer_assets_root" RELEASE-POLICY.json outer
    require_inventory_sha256_field release_policy_signature_sha256 \
      "$outer_checksums" "$outer_assets_root" RELEASE-POLICY.sig outer
    for result_field in \
      trust_statement_verification \
      outer_inventory_verification \
      native_inventory_verification \
      release_manifest_verification \
      release_policy_verification \
      every_outer_inventory_byte_verification \
      every_native_inventory_byte_verification \
      independent_verification; do
      require_result_field "$result_field"
    done
    ;;
  source-security-publication)
    require_inventory_sha256_field source_archive_sha256 \
      "$outer_checksums" "$outer_assets_root" owntransit-0.1.0-source.tar.gz outer
    require_inventory_sha256_field source_manifest_sha256 \
      "$native_checksums" "$native_root" SOURCE-MANIFEST.txt native
    for result_field in \
      go_test_race_default \
      go_test_race_poc \
      go_vet_default \
      go_vet_poc \
      pinned_vulnerability_analysis_default \
      pinned_vulnerability_analysis_poc \
      dependency_license_check \
      security_check_full \
      publication_check_history \
      release_static_check \
      qualification_static_check \
      signature_tool_tests \
      native_archive_tests \
      installer_entrypoint_tests \
      qualification_record_tests \
      candidate_signing_tests; do
      require_result_field "$result_field"
    done
    ;;
  supported-artifact-execution)
    for artifact_id in \
      client_darwin_arm64 \
      client_linux_amd64 \
      client_linux_arm64 \
      connector_linux_amd64 \
      connector_linux_arm64 \
      launcher_darwin_arm64 \
      lifecycle_darwin_arm64 \
      lifecycle_linux_amd64 \
      lifecycle_linux_arm64 \
      provisioner_darwin_arm64 \
      provisioner_linux_amd64 \
      provisioner_linux_arm64 \
      relay_linux_amd64 \
      relay_linux_arm64; do
      case "$artifact_id" in
        client_darwin_arm64) artifact_path=artifacts/owntransit-darwin-arm64 ;;
        client_linux_amd64) artifact_path=artifacts/owntransit-linux-amd64 ;;
        client_linux_arm64) artifact_path=artifacts/owntransit-linux-arm64 ;;
        connector_linux_amd64) artifact_path=artifacts/owntransit-connector-linux-amd64 ;;
        connector_linux_arm64) artifact_path=artifacts/owntransit-connector-linux-arm64 ;;
        launcher_darwin_arm64) artifact_path=artifacts/owntransit-launcher-darwin-arm64 ;;
        lifecycle_darwin_arm64) artifact_path=artifacts/owntransitctl-darwin-arm64 ;;
        lifecycle_linux_amd64) artifact_path=artifacts/owntransitctl-linux-amd64 ;;
        lifecycle_linux_arm64) artifact_path=artifacts/owntransitctl-linux-arm64 ;;
        provisioner_darwin_arm64) artifact_path=artifacts/owntransit-provision-darwin-arm64 ;;
        provisioner_linux_amd64) artifact_path=artifacts/owntransit-provision-linux-amd64 ;;
        provisioner_linux_arm64) artifact_path=artifacts/owntransit-provision-linux-arm64 ;;
        relay_linux_amd64) artifact_path=artifacts/owntransit-relay-linux-amd64.oci.tar ;;
        relay_linux_arm64) artifact_path=artifacts/owntransit-relay-linux-arm64.oci.tar ;;
      esac
      require_inventory_sha256_field \
        "artifact_${artifact_id}_sha256" "$native_checksums" "$native_root" \
        "$artifact_path" native
      require_result_field "artifact_${artifact_id}_result"
    done
    require_sha256_field macos_arm64_transcript_sha256
    require_sha256_field linux_amd64_transcript_sha256
    require_sha256_field linux_arm64_transcript_sha256
    require_result_field macos_arm64_launcher_rejection
    expect_literal macos_arm64_system_mutation NONE

    linux_amd64_lifecycle_pass=yes
    for result_field in \
      linux_amd64_connector_install \
      linux_amd64_connector_enable \
      linux_amd64_connector_restart \
      linux_amd64_connector_reboot \
      linux_amd64_host_ssh_reconnect \
      linux_amd64_connector_running_binary_identity \
      linux_amd64_connector_systemd_confinement \
      linux_amd64_connector_no_listener; do
      require_result_field "$result_field"
      test "$evidence_value" = PASS || linux_amd64_lifecycle_pass=no
    done
    require_result_field linux_amd64_connector_lifecycle
    linux_amd64_lifecycle_result=$evidence_value
    if test "$linux_amd64_lifecycle_pass" = yes; then
      test "$linux_amd64_lifecycle_result" = PASS ||
        fail "linux_amd64_connector_lifecycle does not match its fixed subresults"
    else
      test "$linux_amd64_lifecycle_result" = FAIL ||
        fail "linux_amd64_connector_lifecycle does not match its fixed subresults"
    fi

    linux_arm64_lifecycle_pass=yes
    for result_field in \
      linux_arm64_connector_install \
      linux_arm64_connector_enable \
      linux_arm64_connector_restart \
      linux_arm64_connector_reboot \
      linux_arm64_host_ssh_reconnect \
      linux_arm64_connector_running_binary_identity \
      linux_arm64_connector_systemd_confinement \
      linux_arm64_connector_no_listener; do
      require_result_field "$result_field"
      test "$evidence_value" = PASS || linux_arm64_lifecycle_pass=no
    done
    require_result_field linux_arm64_connector_lifecycle
    linux_arm64_lifecycle_result=$evidence_value
    if test "$linux_arm64_lifecycle_pass" = yes; then
      test "$linux_arm64_lifecycle_result" = PASS ||
        fail "linux_arm64_connector_lifecycle does not match its fixed subresults"
    else
      test "$linux_arm64_lifecycle_result" = FAIL ||
        fail "linux_arm64_connector_lifecycle does not match its fixed subresults"
    fi

    require_not_claimed macos_arm64_client_lifecycle
    require_not_claimed macos_provisioner_package_lifecycle
    require_not_claimed linux_client_package_lifecycle
    require_not_claimed linux_provisioner_package_lifecycle
    require_not_claimed linux_relay_package_lifecycle
    require_not_claimed pristine_host
    require_not_claimed enrollment
    ;;
esac

extra_line=
if IFS= read -r extra_line <&3 || test -n "$extra_line"; then
  fail "evidence contains an unknown or duplicate trailing field"
fi
exec 3<&-

derived_status=FAIL
if test "$all_required_pass" = yes; then
  derived_status=PASS
fi
test "$record_status" = "$derived_status" ||
  fail "status does not match the fixed gate-specific results"

if command -v sha256sum >/dev/null 2>&1; then
  evidence_digest=$(sha256sum "$evidence_file" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  evidence_digest=$(shasum -a 256 "$evidence_file" | awk '{print $1}')
else
  fail "sha256sum or shasum is required"
fi
canonical_sha256 "$evidence_digest" || fail "SHA-256 helper returned a non-canonical digest"
printf 'evidence_sha256=%s\n' "$evidence_digest"
