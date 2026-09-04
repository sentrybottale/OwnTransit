#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'qualification-evidence-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
case "$(uname -s)" in
  Darwin) test_workspace_parent=${TMPDIR:-} ;;
  Linux) test_workspace_parent=${HOME:-} ;;
  *) fail "qualification evidence test requires macOS or Linux" ;;
esac
test -n "$test_workspace_parent" || fail "no private test workspace parent is available"
test -d "$test_workspace_parent" && test ! -L "$test_workspace_parent" ||
  fail "private test workspace parent must be a non-symlink directory"
workspace=$(mktemp -d "$test_workspace_parent/.owntransit-qualification-evidence-test.XXXXXX")
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve test workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

validator="$project_root/scripts/release/validate-qualification-evidence.sh"
fixtures="$project_root/scripts/tests/testdata/qualification-evidence"
release_id=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other_release_id=caaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=cccccccccccccccccccccccccccccccccccccccc

native_root="$workspace/native"
outer_assets_root="$workspace/assets"
trust_root="$workspace/trust"
records="$workspace/records"
transcripts="$workspace/transcripts"
mkdir -m 0700 "$native_root" "$outer_assets_root" "$trust_root" "$records" "$transcripts"
mkdir -m 0700 "$native_root/artifacts"

native_artifact_paths='artifacts/owntransit-connector-linux-amd64
artifacts/owntransit-connector-linux-arm64
artifacts/owntransit-darwin-arm64
artifacts/owntransit-launcher-darwin-arm64
artifacts/owntransit-linux-amd64
artifacts/owntransit-linux-arm64
artifacts/owntransit-provision-darwin-arm64
artifacts/owntransit-provision-linux-amd64
artifacts/owntransit-provision-linux-arm64
artifacts/owntransit-relay-linux-amd64.oci.tar
artifacts/owntransit-relay-linux-arm64.oci.tar
artifacts/owntransitctl-darwin-arm64
artifacts/owntransitctl-linux-amd64
artifacts/owntransitctl-linux-arm64'
printf '%s\n' 'fixture source manifest' > "$native_root/SOURCE-MANIFEST.txt"
printf '%s\n' "$native_artifact_paths" |
  while IFS= read -r relative; do
    printf 'fixture bytes for %s\n' "$relative" > "$native_root/$relative"
  done
(
  cd "$native_root"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done
) > "$native_root/SHA256SUMS"

for relative in \
  NATIVE-SHA256SUMS.sig \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  owntransit-0.1.0-source.tar.gz; do
  printf 'fixture outer asset %s\n' "$relative" > "$outer_assets_root/$relative"
done
(
  cd "$outer_assets_root"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done
) > "$outer_assets_root/SHA256SUMS"

for relative in \
  allowed_signers \
  distribution-public.key \
  release-public.pem \
  policy-public.pem \
  TRUST-STATEMENT.txt \
  TRUST-STATEMENT.txt.sig \
  SHA256SUMS.sig; do
  printf 'fixture trust file %s\n' "$relative" > "$trust_root/$relative"
done

outer_checksums="$outer_assets_root/SHA256SUMS"
native_checksums="$native_root/SHA256SUMS"
outer_digest=$(sha256_file "$outer_checksums")

set_field() {
  selected_record=$1
  selected_name=$2
  selected_value=$3
  rendered="$workspace/rendered-field"
  awk -v name="$selected_name" -v value="$selected_value" '
    index($0, name "=") == 1 { print name "=" value; found++; next }
    { print }
    END { if (found != 1) exit 1 }
  ' "$selected_record" > "$rendered" || fail "cannot render fixture field $selected_name"
  mv "$rendered" "$selected_record"
}

native_digest() {
  sha256_file "$native_root/$1"
}

render_fixture() {
  selected_gate=$1
  selected_record="$records/$selected_gate.txt"
  cp "$fixtures/$selected_gate.txt" "$selected_record"
  printf 'sanitized transcript for %s\n' "$selected_gate" > "$transcripts/$selected_gate.txt"
  set_field "$selected_record" outer_sha256sums_sha256 "$outer_digest"
  set_field "$selected_record" transcript_sha256 "$(sha256_file "$transcripts/$selected_gate.txt")"
  case "$selected_gate" in
    live-ssh-scp-path)
      set_field "$selected_record" client_artifact_sha256 \
        "$(native_digest artifacts/owntransit-darwin-arm64)"
      set_field "$selected_record" connector_artifact_sha256 \
        "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      set_field "$selected_record" connector_running_binary_sha256 \
        "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      ;;
    release-signatures)
      set_field "$selected_record" allowed_signers_sha256 "$(sha256_file "$trust_root/allowed_signers")"
      set_field "$selected_record" distribution_public_key_sha256 "$(sha256_file "$trust_root/distribution-public.key")"
      set_field "$selected_record" release_public_key_sha256 "$(sha256_file "$trust_root/release-public.pem")"
      set_field "$selected_record" policy_public_key_sha256 "$(sha256_file "$trust_root/policy-public.pem")"
      set_field "$selected_record" trust_statement_sha256 "$(sha256_file "$trust_root/TRUST-STATEMENT.txt")"
      set_field "$selected_record" trust_statement_signature_sha256 "$(sha256_file "$trust_root/TRUST-STATEMENT.txt.sig")"
      set_field "$selected_record" outer_sha256sums_signature_sha256 "$(sha256_file "$trust_root/SHA256SUMS.sig")"
      set_field "$selected_record" native_sha256sums_sha256 "$(sha256_file "$native_checksums")"
      set_field "$selected_record" native_sha256sums_signature_sha256 "$(sha256_file "$outer_assets_root/NATIVE-SHA256SUMS.sig")"
      set_field "$selected_record" release_manifest_sha256 "$(sha256_file "$outer_assets_root/RELEASE-MANIFEST.json")"
      set_field "$selected_record" release_manifest_signature_sha256 "$(sha256_file "$outer_assets_root/RELEASE-MANIFEST.sig")"
      set_field "$selected_record" release_policy_sha256 "$(sha256_file "$outer_assets_root/RELEASE-POLICY.json")"
      set_field "$selected_record" release_policy_signature_sha256 "$(sha256_file "$outer_assets_root/RELEASE-POLICY.sig")"
      ;;
    source-security-publication)
      set_field "$selected_record" source_archive_sha256 "$(sha256_file "$outer_assets_root/owntransit-0.1.0-source.tar.gz")"
      set_field "$selected_record" source_manifest_sha256 "$(sha256_file "$native_root/SOURCE-MANIFEST.txt")"
      ;;
    supported-artifact-execution)
      set_field "$selected_record" artifact_client_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-darwin-arm64)"
      set_field "$selected_record" artifact_client_linux_amd64_sha256 "$(native_digest artifacts/owntransit-linux-amd64)"
      set_field "$selected_record" artifact_client_linux_arm64_sha256 "$(native_digest artifacts/owntransit-linux-arm64)"
      set_field "$selected_record" artifact_connector_linux_amd64_sha256 "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      set_field "$selected_record" artifact_connector_linux_arm64_sha256 "$(native_digest artifacts/owntransit-connector-linux-arm64)"
      set_field "$selected_record" artifact_launcher_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-launcher-darwin-arm64)"
      set_field "$selected_record" artifact_lifecycle_darwin_arm64_sha256 "$(native_digest artifacts/owntransitctl-darwin-arm64)"
      set_field "$selected_record" artifact_lifecycle_linux_amd64_sha256 "$(native_digest artifacts/owntransitctl-linux-amd64)"
      set_field "$selected_record" artifact_lifecycle_linux_arm64_sha256 "$(native_digest artifacts/owntransitctl-linux-arm64)"
      set_field "$selected_record" artifact_provisioner_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-provision-darwin-arm64)"
      set_field "$selected_record" artifact_provisioner_linux_amd64_sha256 "$(native_digest artifacts/owntransit-provision-linux-amd64)"
      set_field "$selected_record" artifact_provisioner_linux_arm64_sha256 "$(native_digest artifacts/owntransit-provision-linux-arm64)"
      set_field "$selected_record" artifact_relay_linux_amd64_sha256 "$(native_digest artifacts/owntransit-relay-linux-amd64.oci.tar)"
      set_field "$selected_record" artifact_relay_linux_arm64_sha256 "$(native_digest artifacts/owntransit-relay-linux-arm64.oci.tar)"
      set_field "$selected_record" macos_arm64_transcript_sha256 "$(sha256_file "$transcripts/$selected_gate.txt")"
      set_field "$selected_record" linux_amd64_transcript_sha256 "$(sha256_file "$transcripts/$selected_gate.txt")"
      set_field "$selected_record" linux_arm64_transcript_sha256 "$(sha256_file "$transcripts/$selected_gate.txt")"
      ;;
  esac
}

for gate in \
  live-ssh-scp-path \
  release-signatures \
  source-security-publication \
  supported-artifact-execution; do
  render_fixture "$gate"
done

validate() {
  selected_file=$1
  selected_gate=$2
  selected_status=$3
  "$validator" \
    --file "$selected_file" \
    --gate "$selected_gate" \
    --release-id "$release_id" \
    --source-commit "$source_commit" \
    --outer-sha256sums "$outer_checksums" \
    --outer-assets-root "$outer_assets_root" \
    --native-sha256sums "$native_checksums" \
    --native-root "$native_root" \
    --trust-root "$trust_root" \
    --status "$selected_status"
}

for gate in \
  live-ssh-scp-path \
  release-signatures \
  source-security-publication \
  supported-artifact-execution; do
  fixture="$records/$gate.txt"
  test -f "$fixture" && test ! -L "$fixture" || fail "missing canonical fixture: $gate"
  validation_output=$(validate "$fixture" "$gate" PASS) || fail "canonical fixture was rejected: $gate"
  test "$validation_output" = "evidence_sha256=$(sha256_file "$fixture")" ||
    fail "validator returned an unexpected digest handle: $gate"
done

expect_rejection() {
  rejection_name=$1
  rejection_file=$2
  rejection_gate=$3
  rejection_status=$4
  rejection_text=$5
  if rejection_output=$(validate "$rejection_file" "$rejection_gate" "$rejection_status" 2>&1); then
    fail "validator accepted $rejection_name"
  fi
  printf '%s\n' "$rejection_output" | grep -Fq "$rejection_text" ||
    fail "$rejection_name was rejected for the wrong reason"
}

unknown="$workspace/unknown.txt"
{
  cat "$records/live-ssh-scp-path.txt"
  printf '%s\n' 'unknown_result=PASS'
} > "$unknown"
expect_rejection "an unknown field" "$unknown" live-ssh-scp-path PASS \
  'evidence contains an unknown or duplicate trailing field'

unknown_unterminated="$workspace/unknown-unterminated.txt"
{
  cat "$records/live-ssh-scp-path.txt"
  printf '%s' 'unknown_result=PASS'
} > "$unknown_unterminated"
expect_rejection "an unterminated unknown field" "$unknown_unterminated" \
  live-ssh-scp-path PASS \
  'evidence contains an unknown or duplicate trailing field'

missing="$workspace/missing.txt"
sed '$d' "$records/release-signatures.txt" > "$missing"
expect_rejection "a missing field" "$missing" release-signatures PASS \
  'evidence is missing field independent_verification'

duplicate="$workspace/duplicate.txt"
awk '/^client_artifact_id=/ { print; print; next } { print }' \
  "$records/live-ssh-scp-path.txt" > "$duplicate"
expect_rejection "a duplicate field" "$duplicate" live-ssh-scp-path PASS \
  'expected field client_artifact_sha256 in fixed canonical order'

out_of_order="$workspace/out-of-order.txt"
{
  sed -n '1,8p' "$records/release-signatures.txt"
  sed -n '10p' "$records/release-signatures.txt"
  sed -n '9p' "$records/release-signatures.txt"
  sed -n '11,$p' "$records/release-signatures.txt"
} > "$out_of_order"
expect_rejection "out-of-order fields" "$out_of_order" release-signatures PASS \
  'expected field allowed_signers_sha256 in fixed canonical order'

wrong_binding="$workspace/wrong-binding.txt"
sed "s/^release_id=$release_id$/release_id=$other_release_id/" \
  "$records/source-security-publication.txt" > "$wrong_binding"
expect_rejection "a wrong release binding" "$wrong_binding" source-security-publication PASS \
  'release_id does not match the required binding'

wrong_digest="$workspace/wrong-digest.txt"
sed 's/^artifact_client_darwin_arm64_sha256=.*/artifact_client_darwin_arm64_sha256=gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg/' \
  "$records/supported-artifact-execution.txt" > "$wrong_digest"
expect_rejection "an invalid artifact digest" "$wrong_digest" supported-artifact-execution PASS \
  'artifact_client_darwin_arm64_sha256 is not a canonical SHA-256'

wrong_inventory_digest="$workspace/wrong-inventory-digest.txt"
sed 's/^artifact_client_darwin_arm64_sha256=.*/artifact_client_darwin_arm64_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/' \
  "$records/supported-artifact-execution.txt" > "$wrong_inventory_digest"
expect_rejection "an artifact digest outside the authenticated inventory" \
  "$wrong_inventory_digest" supported-artifact-execution PASS \
  'artifact_client_darwin_arm64_sha256 does not match the authenticated inventory'

cp "$native_root/artifacts/owntransit-linux-arm64" "$workspace/owntransit-linux-arm64.original"
printf '%s\n' 'tampered artifact bytes' > "$native_root/artifacts/owntransit-linux-arm64"
expect_rejection "artifact bytes changed after inventory creation" \
  "$records/supported-artifact-execution.txt" supported-artifact-execution PASS \
  'native file digest does not match its authenticated inventory: artifacts/owntransit-linux-arm64'
mv "$workspace/owntransit-linux-arm64.original" "$native_root/artifacts/owntransit-linux-arm64"

cp "$native_checksums" "$workspace/native-SHA256SUMS.saved"
{
  first_inventory_line=$(sed -n '1p' "$workspace/native-SHA256SUMS.saved")
  printf '%s\000\n' "$first_inventory_line"
  sed -n '2,$p' "$workspace/native-SHA256SUMS.saved"
} > "$native_checksums"
expect_rejection "an embedded NUL in the native inventory" \
  "$records/supported-artifact-execution.txt" supported-artifact-execution PASS \
  'native-sha256sums contains a non-canonical byte'
mv "$workspace/native-SHA256SUMS.saved" "$native_checksums"

wrong_running_digest="$workspace/wrong-running-digest.txt"
sed 's/^connector_running_binary_sha256=.*/connector_running_binary_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/' \
  "$records/live-ssh-scp-path.txt" > "$wrong_running_digest"
expect_rejection "a different running connector digest" "$wrong_running_digest" live-ssh-scp-path PASS \
  'running connector digest does not match the signed connector artifact'

wrong_scp_equality="$workspace/wrong-scp-equality.txt"
sed 's/^scp_remote_sha256=.*/scp_remote_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/; s/^scp_digest_equality=PASS$/scp_digest_equality=FAIL/; s/^status=PASS$/status=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$wrong_scp_equality"
validation_output=$(validate "$wrong_scp_equality" live-ssh-scp-path FAIL) ||
  fail "canonical failed SCP evidence was rejected"
test "$validation_output" = "evidence_sha256=$(sha256_file "$wrong_scp_equality")" ||
  fail "failed evidence returned an unexpected digest handle"

false_scp_equality="$workspace/false-scp-equality.txt"
sed 's/^scp_remote_sha256=.*/scp_remote_sha256=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/' \
  "$records/live-ssh-scp-path.txt" > "$false_scp_equality"
expect_rejection "a false SCP digest-equality result" "$false_scp_equality" live-ssh-scp-path PASS \
  'unequal SCP digests must record scp_digest_equality=FAIL'

live_macos_mutation="$workspace/live-macos-mutation.txt"
sed 's/^macos_arm64_system_mutation=NONE$/macos_arm64_system_mutation=MUTATED/' \
  "$records/live-ssh-scp-path.txt" > "$live_macos_mutation"
expect_rejection "a live-path macOS system mutation" "$live_macos_mutation" \
  live-ssh-scp-path PASS \
  'macos_arm64_system_mutation does not match the required binding'

changed_client_configuration="$workspace/changed-client-configuration.txt"
sed 's/^client_configuration_unchanged=PASS$/client_configuration_unchanged=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$changed_client_configuration"
expect_rejection "a changed live client configuration under PASS" \
  "$changed_client_configuration" live-ssh-scp-path PASS \
  'status does not match the fixed gate-specific results'

changed_operator_key="$workspace/changed-operator-key.txt"
sed 's/^operator_ssh_key_unchanged=PASS$/operator_ssh_key_unchanged=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$changed_operator_key"
expect_rejection "a changed operator SSH key under PASS" "$changed_operator_key" \
  live-ssh-scp-path PASS \
  'status does not match the fixed gate-specific results'

changed_connector_configuration="$workspace/changed-connector-configuration.txt"
sed 's/^connector_configuration_unchanged=PASS$/connector_configuration_unchanged=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$changed_connector_configuration"
expect_rejection "a changed connector configuration under PASS" \
  "$changed_connector_configuration" live-ssh-scp-path PASS \
  'status does not match the fixed gate-specific results'

changed_connector_credentials="$workspace/changed-connector-credentials.txt"
sed 's/^connector_endpoint_credentials_unchanged=PASS$/connector_endpoint_credentials_unchanged=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$changed_connector_credentials"
expect_rejection "changed connector endpoint credentials under PASS" \
  "$changed_connector_credentials" live-ssh-scp-path PASS \
  'status does not match the fixed gate-specific results'

wrong_overall_status="$workspace/wrong-overall-status.txt"
sed 's/^ssh_session_result=PASS$/ssh_session_result=FAIL/' \
  "$records/live-ssh-scp-path.txt" > "$wrong_overall_status"
expect_rejection "an inconsistent overall gate status" "$wrong_overall_status" live-ssh-scp-path PASS \
  'status does not match the fixed gate-specific results'

wrong_lifecycle="$workspace/wrong-lifecycle.txt"
sed 's/^linux_amd64_connector_reboot=PASS$/linux_amd64_connector_reboot=FAIL/; s/^status=PASS$/status=FAIL/' \
  "$records/supported-artifact-execution.txt" > "$wrong_lifecycle"
expect_rejection "an inconsistent connector lifecycle result" "$wrong_lifecycle" supported-artifact-execution FAIL \
  'linux_amd64_connector_lifecycle does not match its fixed subresults'

macos_mutation="$workspace/macos-mutation.txt"
sed 's/^macos_arm64_system_mutation=NONE$/macos_arm64_system_mutation=MUTATED/' \
  "$records/supported-artifact-execution.txt" > "$macos_mutation"
expect_rejection "a macOS system-mutation claim" "$macos_mutation" \
  supported-artifact-execution PASS \
  'macos_arm64_system_mutation does not match the required binding'

for nonclaim_field in \
  macos_provisioner_package_lifecycle \
  linux_client_package_lifecycle \
  linux_provisioner_package_lifecycle; do
  claimed_lifecycle="$workspace/claimed-$nonclaim_field.txt"
  sed "s/^$nonclaim_field=NOT-CLAIMED$/$nonclaim_field=PASS/" \
    "$records/supported-artifact-execution.txt" > "$claimed_lifecycle"
  expect_rejection "an unsupported $nonclaim_field claim" "$claimed_lifecycle" \
    supported-artifact-execution PASS \
    "$nonclaim_field does not match the required binding"
done

missing_newline="$workspace/missing-newline.txt"
sed '$s/$//' "$records/source-security-publication.txt" |
  awk 'NR == 1 { hold = $0; next } { print hold; hold = $0 } END { printf "%s", hold }' > "$missing_newline"
expect_rejection "a missing final newline" "$missing_newline" source-security-publication PASS \
  'evidence is missing field candidate_signing_tests'

printf '%s\n' 'qualification evidence canonical validation and fail-closed tests passed'
