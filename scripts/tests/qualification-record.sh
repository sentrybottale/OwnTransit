#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'qualification-record-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
case "$(uname -s)" in
  Darwin) test_workspace_parent=${TMPDIR:-} ;;
  Linux) test_workspace_parent=${HOME:-} ;;
  *) fail "qualification record test requires macOS or Linux" ;;
esac
test -n "$test_workspace_parent" || fail "no private test workspace parent is available"
test -d "$test_workspace_parent" && test ! -L "$test_workspace_parent" ||
  fail "private test workspace parent must be a non-symlink directory"
workspace=$(mktemp -d "$test_workspace_parent/.owntransit-qualification-record-test.XXXXXX")
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

mkdir -m 0700 \
  "$workspace/keys" \
  "$workspace/assets" \
  "$workspace/native" \
  "$workspace/native/artifacts" \
  "$workspace/trust" \
  "$workspace/evidence-pass" \
  "$workspace/output"

distribution_key="$workspace/keys/distribution"
ssh-keygen -q -t ed25519 -N '' -f "$distribution_key"
chmod 0600 "$distribution_key"
public_fields=$(awk '{print $1 " " $2}' "$distribution_key.pub")
printf '%s\n' "owntransit-release $public_fields" "owntransit-source $public_fields" > "$workspace/keys/allowed_signers"
cp "$workspace/keys/allowed_signers" "$workspace/trust/allowed_signers"
cp "$distribution_key.pub" "$workspace/trust/distribution-public.key"
printf '%s\n' fixture-release-public > "$workspace/trust/release-public.pem"
printf '%s\n' fixture-policy-public > "$workspace/trust/policy-public.pem"

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
printf '%s\n' fixture-source-manifest > "$workspace/native/SOURCE-MANIFEST.txt"
printf '%s\n' "$native_artifact_paths" |
  while IFS= read -r relative; do
    printf 'fixture bytes for %s\n' "$relative" > "$workspace/native/$relative"
  done
(
  cd "$workspace/native"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done
) > "$workspace/native/SHA256SUMS"
ssh-keygen -q -Y sign -f "$distribution_key" -n owntransit-release-v1 "$workspace/native/SHA256SUMS"
mv "$workspace/native/SHA256SUMS.sig" "$workspace/assets/NATIVE-SHA256SUMS.sig"

for relative in \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  owntransit-0.1.0-source.tar.gz; do
  printf 'fixture outer asset %s\n' "$relative" > "$workspace/assets/$relative"
done
(
  cd "$workspace/assets"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done
) > "$workspace/assets/SHA256SUMS"
ssh-keygen -q -Y sign -f "$distribution_key" -n owntransit-release-v1 "$workspace/assets/SHA256SUMS"
mv "$workspace/assets/SHA256SUMS.sig" "$workspace/trust/SHA256SUMS.sig"

release_id=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=cccccccccccccccccccccccccccccccccccccccc
outer_digest=$(sha256_file "$workspace/assets/SHA256SUMS")
printf '%s\n' \
  'schema=owntransit.release-trust.v1' \
  'product=owntransit' \
  'version=0.1.0' \
  "release_id=$release_id" \
  "source_commit=$source_commit" \
  "distribution_public_sha256=$(sha256_file "$workspace/trust/distribution-public.key")" \
  "release_public_sha256=$(sha256_file "$workspace/trust/release-public.pem")" \
  "policy_public_sha256=$(sha256_file "$workspace/trust/policy-public.pem")" \
  "allowed_signers_sha256=$(sha256_file "$workspace/trust/allowed_signers")" \
  "outer_sha256sums_sha256=$outer_digest" > "$workspace/trust/TRUST-STATEMENT.txt"
ssh-keygen -q -Y sign -f "$distribution_key" -n owntransit-trust-v1 "$workspace/trust/TRUST-STATEMENT.txt"

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
  sha256_file "$workspace/native/$1"
}

fixtures="$project_root/scripts/tests/testdata/qualification-evidence"
for gate in \
  live-ssh-scp-path \
  release-signatures \
  source-security-publication \
  supported-artifact-execution; do
  record="$workspace/evidence-pass/$gate.txt"
  cp "$fixtures/$gate.txt" "$record"
  set_field "$record" outer_sha256sums_sha256 "$outer_digest"
  case "$gate" in
    live-ssh-scp-path)
      set_field "$record" client_artifact_sha256 "$(native_digest artifacts/owntransit-darwin-arm64)"
      set_field "$record" connector_artifact_sha256 "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      set_field "$record" connector_running_binary_sha256 "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      ;;
    release-signatures)
      set_field "$record" allowed_signers_sha256 "$(sha256_file "$workspace/trust/allowed_signers")"
      set_field "$record" distribution_public_key_sha256 "$(sha256_file "$workspace/trust/distribution-public.key")"
      set_field "$record" release_public_key_sha256 "$(sha256_file "$workspace/trust/release-public.pem")"
      set_field "$record" policy_public_key_sha256 "$(sha256_file "$workspace/trust/policy-public.pem")"
      set_field "$record" trust_statement_sha256 "$(sha256_file "$workspace/trust/TRUST-STATEMENT.txt")"
      set_field "$record" trust_statement_signature_sha256 "$(sha256_file "$workspace/trust/TRUST-STATEMENT.txt.sig")"
      set_field "$record" outer_sha256sums_signature_sha256 "$(sha256_file "$workspace/trust/SHA256SUMS.sig")"
      set_field "$record" native_sha256sums_sha256 "$(sha256_file "$workspace/native/SHA256SUMS")"
      set_field "$record" native_sha256sums_signature_sha256 "$(sha256_file "$workspace/assets/NATIVE-SHA256SUMS.sig")"
      set_field "$record" release_manifest_sha256 "$(sha256_file "$workspace/assets/RELEASE-MANIFEST.json")"
      set_field "$record" release_manifest_signature_sha256 "$(sha256_file "$workspace/assets/RELEASE-MANIFEST.sig")"
      set_field "$record" release_policy_sha256 "$(sha256_file "$workspace/assets/RELEASE-POLICY.json")"
      set_field "$record" release_policy_signature_sha256 "$(sha256_file "$workspace/assets/RELEASE-POLICY.sig")"
      ;;
    source-security-publication)
      set_field "$record" source_archive_sha256 "$(sha256_file "$workspace/assets/owntransit-0.1.0-source.tar.gz")"
      set_field "$record" source_manifest_sha256 "$(sha256_file "$workspace/native/SOURCE-MANIFEST.txt")"
      ;;
    supported-artifact-execution)
      set_field "$record" artifact_client_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-darwin-arm64)"
      set_field "$record" artifact_client_linux_amd64_sha256 "$(native_digest artifacts/owntransit-linux-amd64)"
      set_field "$record" artifact_client_linux_arm64_sha256 "$(native_digest artifacts/owntransit-linux-arm64)"
      set_field "$record" artifact_connector_linux_amd64_sha256 "$(native_digest artifacts/owntransit-connector-linux-amd64)"
      set_field "$record" artifact_connector_linux_arm64_sha256 "$(native_digest artifacts/owntransit-connector-linux-arm64)"
      set_field "$record" artifact_launcher_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-launcher-darwin-arm64)"
      set_field "$record" artifact_lifecycle_darwin_arm64_sha256 "$(native_digest artifacts/owntransitctl-darwin-arm64)"
      set_field "$record" artifact_lifecycle_linux_amd64_sha256 "$(native_digest artifacts/owntransitctl-linux-amd64)"
      set_field "$record" artifact_lifecycle_linux_arm64_sha256 "$(native_digest artifacts/owntransitctl-linux-arm64)"
      set_field "$record" artifact_provisioner_darwin_arm64_sha256 "$(native_digest artifacts/owntransit-provision-darwin-arm64)"
      set_field "$record" artifact_provisioner_linux_amd64_sha256 "$(native_digest artifacts/owntransit-provision-linux-amd64)"
      set_field "$record" artifact_provisioner_linux_arm64_sha256 "$(native_digest artifacts/owntransit-provision-linux-arm64)"
      set_field "$record" artifact_relay_linux_amd64_sha256 "$(native_digest artifacts/owntransit-relay-linux-amd64.oci.tar)"
      set_field "$record" artifact_relay_linux_arm64_sha256 "$(native_digest artifacts/owntransit-relay-linux-arm64.oci.tar)"
      ;;
  esac
done

live_digest=$(sha256_file "$workspace/evidence-pass/live-ssh-scp-path.txt")
signature_digest=$(sha256_file "$workspace/evidence-pass/release-signatures.txt")
source_digest=$(sha256_file "$workspace/evidence-pass/source-security-publication.txt")
artifact_digest=$(sha256_file "$workspace/evidence-pass/supported-artifact-execution.txt")
results="$workspace/keys/results"
printf '%s\n' \
  "live-ssh-scp-path|PASS|$live_digest" \
  "release-signatures|PASS|$signature_digest" \
  "source-security-publication|PASS|$source_digest" \
  "supported-artifact-execution|PASS|$artifact_digest" > "$results"

signer="$project_root/scripts/release/sign-qualification-record.sh"
invoke_signer() {
  selected_results=$1
  selected_evidence_root=$2
  selected_critical=$3
  selected_high=$4
  selected_output=$5
  "$signer" \
    --release-id "$release_id" \
    --source-commit "$source_commit" \
    --outer-checksums "$workspace/assets/SHA256SUMS" \
    --outer-signature "$workspace/trust/SHA256SUMS.sig" \
    --native-checksums "$workspace/native/SHA256SUMS" \
    --trust-root "$workspace/trust" \
    --allowed-signers "$workspace/keys/allowed_signers" \
    --distribution-key "$distribution_key" \
    --results "$selected_results" \
    --evidence-root "$selected_evidence_root" \
    --unresolved-critical "$selected_critical" \
    --unresolved-high "$selected_high" \
    --output "$selected_output"
}

pass_output="$workspace/output/pass"
invoke_signer "$results" "$workspace/evidence-pass" 0 0 "$pass_output" > "$workspace/pass.out"
grep -Fqx 'schema=owntransit.qualification.v1' "$pass_output/QUALIFICATION.txt" || fail "record omitted qualification schema"
grep -Fqx 'status=PASS' "$pass_output/QUALIFICATION.txt" || fail "all-passing record was not PASS"
grep -Fqx "release_id=$release_id" "$pass_output/QUALIFICATION.txt" || fail "record omitted release ID"
grep -Fqx "source_commit=$source_commit" "$pass_output/QUALIFICATION.txt" || fail "record omitted source commit"
grep -Fqx "outer_sha256sums_sha256=$outer_digest" "$pass_output/QUALIFICATION.txt" || fail "record omitted outer inventory digest"
grep -Fqx 'gate_set=owntransit-0.1.0-minimal.v1' "$pass_output/QUALIFICATION.txt" || fail "record omitted stable gate-set identity"
test "$(grep -c '^test=' "$pass_output/QUALIFICATION.txt")" -eq 4 || fail "record omitted fixed tests"
test "$(find "$pass_output/evidence" -type f | wc -l | tr -d '[:space:]')" -eq 4 || fail "output omitted canonical evidence records"
for gate in live-ssh-scp-path release-signatures source-security-publication supported-artifact-execution; do
  cmp -s "$workspace/evidence-pass/$gate.txt" "$pass_output/evidence/$gate.txt" ||
    fail "published canonical evidence changed: $gate"
done
record_digest=$(sha256_file "$pass_output/QUALIFICATION.txt")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$pass_output/QUALIFICATION.txt" \
  --sha256 "$record_digest" \
  --signature "$pass_output/QUALIFICATION.txt.sig" \
  --allowed-signers "$workspace/keys/allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-qualification-v1 >/dev/null || fail "PASS record signature did not verify"

blocked_output="$workspace/output/blocked"
invoke_signer "$results" "$workspace/evidence-pass" 0 1 "$blocked_output" >/dev/null
grep -Fqx 'status=BLOCKED' "$blocked_output/QUALIFICATION.txt" || fail "unresolved High did not force BLOCKED"
grep -Fqx 'unresolved_high=1' "$blocked_output/QUALIFICATION.txt" || fail "record omitted unresolved High count"

critical_output="$workspace/output/critical"
invoke_signer "$results" "$workspace/evidence-pass" 1 0 "$critical_output" >/dev/null
grep -Fqx 'status=BLOCKED' "$critical_output/QUALIFICATION.txt" || fail "unresolved Critical did not force BLOCKED"
grep -Fqx 'unresolved_critical=1' "$critical_output/QUALIFICATION.txt" || fail "record omitted unresolved Critical count"

cp -R "$workspace/evidence-pass" "$workspace/evidence-failed"
sed 's/^status=PASS$/status=FAIL/; s/^ssh_session_result=PASS$/ssh_session_result=FAIL/' \
  "$workspace/evidence-pass/live-ssh-scp-path.txt" > "$workspace/evidence-failed/live-ssh-scp-path.txt"
failed_live_digest=$(sha256_file "$workspace/evidence-failed/live-ssh-scp-path.txt")
failed_results="$workspace/keys/results-failed"
sed "s/^live-ssh-scp-path|PASS|$live_digest$/live-ssh-scp-path|FAIL|$failed_live_digest/" "$results" > "$failed_results"
failed_output="$workspace/output/failed"
invoke_signer "$failed_results" "$workspace/evidence-failed" 0 0 "$failed_output" >/dev/null
grep -Fqx 'status=BLOCKED' "$failed_output/QUALIFICATION.txt" || fail "FAIL result did not force BLOCKED"
grep -Fqx "test=live-ssh-scp-path|FAIL|$failed_live_digest" "$failed_output/QUALIFICATION.txt" || fail "FAIL result was not preserved"

cp -R "$workspace/evidence-pass" "$workspace/evidence-not-performed"
rm "$workspace/evidence-not-performed/supported-artifact-execution.txt"
not_performed_results="$workspace/keys/results-not-performed"
sed "s/^supported-artifact-execution|PASS|$artifact_digest$/supported-artifact-execution|NOT-PERFORMED|-/" "$results" > "$not_performed_results"
not_performed_output="$workspace/output/not-performed"
invoke_signer "$not_performed_results" "$workspace/evidence-not-performed" 0 0 "$not_performed_output" >/dev/null
grep -Fqx 'status=BLOCKED' "$not_performed_output/QUALIFICATION.txt" || fail "NOT-PERFORMED result did not force BLOCKED"
grep -Fqx 'test=supported-artifact-execution|NOT-PERFORMED|-' "$not_performed_output/QUALIFICATION.txt" || fail "NOT-PERFORMED result was not preserved"
test ! -e "$not_performed_output/evidence/supported-artifact-execution.txt" ||
  fail "NOT-PERFORMED output unexpectedly included an evidence record"

invalid_not_performed_results="$workspace/keys/results-invalid-not-performed"
sed "s/^supported-artifact-execution|PASS|/supported-artifact-execution|NOT-PERFORMED|/" "$results" > "$invalid_not_performed_results"
if invalid_not_performed_rejection=$(invoke_signer "$invalid_not_performed_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-invalid-not-performed" 2>&1); then
  fail "signer accepted NOT-PERFORMED with digest evidence"
fi
printf '%s\n' "$invalid_not_performed_rejection" | grep -Fq "NOT-PERFORMED result must use '-' evidence" ||
  fail "invalid NOT-PERFORMED result was rejected for the wrong reason"

extra_results="$workspace/keys/results-extra"
{
  cat "$results"
  printf '%s\n' "unexpected-test|PASS|$live_digest"
} > "$extra_results"
if extra_rejection=$(invoke_signer "$extra_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-extra" 2>&1); then
  fail "signer accepted an extra test"
fi
printf '%s\n' "$extra_rejection" | grep -Fq 'results file contains an unexpected extra line' || fail "extra test was rejected for the wrong reason"
test ! -e "$workspace/output/rejected-extra" || fail "rejected extra-test output was created"

extra_unterminated_results="$workspace/keys/results-extra-unterminated"
{
  cat "$results"
  printf '%s' "unexpected-test|PASS|$live_digest"
} > "$extra_unterminated_results"
if extra_unterminated_rejection=$(invoke_signer "$extra_unterminated_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-extra-unterminated" 2>&1); then
  fail "signer accepted an unterminated extra test"
fi
printf '%s\n' "$extra_unterminated_rejection" | grep -Fq 'results file contains an unexpected extra line' ||
  fail "unterminated extra test was rejected for the wrong reason"
test ! -e "$workspace/output/rejected-extra-unterminated" ||
  fail "rejected unterminated extra-test output was created"

embedded_nul_results="$workspace/keys/results-embedded-nul"
{
  sed -n '1,3p' "$results"
  printf '%s\000\n' "$(sed -n '4p' "$results")"
} > "$embedded_nul_results"
if embedded_nul_rejection=$(invoke_signer "$embedded_nul_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-embedded-nul" 2>&1); then
  fail "signer accepted a results file containing an embedded NUL"
fi
printf '%s\n' "$embedded_nul_rejection" | grep -Fq 'results file contains a non-canonical byte' ||
  fail "embedded-NUL results were rejected for the wrong reason"
test ! -e "$workspace/output/rejected-embedded-nul" ||
  fail "rejected embedded-NUL output was created"

missing_results="$workspace/keys/results-missing"
sed '$d' "$results" > "$missing_results"
if missing_rejection=$(invoke_signer "$missing_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-missing" 2>&1); then
  fail "signer accepted an omitted fixed test"
fi
printf '%s\n' "$missing_rejection" | grep -Fq 'results file is incomplete' || fail "missing test was rejected for the wrong reason"

unsorted_results="$workspace/keys/results-unsorted"
{
  sed -n '2p' "$results"
  sed -n '1p' "$results"
  sed -n '3,4p' "$results"
} > "$unsorted_results"
if unsorted_rejection=$(invoke_signer "$unsorted_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-unsorted" 2>&1); then
  fail "signer accepted an unsorted fixed test set"
fi
printf '%s\n' "$unsorted_rejection" | grep -Fq 'results file does not contain the exact fixed sorted stable 0.1.0 gate set' ||
  fail "unsorted test set was rejected for the wrong reason"

wrong_digest_results="$workspace/keys/results-wrong-digest"
sed "s/^live-ssh-scp-path|PASS|$live_digest$/live-ssh-scp-path|PASS|eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/" "$results" > "$wrong_digest_results"
if wrong_digest_rejection=$(invoke_signer "$wrong_digest_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-wrong-digest" 2>&1); then
  fail "signer accepted an evidence digest mismatch"
fi
printf '%s\n' "$wrong_digest_rejection" | grep -Fq 'validated evidence digest does not match the results file' ||
  fail "evidence digest mismatch was rejected for the wrong reason"

cp -R "$workspace/evidence-pass" "$workspace/evidence-wrong-binding"
sed 's/^source_commit=.*/source_commit=dddddddddddddddddddddddddddddddddddddddd/' \
  "$workspace/evidence-pass/source-security-publication.txt" > "$workspace/evidence-wrong-binding/source-security-publication.txt"
wrong_binding_digest=$(sha256_file "$workspace/evidence-wrong-binding/source-security-publication.txt")
wrong_binding_results="$workspace/keys/results-wrong-binding"
sed "s/^source-security-publication|PASS|$source_digest$/source-security-publication|PASS|$wrong_binding_digest/" "$results" > "$wrong_binding_results"
if wrong_binding_rejection=$(invoke_signer "$wrong_binding_results" "$workspace/evidence-wrong-binding" 0 0 "$workspace/output/rejected-wrong-binding" 2>&1); then
  fail "signer accepted wrongly bound evidence"
fi
printf '%s\n' "$wrong_binding_rejection" | grep -Fq 'canonical evidence validation failed' ||
  fail "wrong evidence binding was rejected for the wrong reason"

cp -R "$workspace/evidence-pass" "$workspace/evidence-missing"
rm "$workspace/evidence-missing/live-ssh-scp-path.txt"
if missing_evidence_rejection=$(invoke_signer "$results" "$workspace/evidence-missing" 0 0 "$workspace/output/rejected-missing-evidence" 2>&1); then
  fail "signer accepted a missing PASS evidence record"
fi
printf '%s\n' "$missing_evidence_rejection" | grep -Fq 'live-ssh-scp-path evidence must be a regular non-symlink file' ||
  fail "missing PASS evidence was rejected for the wrong reason"

if not_performed_evidence_rejection=$(invoke_signer "$not_performed_results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-not-performed-evidence" 2>&1); then
  fail "signer accepted evidence for NOT-PERFORMED"
fi
printf '%s\n' "$not_performed_evidence_rejection" | grep -Fq "NOT-PERFORMED result must not have a canonical evidence record" ||
  fail "NOT-PERFORMED evidence was rejected for the wrong reason"

cp -R "$workspace/evidence-pass" "$workspace/evidence-extra-file"
printf '%s\n' 'unexpected evidence' > "$workspace/evidence-extra-file/unexpected.txt"
if extra_evidence_file_rejection=$(invoke_signer "$results" "$workspace/evidence-extra-file" 0 0 "$workspace/output/rejected-extra-evidence-file" 2>&1); then
  fail "signer accepted an extra evidence file"
fi
printf '%s\n' "$extra_evidence_file_rejection" | grep -Fq 'evidence root contains an unexpected entry' ||
  fail "extra evidence file was rejected for the wrong reason"

cp -R "$workspace/evidence-pass" "$workspace/evidence-extra-directory"
mkdir "$workspace/evidence-extra-directory/unexpected-directory"
if extra_evidence_directory_rejection=$(invoke_signer "$results" "$workspace/evidence-extra-directory" 0 0 "$workspace/output/rejected-extra-evidence-directory" 2>&1); then
  fail "signer accepted an extra evidence directory"
fi
printf '%s\n' "$extra_evidence_directory_rejection" | grep -Fq 'evidence root contains an unexpected entry' ||
  fail "extra evidence directory was rejected for the wrong reason"

cp -R "$workspace/evidence-pass" "$workspace/evidence-extra-symlink"
ln -s live-ssh-scp-path.txt "$workspace/evidence-extra-symlink/.unexpected-link"
if extra_evidence_symlink_rejection=$(invoke_signer "$results" "$workspace/evidence-extra-symlink" 0 0 "$workspace/output/rejected-extra-evidence-symlink" 2>&1); then
  fail "signer accepted an extra evidence symlink"
fi
printf '%s\n' "$extra_evidence_symlink_rejection" | grep -Fq 'evidence root contains an unexpected entry' ||
  fail "extra evidence symlink was rejected for the wrong reason"

cp "$workspace/native/SHA256SUMS" "$workspace/native-SHA256SUMS.saved"
printf '%s\n' 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee  unexpected' >> "$workspace/native/SHA256SUMS"
if native_auth_rejection=$(invoke_signer "$results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-native-auth" 2>&1); then
  fail "signer accepted an unauthenticated native inventory"
fi
printf '%s\n' "$native_auth_rejection" | grep -Fq 'native asset inventory authentication failed' ||
  fail "unauthenticated native inventory was rejected for the wrong reason"
mv "$workspace/native-SHA256SUMS.saved" "$workspace/native/SHA256SUMS"

cp "$workspace/trust/TRUST-STATEMENT.txt" "$workspace/TRUST-STATEMENT.saved"
sed 's/^product=owntransit$/product=wrong/' "$workspace/TRUST-STATEMENT.saved" > "$workspace/trust/TRUST-STATEMENT.txt"
if trust_auth_rejection=$(invoke_signer "$results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-trust-auth" 2>&1); then
  fail "signer accepted an unauthenticated trust statement"
fi
printf '%s\n' "$trust_auth_rejection" | grep -Fq 'handoff trust statement authentication failed' ||
  fail "unauthenticated trust statement was rejected for the wrong reason"
mv "$workspace/TRUST-STATEMENT.saved" "$workspace/trust/TRUST-STATEMENT.txt"

if nested_rejection=$(invoke_signer "$results" "$workspace/evidence-pass" 0 0 "$workspace/assets/qualification" 2>&1); then
  fail "signer wrote qualification evidence inside signed assets"
fi
printf '%s\n' "$nested_rejection" | grep -Fq 'qualification output must remain outside the signed asset inventory' || fail "nested output was rejected for the wrong reason"

chmod 1600 "$workspace/keys/distribution"
if special_mode_rejection=$(invoke_signer "$results" "$workspace/evidence-pass" 0 0 "$workspace/output/rejected-special-mode" 2>&1); then
  fail "signer accepted a distribution key with special mode bits"
fi
printf '%s\n' "$special_mode_rejection" | grep -Fq 'distribution key mode must be 0600' ||
  fail "special-mode distribution key was rejected for the wrong reason"
test ! -e "$workspace/output/rejected-special-mode" || fail "rejected special-mode output was created"
chmod 0600 "$workspace/keys/distribution"

printf '%s\n' 'qualification record canonical signing and fail-closed tests passed'
