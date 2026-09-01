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
workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-qualification-record-test.XXXXXX")
workspace=$(CDPATH= cd -P -- "$workspace" && pwd) || fail "cannot resolve test workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi
}

mkdir -m 0700 "$workspace/keys"
mkdir -m 0755 "$workspace/assets" "$workspace/output"
ssh-keygen -q -t ed25519 -N '' -f "$workspace/keys/distribution"
chmod 0600 "$workspace/keys/distribution"
public_fields=$(awk '{print $1 " " $2}' "$workspace/keys/distribution.pub")
printf '%s\n' "owntransit-release $public_fields" "owntransit-source $public_fields" > "$workspace/keys/allowed_signers"
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  owntransit-0.1.0-native.tar.gz' > "$workspace/assets/SHA256SUMS"
ssh-keygen -q -Y sign -f "$workspace/keys/distribution" -n owntransit-release-v1 "$workspace/assets/SHA256SUMS"
mv "$workspace/assets/SHA256SUMS.sig" "$workspace/keys/SHA256SUMS.sig"

evidence=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
results="$workspace/keys/results"
printf '%s\n' \
  "connector-client-ssh-boundary|PASS|$evidence" \
  "hostile-relay-resource-exhaustion|PASS|$evidence" \
  "linux-amd64-clean-host-lifecycle|PASS|$evidence" \
  "linux-amd64-relay-exchange|PASS|$evidence" \
  "macos-arm64-clean-host-lifecycle|PASS|$evidence" \
  "public-history-clean-export|PASS|$evidence" \
  "public-tree-source-gates|PASS|$evidence" \
  "release-signatures|PASS|$evidence" > "$results"

release_id=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
source_commit=cccccccccccccccccccccccccccccccccccccccc
signer="$project_root/scripts/release/sign-qualification-record.sh"

invoke_signer() {
  selected_results=$1
  selected_critical=$2
  selected_high=$3
  selected_output=$4
  "$signer" \
    --release-id "$release_id" \
    --source-commit "$source_commit" \
    --outer-checksums "$workspace/assets/SHA256SUMS" \
    --outer-signature "$workspace/keys/SHA256SUMS.sig" \
    --allowed-signers "$workspace/keys/allowed_signers" \
    --distribution-key "$workspace/keys/distribution" \
    --results "$selected_results" \
    --unresolved-critical "$selected_critical" \
    --unresolved-high "$selected_high" \
    --output "$selected_output"
}

pass_output="$workspace/output/pass"
invoke_signer "$results" 0 0 "$pass_output" > "$workspace/pass.out"
grep -Fqx 'status=PASS' "$pass_output/QUALIFICATION.txt" || fail "all-passing record was not PASS"
grep -Fqx "release_id=$release_id" "$pass_output/QUALIFICATION.txt" || fail "record omitted release ID"
grep -Fqx "source_commit=$source_commit" "$pass_output/QUALIFICATION.txt" || fail "record omitted source commit"
grep -Fqx "outer_sha256sums_sha256=$(sha256_file "$workspace/assets/SHA256SUMS")" "$pass_output/QUALIFICATION.txt" || fail "record omitted outer inventory digest"
test "$(grep -c '^test=' "$pass_output/QUALIFICATION.txt")" -eq 8 || fail "record omitted fixed tests"
record_digest=$(sha256_file "$pass_output/QUALIFICATION.txt")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$pass_output/QUALIFICATION.txt" \
  --sha256 "$record_digest" \
  --signature "$pass_output/QUALIFICATION.txt.sig" \
  --allowed-signers "$workspace/keys/allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-qualification-v1 >/dev/null || fail "PASS record signature did not verify"

blocked_output="$workspace/output/blocked"
invoke_signer "$results" 0 1 "$blocked_output" >/dev/null
grep -Fqx 'status=BLOCKED' "$blocked_output/QUALIFICATION.txt" || fail "unresolved High did not force BLOCKED"
grep -Fqx 'unresolved_high=1' "$blocked_output/QUALIFICATION.txt" || fail "record omitted unresolved High count"

extra_results="$workspace/keys/results-extra"
{
  cat "$results"
  printf '%s\n' "unexpected-test|PASS|$evidence"
} > "$extra_results"
if extra_rejection=$(invoke_signer "$extra_results" 0 0 "$workspace/output/rejected-extra" 2>&1); then
  fail "signer accepted an extra test"
fi
printf '%s\n' "$extra_rejection" | grep -Fq 'results file contains an unexpected extra line' || fail "extra test was rejected for the wrong reason"
test ! -e "$workspace/output/rejected-extra" || fail "rejected extra-test output was created"

missing_results="$workspace/keys/results-missing"
sed '$d' "$results" > "$missing_results"
if missing_rejection=$(invoke_signer "$missing_results" 0 0 "$workspace/output/rejected-missing" 2>&1); then
  fail "signer accepted an omitted fixed test"
fi
printf '%s\n' "$missing_rejection" | grep -Fq 'results file is incomplete' || fail "missing test was rejected for the wrong reason"

if nested_rejection=$(invoke_signer "$results" 0 0 "$workspace/assets/qualification" 2>&1); then
  fail "signer wrote qualification evidence inside signed assets"
fi
printf '%s\n' "$nested_rejection" | grep -Fq 'qualification output must remain outside the signed asset inventory' || fail "nested output was rejected for the wrong reason"

printf '%s\n' 'qualification record canonical signing and fail-closed tests passed'
