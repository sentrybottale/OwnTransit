#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'sign-candidate-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-sign-candidate-test.XXXXXX")
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

write_native_paths() {
  cat <<'EOF'
BUILD-INPUTS
LICENSE
RELEASE-MANIFEST.json
SOURCE-MANIFEST.txt
artifacts/owntransit-connector-linux-amd64
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
artifacts/owntransitctl-linux-arm64
evidence/PROVENANCE.json
evidence/THIRD_PARTY_LICENSES.txt
evidence/owntransit-connector-linux-amd64.spdx.json
evidence/owntransit-connector-linux-arm64.spdx.json
evidence/owntransit-darwin-arm64.spdx.json
evidence/owntransit-launcher-darwin-arm64.spdx.json
evidence/owntransit-linux-amd64.spdx.json
evidence/owntransit-linux-arm64.spdx.json
evidence/owntransit-provision-darwin-arm64.spdx.json
evidence/owntransit-provision-linux-amd64.spdx.json
evidence/owntransit-provision-linux-arm64.spdx.json
evidence/owntransit-relay-linux-amd64.oci.tar.spdx.json
evidence/owntransit-relay-linux-arm64.oci.tar.spdx.json
evidence/owntransitctl-darwin-arm64.spdx.json
evidence/owntransitctl-linux-amd64.spdx.json
evidence/owntransitctl-linux-arm64.spdx.json
packaging/launchd/README.md
packaging/scripts/install.sh
packaging/scripts/install-linux.sh
packaging/scripts/install-macos.sh
packaging/scripts/uninstall-linux.sh
packaging/scripts/uninstall-macos.sh
packaging/systemd/README.md
packaging/systemd/owntransit-connector.service
packaging/systemd/owntransit-relay-exchange-template.service
packaging/systemd/owntransit-relay.service
EOF
}

native_mode() {
  case "$1" in
    artifacts/owntransit-relay-linux-amd64.oci.tar|artifacts/owntransit-relay-linux-arm64.oci.tar) printf '%s\n' 0644 ;;
    artifacts/*|packaging/scripts/*) printf '%s\n' 0755 ;;
    *) printf '%s\n' 0644 ;;
  esac
}

file_mode() {
  if test "$(uname -s)" = Darwin; then
    file_mode_raw=$(stat -f %p -- "$1") || return 1
    case "$file_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
    printf '%o\n' "$((0$file_mode_raw & 07777))"
  else
    stat -c '%a' -- "$1"
  fi
}

verify_checksum_inventory() {
  checksum_root=$1
  checksum_record=$2
  expected_paths=$3
  checksum_label=$4
  observed_paths="$workspace/$checksum_label.paths"
  : > "$observed_paths"
  while IFS= read -r checksum_line; do
    digest=${checksum_line%%  *}
    relative=${checksum_line#"$digest  "}
    test "$checksum_line" = "$digest  $relative" || fail "$checksum_label contains a non-canonical line"
    case "$digest" in ''|*[!0-9a-f]*) fail "$checksum_label contains an invalid digest" ;; esac
    test "${#digest}" -eq 64 || fail "$checksum_label contains a digest with the wrong length"
    case "$relative" in ''|/*|../*|*/../*|*/..|*//*|*[!A-Za-z0-9._/+:-]*) fail "$checksum_label contains an unsafe path" ;; esac
    printf '%s\n' "$relative" >> "$observed_paths"
    test "$(sha256_file "$checksum_root/$relative")" = "$digest" || fail "$checksum_label digest mismatch: $relative"
  done < "$checksum_record"
  cmp -s "$expected_paths" "$observed_paths" || fail "$checksum_label does not cover the exact expected inventory"
}

snapshot_tree() {
  snapshot_root=$1
  snapshot_output=$2
  (
    cd "$snapshot_root"
    find . -print | LC_ALL=C sort |
      while IFS= read -r relative; do
        if test -d "$relative"; then
          printf 'd %s %s\n' "$(file_mode "$relative")" "$relative"
        else
          printf 'f %s %s %s\n' "$(file_mode "$relative")" "$(sha256_file "$relative")" "$relative"
        fi
      done
  ) > "$snapshot_output"
}

mkdir -m 0700 "$workspace/keys" "$workspace/output-parent" "$workspace/source"
distribution_key="$workspace/keys/distribution"
ssh-keygen -q -t ed25519 -N '' -f "$distribution_key"
chmod 0600 "$distribution_key"
distribution_public_key="$distribution_key.pub"
public_fields=$(awk '{print $1 " " $2}' "$distribution_public_key")
printf '%s\n' "owntransit-release $public_fields" "owntransit-source $public_fields" > "$workspace/keys/allowed_signers"
printf '%s\n' release-public > "$workspace/keys/release-public.pem"
printf '%s\n' release-private > "$workspace/keys/release-private.pem"
printf '%s\n' policy-public > "$workspace/keys/policy-public.pem"
printf '%s\n' policy-private > "$workspace/keys/policy-private.pem"
chmod 0600 "$workspace/keys/release-private.pem" "$workspace/keys/policy-private.pem"

mkdir -p "$workspace/source/cmd/example" "$workspace/source/internal/example" "$workspace/source/tools"
printf '%s\n' 'module example.invalid/owntransit-test' '' 'go 1.26' > "$workspace/source/go.mod"
: > "$workspace/source/go.sum"
printf '%s\n' 'package main' 'func main() {}' > "$workspace/source/cmd/example/main.go"
printf '%s\n' 'package example' > "$workspace/source/internal/example/example.go"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$workspace/source/tools/example.sh"
chmod 0755 "$workspace/source/tools/example.sh"
printf '%s\n' 'Apache License Version 2.0' > "$workspace/source/LICENSE"
printf '%s\n' 'No third-party notices.' > "$workspace/source/THIRD_PARTY_NOTICES.md"
printf '%s\n' '# Changelog' '' '## [0.1.0-rc.1]' '' '## [0.1.0]' > "$workspace/source/CHANGELOG.md"
source_date_epoch=1700000000
git -C "$workspace/source" init -q
git -C "$workspace/source" config user.email test@example.invalid
git -C "$workspace/source" config user.name 'OwnTransit Test'
git -C "$workspace/source" config tar.umask 0000
git -C "$workspace/source" add .
GIT_AUTHOR_DATE="@$source_date_epoch +0000" GIT_COMMITTER_DATE="@$source_date_epoch +0000" \
  git -C "$workspace/source" commit -q -m fixture
source_commit=$(git -C "$workspace/source" rev-parse HEAD)

bundle="$workspace/bundle"
native_paths="$workspace/native-paths"
write_native_paths | LC_ALL=C sort > "$native_paths"
mkdir -m 0755 "$bundle"
while IFS= read -r relative; do
  case "$relative" in */*) mkdir -p "$bundle/${relative%/*}" ;; esac
done < "$native_paths"
find "$bundle" -type d -exec chmod 0755 {} \;

printf '%s\n' fixture-source-manifest > "$bundle/SOURCE-MANIFEST.txt"
source_manifest_sha256=$(sha256_file "$bundle/SOURCE-MANIFEST.txt")
release_id=$(printf 'b%051d' 0 | tr 0 a)
version=0.1.0-rc.1
printf '%s\n' \
  "version=$version" \
  "release_id=$release_id" \
  'release_sequence=1' \
  "source_commit=$source_commit" \
  "source_date_epoch=$source_date_epoch" \
  "source_manifest_sha256=$source_manifest_sha256" > "$bundle/BUILD-INPUTS"
printf '%s\n' \
  "{\"schema\":\"owntransit.software-release.v1\",\"product\":\"owntransit\",\"version\":\"$version\",\"release_id\":\"$release_id\",\"sequence\":1,\"created_unix\":$source_date_epoch,\"minimum_lifecycle\":2,\"source\":{\"repository\":\"https://github.com/sentrybottale/owntransit\",\"commit\":\"$source_commit\",\"dirty\":false,\"source_manifest_sha256\":\"$source_manifest_sha256\"},\"toolchain\":{\"go_version\":\"go1.26.7\",\"builder_image\":\"fixture\"}}" > "$bundle/RELEASE-MANIFEST.json"

while IFS= read -r relative; do
  case "$relative" in BUILD-INPUTS|RELEASE-MANIFEST.json|SOURCE-MANIFEST.txt) continue ;; esac
  printf 'sign-candidate fixture: %s\n' "$relative" > "$bundle/$relative"
done < "$native_paths"
while IFS= read -r relative; do
  chmod "$(native_mode "$relative")" "$bundle/$relative"
done < "$native_paths"
(
  cd "$bundle"
  while IFS= read -r relative; do
    printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
  done < "$native_paths"
) > "$bundle/SHA256SUMS"
chmod 0644 "$bundle/SHA256SUMS"

candidate="$workspace/candidate.json"
printf '%s\n' \
  "{\"schema\":\"owntransit.release-candidate-ledger.v1\",\"status\":\"qualification-only\",\"version\":\"$version\",\"release_id\":\"$release_id\",\"release_sequence\":1,\"policy_sequence\":1,\"minimum_release_sequence\":1,\"minimum_lifecycle\":2,\"source_commit\":\"$source_commit\",\"source_date_epoch\":$source_date_epoch}" \
  > "$candidate"
chmod 0600 "$candidate"

advanced_candidate="$workspace/candidate-policy-2.json"
printf '%s\n' \
  "{\"schema\":\"owntransit.release-candidate-ledger.v1\",\"status\":\"qualification-only\",\"version\":\"$version\",\"release_id\":\"$release_id\",\"release_sequence\":1,\"policy_sequence\":2,\"minimum_release_sequence\":1,\"minimum_lifecycle\":2,\"source_commit\":\"$source_commit\",\"source_date_epoch\":$source_date_epoch}" \
  > "$advanced_candidate"
chmod 0600 "$advanced_candidate"

fake_releasectl="$workspace/fake-releasectl"
cat > "$fake_releasectl" <<'EOF'
#!/bin/sh
set -eu
command_name=$1
shift
printf '%s\n' "$command_name" >> "$(dirname "$0")/fake-releasectl.calls"
argument() {
  wanted=$1
  shift
  while test "$#" -gt 0; do
    if test "$1" = "$wanted"; then printf '%s\n' "$2"; return 0; fi
    shift 2
  done
  return 1
}
case "$command_name" in
  candidate-verify)
    selected_candidate=$(argument --candidate "$@")
    selected_bundle=$(argument --bundle "$@")
    selected_source=$(argument --source-root "$@")
    test -s "$selected_candidate"
    version=$(awk -F= '$1 == "version" {print $2}' "$selected_bundle/BUILD-INPUTS")
    release_id=$(awk -F= '$1 == "release_id" {print $2}' "$selected_bundle/BUILD-INPUTS")
    sequence=$(awk -F= '$1 == "release_sequence" {print $2}' "$selected_bundle/BUILD-INPUTS")
    source_commit=$(awk -F= '$1 == "source_commit" {print $2}' "$selected_bundle/BUILD-INPUTS")
    source_date_epoch=$(awk -F= '$1 == "source_date_epoch" {print $2}' "$selected_bundle/BUILD-INPUTS")
    test "$(git -C "$selected_source" status --porcelain=v1 --untracked-files=all)" = ''
    test "$(git -C "$selected_source" rev-parse --verify 'HEAD^{commit}')" = "$source_commit"
    test "$(git -C "$selected_source" show -s --format=%ct "$source_commit")" = "$source_date_epoch"
    policy_sequence=$(argument --policy-sequence "$@")
    release_floor=$(argument --release-floor "$@")
    lifecycle_floor=$(argument --lifecycle-floor "$@")
    expected_candidate=$(printf '{"schema":"owntransit.release-candidate-ledger.v1","status":"qualification-only","version":"%s","release_id":"%s","release_sequence":%s,"policy_sequence":%s,"minimum_release_sequence":%s,"minimum_lifecycle":%s,"source_commit":"%s","source_date_epoch":%s}' \
      "$version" "$release_id" "$sequence" "$policy_sequence" "$release_floor" "$lifecycle_floor" "$source_commit" "$source_date_epoch")
    test "$(cat "$selected_candidate")" = "$expected_candidate"
    printf 'verified qualification-only candidate version=%s release_id=%s release_sequence=%s policy_sequence=%s minimum_release_sequence=%s minimum_lifecycle=%s source_commit=%s source_date_epoch=%s\n' \
      "$version" "$release_id" "$sequence" "$policy_sequence" "$release_floor" "$lifecycle_floor" "$source_commit" "$source_date_epoch"
    ;;
  public-key-id)
    key=$(argument --public-key "$@")
    case "$(sed -n '1p' "$key")" in
      release-public) printf '%s\n' sha256/release ;;
      policy-public) printf '%s\n' sha256/policy ;;
      *) printf '%s\n' sha256/same ;;
    esac
    ;;
  sign-manifest|sign-policy)
    out=$(argument --out "$@")
    printf '%s\n' "$command_name-signature" > "$out"
    chmod 0644 "$out"
    ;;
  verify-bundle)
    selected_bundle=$(argument --bundle "$@")
    release_id=$(awk -F= '$1 == "release_id" {print $2}' "$selected_bundle/BUILD-INPUTS")
    sequence=$(awk -F= '$1 == "release_sequence" {print $2}' "$selected_bundle/BUILD-INPUTS")
    printf 'verified release %s sequence %s key sha256/release\n' "$release_id" "$sequence"
    ;;
  policy)
    out=$(argument --out "$@")
    sequence=$(argument --sequence "$@")
    release_floor=$(argument --release-floor "$@")
    lifecycle_floor=$(argument --lifecycle-floor "$@")
    printf '{"schema":"fixture-policy","sequence":%s,"minimum_release_sequence":%s,"minimum_lifecycle":%s}\n' \
      "$sequence" "$release_floor" "$lifecycle_floor" > "$out"
    chmod 0644 "$out"
    ;;
  verify-policy)
    selected_policy=$(argument --policy "$@")
    anchor_policy_sequence=$(argument --anchor-policy-sequence "$@" 2>/dev/null || printf '%s\n' 0)
    anchor_release_floor=$(argument --anchor-release-floor "$@" 2>/dev/null || printf '%s\n' 0)
    anchor_lifecycle_floor=$(argument --anchor-lifecycle-floor "$@" 2>/dev/null || printf '%s\n' 0)
    policy_values=$(sed -n 's/^{"schema":"fixture-policy","sequence":\([0-9][0-9]*\),"minimum_release_sequence":\([0-9][0-9]*\),"minimum_lifecycle":\([0-9][0-9]*\)}$/\1 \2 \3/p' "$selected_policy")
    test -n "$policy_values"
    set -- $policy_values
    test "$#" -eq 3
    policy_sequence=$1
    release_floor=$2
    lifecycle_floor=$3
    test "$policy_sequence" -gt "$anchor_policy_sequence"
    test "$release_floor" -ge "$anchor_release_floor"
    test "$lifecycle_floor" -ge "$anchor_lifecycle_floor"
    printf 'policy=%s anchor=%s/%s/%s\n' "$policy_sequence" "$anchor_policy_sequence" "$anchor_release_floor" "$anchor_lifecycle_floor" \
      >> "$(dirname "$0")/fake-releasectl.policy-anchors"
    printf '{"schema":"owntransit.release-policy-anchor.v1","highest_policy_sequence":%s,"minimum_release_sequence":%s,"minimum_lifecycle":%s,"tombstoned_release_ids":null}\n' \
      "$policy_sequence" "$release_floor" "$lifecycle_floor"
    ;;
  *) exit 64 ;;
esac
EOF
chmod 0755 "$fake_releasectl"

signer="$project_root/scripts/release/sign-candidate.sh"
invoke_signer() {
  selected_policy_public=$1
  selected_output=$2
  selected_allowed_signers=${3:-$workspace/keys/allowed_signers}
  selected_policy_sequence=${4:-1}
  selected_release_floor=${5:-1}
  selected_lifecycle_floor=${6:-2}
  selected_anchor_policy_sequence=${7:-0}
  selected_anchor_release_floor=${8:-0}
  selected_anchor_lifecycle_floor=${9:-0}
  selected_candidate=${10:-$candidate}
  selected_anchor_policy_key_id=${11:-}
  selected_anchor_tombstones=${12:-}
  selected_source_root=${13:-$workspace/source}
  selected_source_commit=${14:-$source_commit}
  set -- "$signer" \
    --bundle "$bundle" \
    --candidate "$selected_candidate" \
    --releasectl "$fake_releasectl" \
    --release-private-key "$workspace/keys/release-private.pem" \
    --release-public-key "$workspace/keys/release-public.pem" \
    --policy-private-key "$workspace/keys/policy-private.pem" \
    --policy-public-key "$selected_policy_public" \
    --distribution-key "$distribution_key" \
    --distribution-public-key "$distribution_public_key" \
    --allowed-signers "$selected_allowed_signers" \
    --source-root "$selected_source_root" \
    --version "$version" \
    --source-commit "$selected_source_commit" \
    --policy-sequence "$selected_policy_sequence" \
    --release-floor "$selected_release_floor" \
    --lifecycle-floor "$selected_lifecycle_floor" \
    --anchor-policy-sequence "$selected_anchor_policy_sequence" \
    --anchor-release-floor "$selected_anchor_release_floor" \
    --anchor-lifecycle-floor "$selected_anchor_lifecycle_floor" \
    --output "$selected_output"
  if test -n "$selected_anchor_policy_key_id"; then
    set -- "$@" --anchor-policy-key-id "$selected_anchor_policy_key_id"
  fi
  if test -n "$selected_anchor_tombstones"; then
    set -- "$@" --anchor-tombstones "$selected_anchor_tombstones"
  fi
  "$@"
}

output="$workspace/output-parent/candidate"
missing_changelog_source="$workspace/source-missing-changelog"
cp -R "$workspace/source" "$missing_changelog_source"
printf '%s\n' '# Changelog' '' '## [0.1.0]' > "$missing_changelog_source/CHANGELOG.md"
git -C "$missing_changelog_source" add CHANGELOG.md
GIT_AUTHOR_DATE="@$source_date_epoch +0000" GIT_COMMITTER_DATE="@$source_date_epoch +0000" \
  git -C "$missing_changelog_source" commit -q -m missing-release-heading
missing_changelog_commit=$(git -C "$missing_changelog_source" rev-parse HEAD)
# Leave a misleading valid working-tree heading in place: the signer must read
# the selected commit, not these uncommitted bytes.
cp "$workspace/source/CHANGELOG.md" "$missing_changelog_source/CHANGELOG.md"
if changelog_rejection=$(invoke_signer "$workspace/keys/policy-public.pem" \
  "$workspace/output-parent/rejected-changelog" "$workspace/keys/allowed_signers" \
  1 1 2 0 0 0 "$candidate" '' '' "$missing_changelog_source" "$missing_changelog_commit" 2>&1); then
  fail "candidate signing accepted a commit without its exact changelog release heading"
fi
printf '%s\n' "$changelog_rejection" | grep -Fq "committed CHANGELOG.md has no exact release heading for $version" ||
  fail "missing changelog release heading was rejected for the wrong reason: $changelog_rejection"
test ! -e "$workspace/output-parent/rejected-changelog" || fail "missing changelog release heading created output"

invoke_signer "$workspace/keys/policy-public.pem" "$output" > "$workspace/sign-candidate.out"
grep -Fq "created signed candidate handoff: $output" "$workspace/sign-candidate.out" || fail "positive conductor did not report its atomic output"
grep -Fq "release_id=$release_id" "$workspace/sign-candidate.out" || fail "positive conductor reported the wrong release ID"
expected_releasectl_calls="$workspace/expected-releasectl.calls"
printf '%s\n' \
  public-key-id \
  public-key-id \
  public-key-id \
  public-key-id \
  candidate-verify \
  sign-manifest \
  verify-bundle \
  policy \
  sign-policy \
  verify-policy \
  verify-bundle \
  verify-policy \
  verify-bundle > "$expected_releasectl_calls"
cmp -s "$expected_releasectl_calls" "$workspace/fake-releasectl.calls" || fail "positive conductor did not invoke the exact release/policy component sequence"
printf '%s\n' 'policy=1 anchor=0/0/0' 'policy=1 anchor=0/0/0' > "$workspace/expected-policy-anchors"
cmp -s "$workspace/expected-policy-anchors" "$workspace/fake-releasectl.policy-anchors" ||
  fail "initial conductor did not verify policy twice against the exact empty anchor"

chmod 1644 "$bundle/LICENSE"
special_mode_output="$workspace/output-parent/rejected-special-mode"
if special_mode_rejection=$(invoke_signer "$workspace/keys/policy-public.pem" "$special_mode_output" 2>&1); then
  fail "signing conductor accepted a native member with special mode bits"
fi
printf '%s\n' "$special_mode_rejection" | grep -Fq 'input-bundle member has special or invalid mode bits: LICENSE' ||
  fail "special native member was rejected for the wrong reason: $special_mode_rejection"
test ! -e "$special_mode_output" || fail "special-mode rejection created output"
chmod 0644 "$bundle/LICENSE"

advanced_output="$workspace/output-parent/advanced-candidate"
invoke_signer "$workspace/keys/policy-public.pem" "$advanced_output" "$workspace/keys/allowed_signers" \
  2 1 2 1 1 2 "$advanced_candidate" sha256/policy none > "$workspace/sign-candidate-advanced.out"
grep -Fq "created signed candidate handoff: $advanced_output" "$workspace/sign-candidate-advanced.out" ||
  fail "policy-advance conductor did not report its atomic output"
grep -Fq '"sequence":2' "$advanced_output/assets/RELEASE-POLICY.json" || fail "advanced handoff carries another policy sequence"
printf '%s\n' \
  'policy=1 anchor=0/0/0' \
  'policy=1 anchor=0/0/0' \
  'policy=2 anchor=1/1/2' \
  'policy=2 anchor=1/1/2' > "$workspace/expected-policy-anchors"
cmp -s "$workspace/expected-policy-anchors" "$workspace/fake-releasectl.policy-anchors" ||
  fail "policy-advance conductor did not verify policy twice against the exact persisted anchor"

rejected_empty_advance="$workspace/output-parent/rejected-empty-anchor-advance"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_empty_advance" "$workspace/keys/allowed_signers" 2 1 2 0 0 0 >/dev/null 2>&1; then
  fail "empty-anchor path accepted a policy sequence other than one"
fi
test ! -e "$rejected_empty_advance" || fail "rejected empty-anchor advance created output"

rejected_partial_anchor="$workspace/output-parent/rejected-partial-anchor"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_partial_anchor" "$workspace/keys/allowed_signers" 2 1 2 1 0 2 >/dev/null 2>&1; then
  fail "policy advance accepted a partial persisted anchor"
fi
test ! -e "$rejected_partial_anchor" || fail "rejected partial anchor created output"

rejected_policy_replay="$workspace/output-parent/rejected-policy-replay"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_policy_replay" "$workspace/keys/allowed_signers" \
  1 1 2 1 1 2 "$candidate" sha256/policy none >/dev/null 2>&1; then
  fail "policy advance accepted a replayed policy sequence"
fi
test ! -e "$rejected_policy_replay" || fail "rejected policy replay created output"

rejected_release_floor="$workspace/output-parent/rejected-weaker-release-floor"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_release_floor" "$workspace/keys/allowed_signers" \
  2 1 2 1 2 2 "$advanced_candidate" sha256/policy none >/dev/null 2>&1; then
  fail "policy advance weakened the persisted release floor"
fi
test ! -e "$rejected_release_floor" || fail "weaker-release-floor rejection created output"

rejected_lifecycle_floor="$workspace/output-parent/rejected-weaker-lifecycle-floor"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_lifecycle_floor" "$workspace/keys/allowed_signers" \
  2 1 1 1 1 2 "$advanced_candidate" sha256/policy none >/dev/null 2>&1; then
  fail "policy advance weakened the persisted lifecycle floor"
fi
test ! -e "$rejected_lifecycle_floor" || fail "weaker-lifecycle-floor rejection created output"

rejected_policy_key="$workspace/output-parent/rejected-policy-key-change"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_policy_key" "$workspace/keys/allowed_signers" \
  2 1 2 1 1 2 "$advanced_candidate" sha256/not-the-pinned-key none >/dev/null 2>&1; then
  fail "policy advance changed the pinned policy key"
fi
test ! -e "$rejected_policy_key" || fail "policy-key rejection created output"

rejected_missing_policy_key="$workspace/output-parent/rejected-missing-policy-key"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_missing_policy_key" "$workspace/keys/allowed_signers" \
  2 1 2 1 1 2 "$advanced_candidate" '' none >/dev/null 2>&1; then
  fail "policy advance omitted the pinned policy-key ID"
fi
test ! -e "$rejected_missing_policy_key" || fail "missing-policy-key rejection created output"

rejected_implicit_tombstones="$workspace/output-parent/rejected-implicit-tombstones"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_implicit_tombstones" "$workspace/keys/allowed_signers" \
  2 1 2 1 1 2 "$advanced_candidate" sha256/policy >/dev/null 2>&1; then
  fail "policy advance inferred an empty persisted tombstone set"
fi
test ! -e "$rejected_implicit_tombstones" || fail "implicit-tombstone rejection created output"

rejected_nonempty_tombstones="$workspace/output-parent/rejected-nonempty-tombstones"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_nonempty_tombstones" "$workspace/keys/allowed_signers" \
  2 1 2 1 1 2 "$advanced_candidate" sha256/policy present >/dev/null 2>&1; then
  fail "scalar policy advance accepted a nonempty persisted tombstone set"
fi
test ! -e "$rejected_nonempty_tombstones" || fail "nonempty-tombstone rejection created output"

rejected_empty_anchor_key="$workspace/output-parent/rejected-empty-anchor-key"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_empty_anchor_key" "$workspace/keys/allowed_signers" \
  1 1 2 0 0 0 "$candidate" sha256/policy >/dev/null 2>&1; then
  fail "empty-anchor path accepted a persisted policy-key claim"
fi
test ! -e "$rejected_empty_anchor_key" || fail "empty-anchor key rejection created output"

rejected_empty_anchor_tombstones="$workspace/output-parent/rejected-empty-anchor-tombstones"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_empty_anchor_tombstones" "$workspace/keys/allowed_signers" \
  1 1 2 0 0 0 "$candidate" '' none >/dev/null 2>&1; then
  fail "empty-anchor path accepted a persisted tombstone claim"
fi
test ! -e "$rejected_empty_anchor_tombstones" || fail "empty-anchor tombstone rejection created output"

rejected_malformed_anchor="$workspace/output-parent/rejected-malformed-anchor"
if invoke_signer "$workspace/keys/policy-public.pem" "$rejected_malformed_anchor" "$workspace/keys/allowed_signers" \
  2 1 2 01 1 2 "$advanced_candidate" sha256/policy none >/dev/null 2>&1; then
  fail "policy advance accepted a noncanonical anchor sequence"
fi
test ! -e "$rejected_malformed_anchor" || fail "malformed-anchor rejection created output"

extra_allowed_signers="$workspace/keys/allowed_signers-extra"
{
  cat "$workspace/keys/allowed_signers"
  printf '%s\n' "unexpected-release $public_fields"
} > "$extra_allowed_signers"
if extra_allowed_output=$(invoke_signer "$workspace/keys/policy-public.pem" "$workspace/output-parent/rejected-extra-allowed" "$extra_allowed_signers" 2>&1); then
  fail "signing conductor accepted an extra bootstrap authority"
fi
printf '%s\n' "$extra_allowed_output" | grep -Fq 'allowed-signers must contain exactly the two canonical v1 principals' ||
  fail "extra bootstrap authority was rejected for the wrong reason"
test ! -e "$workspace/output-parent/rejected-extra-allowed" || fail "rejected extra-authority output was created"

ssh-keygen -q -t ed25519 -N '' -f "$workspace/keys/other-distribution"
other_public_fields=$(awk '{print $1 " " $2}' "$workspace/keys/other-distribution.pub")
wrong_source_allowed_signers="$workspace/keys/allowed_signers-wrong-source"
printf '%s\n' "owntransit-release $public_fields" "owntransit-source $other_public_fields" > "$wrong_source_allowed_signers"
if wrong_source_output=$(invoke_signer "$workspace/keys/policy-public.pem" "$workspace/output-parent/rejected-wrong-source" "$wrong_source_allowed_signers" 2>&1); then
  fail "signing conductor accepted a source principal under another key"
fi
printf '%s\n' "$wrong_source_output" | grep -Fq 'allowed-signers source principal is not bound to the distribution public key' ||
  fail "wrong source bootstrap authority was rejected for the wrong reason"
test ! -e "$workspace/output-parent/rejected-wrong-source" || fail "rejected wrong-source output was created"

expected_directories="$workspace/expected-output-directories"
printf '%s\n' . ./assets ./trust > "$expected_directories"
actual_directories="$workspace/actual-output-directories"
(
  cd "$output"
  find . -type d -print | LC_ALL=C sort
) > "$actual_directories"
cmp -s "$expected_directories" "$actual_directories" || fail "signed handoff has an unexpected directory inventory"

expected_assets="$workspace/expected-assets"
printf '%s\n' \
  NATIVE-SHA256SUMS.sig \
  RELEASE-CANDIDATE.json \
  RELEASE-MANIFEST.json \
  RELEASE-MANIFEST.sig \
  RELEASE-POLICY.json \
  RELEASE-POLICY.sig \
  SHA256SUMS \
  "owntransit-$version-native.tar.gz" \
  "owntransit-$version-source.tar.gz" \
  owntransit.rb | LC_ALL=C sort > "$expected_assets"
actual_assets="$workspace/actual-assets"
(
  cd "$output/assets"
  find . -type f -print | sed 's|^\./||' | LC_ALL=C sort
) > "$actual_assets"
cmp -s "$expected_assets" "$actual_assets" || fail "signed handoff has an unexpected asset inventory"

expected_trust="$workspace/expected-trust"
printf '%s\n' \
  SHA256SUMS.sig \
  TRUST-STATEMENT.txt \
  TRUST-STATEMENT.txt.sig \
  allowed_signers \
  distribution-public.key \
  policy-public.pem \
  release-public.pem | LC_ALL=C sort > "$expected_trust"
actual_trust="$workspace/actual-trust"
(
  cd "$output/trust"
  find . -type f -print | sed 's|^\./||' | LC_ALL=C sort
) > "$actual_trust"
cmp -s "$expected_trust" "$actual_trust" || fail "signed handoff has an unexpected trust inventory"
cmp -s "$workspace/keys/release-public.pem" "$output/trust/release-public.pem" || fail "release public trust copy changed"
cmp -s "$workspace/keys/policy-public.pem" "$output/trust/policy-public.pem" || fail "policy public trust copy changed"
cmp -s "$distribution_public_key" "$output/trust/distribution-public.key" || fail "distribution public trust copy changed"
cmp -s "$workspace/keys/allowed_signers" "$output/trust/allowed_signers" || fail "allowed-signers trust copy changed"
cmp -s "$candidate" "$output/assets/RELEASE-CANDIDATE.json" || fail "candidate ledger copy changed"

expected_asset_checksums="$workspace/expected-asset-checksums"
grep -v '^SHA256SUMS$' "$expected_assets" > "$expected_asset_checksums"
verify_checksum_inventory "$output/assets" "$output/assets/SHA256SUMS" "$expected_asset_checksums" outer-assets
outer_checksum_sha256=$(sha256_file "$output/assets/SHA256SUMS")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$output/assets/SHA256SUMS" \
  --sha256 "$outer_checksum_sha256" \
  --signature "$output/trust/SHA256SUMS.sig" \
  --allowed-signers "$output/trust/allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "outer asset SSHSIG did not verify"
expected_trust_statement="$workspace/expected-trust-statement"
printf '%s\n' \
  'schema=owntransit.release-trust.v1' \
  'product=owntransit' \
  "version=$version" \
  "release_id=$release_id" \
  "source_commit=$source_commit" \
  "distribution_public_sha256=$(sha256_file "$output/trust/distribution-public.key")" \
  "release_public_sha256=$(sha256_file "$output/trust/release-public.pem")" \
  "policy_public_sha256=$(sha256_file "$output/trust/policy-public.pem")" \
  "allowed_signers_sha256=$(sha256_file "$output/trust/allowed_signers")" \
  "outer_sha256sums_sha256=$outer_checksum_sha256" \
  > "$expected_trust_statement"
cmp -s "$expected_trust_statement" "$output/trust/TRUST-STATEMENT.txt" || fail "trust statement is not the canonical trust/identity binding"
trust_statement_sha256=$(sha256_file "$output/trust/TRUST-STATEMENT.txt")
grep -Fq "trust_statement_sha256=$trust_statement_sha256" "$workspace/sign-candidate.out" || fail "positive conductor did not report the trust-statement handle"
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$output/trust/TRUST-STATEMENT.txt" \
  --sha256 "$trust_statement_sha256" \
  --signature "$output/trust/TRUST-STATEMENT.txt.sig" \
  --allowed-signers "$output/trust/allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-trust-v1 >/dev/null || fail "trust statement SSHSIG did not verify"

native_extract="$workspace/native-extract"
mkdir "$native_extract"
gzip -cd "$output/assets/owntransit-$version-native.tar.gz" | tar -xpf - -C "$native_extract"
native_root="$native_extract/owntransit-$version-native"
test -d "$native_root" || fail "native archive omitted its canonical root"
expected_native_files="$workspace/expected-native-files"
{
  cat "$native_paths"
  printf '%s\n' SHA256SUMS
} | LC_ALL=C sort > "$expected_native_files"
actual_native_files="$workspace/actual-native-files"
(
  cd "$native_root"
  find . -type f -print | sed 's|^\./||' | LC_ALL=C sort
) > "$actual_native_files"
cmp -s "$expected_native_files" "$actual_native_files" || fail "native archive does not contain the exact fixed file inventory"
verify_checksum_inventory "$native_root" "$native_root/SHA256SUMS" "$native_paths" inner-native
native_checksum_sha256=$(sha256_file "$native_root/SHA256SUMS")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$native_root/SHA256SUMS" \
  --sha256 "$native_checksum_sha256" \
  --signature "$output/assets/NATIVE-SHA256SUMS.sig" \
  --allowed-signers "$output/trust/allowed_signers" \
  --signer owntransit-release \
  --namespace owntransit-release-v1 >/dev/null || fail "inner native SSHSIG did not verify"
cmp -s "$native_root/RELEASE-MANIFEST.json" "$output/assets/RELEASE-MANIFEST.json" || fail "external and archived release manifests differ"
while IFS= read -r relative; do
  cmp -s "$bundle/$relative" "$native_root/$relative" || fail "native archive changed $relative"
  expected_mode=$(native_mode "$relative")
  expected_mode=${expected_mode#0}
  test "$(file_mode "$native_root/$relative")" = "$expected_mode" || fail "native archive changed mode for $relative"
done < "$native_paths"
test "$(file_mode "$native_root/SHA256SUMS")" = 644 || fail "native archive changed SHA256SUMS mode"
find "$native_root" -type d -print > "$workspace/native-directories"
while IFS= read -r native_directory; do
  test "$(file_mode "$native_directory")" = 755 || fail "native archive contains a directory not mode 0755"
done < "$workspace/native-directories"

source_extract="$workspace/source-extract"
mkdir "$source_extract"
tar -xzpf "$output/assets/owntransit-$version-source.tar.gz" -C "$source_extract"
source_archive_root="$source_extract/owntransit-$version"
unexpected_source_member=$(find "$source_archive_root" ! -type f ! -type d -print)
test -z "$unexpected_source_member" || fail "source archive contains a symlink or special entry"
find "$source_archive_root" -type d -print > "$workspace/source-directories"
while IFS= read -r source_directory; do
  test "$(file_mode "$source_directory")" = 755 || fail "source archive contains a directory not mode 0755"
done < "$workspace/source-directories"
git -C "$workspace/source" ls-tree -r "$source_commit" > "$workspace/source-tree-modes"
while IFS="$(printf '\t')" read -r tree_metadata relative; do
  tree_mode=${tree_metadata%% *}
  case "$tree_mode" in
    100644) expected_mode=644 ;;
    100755) expected_mode=755 ;;
    *) fail "source fixture contains unsupported Git mode $tree_mode" ;;
  esac
  test "$(file_mode "$source_archive_root/$relative")" = "$expected_mode" ||
    fail "source archive changed tracked mode for $relative"
done < "$workspace/source-tree-modes"
test "$(file_mode "$source_archive_root/SOURCE-MANIFEST.txt")" = 644 ||
  fail "source archive changed generated manifest mode"
test "$(file_mode "$source_archive_root/SOURCE-MANIFEST.txt.sig")" = 644 ||
  fail "source archive changed generated signature mode"
"$project_root/packaging/homebrew/verify-source-tree.sh" \
  --source "$source_archive_root" \
  --allowed-signers "$output/trust/allowed_signers" \
  --signer owntransit-source >/dev/null || fail "signed source archive did not verify"

command -v ruby >/dev/null 2>&1 || fail "ruby is required for formula syntax verification"
ruby -c "$output/assets/owntransit.rb" >/dev/null || fail "rendered formula is not valid Ruby"
source_archive_sha256=$(sha256_file "$output/assets/owntransit-$version-source.tar.gz")
grep -Fq "sha256 \"$source_archive_sha256\"" "$output/assets/owntransit.rb" || fail "formula source digest does not match the signed source archive"
grep -Fq "https://github.com/sentrybottale/owntransit/releases/download/v$version/owntransit-$version-source.tar.gz" "$output/assets/owntransit.rb" || fail "formula source URL is not the canonical release asset"
test -z "$(grep -E '\{\{[A-Z0-9_]+\}\}' "$output/assets/owntransit.rb" || true)" || fail "formula contains an unresolved template value"

before_no_overwrite="$workspace/before-no-overwrite"
after_no_overwrite="$workspace/after-no-overwrite"
snapshot_tree "$output" "$before_no_overwrite"
if overwrite_rejection=$(invoke_signer "$workspace/keys/policy-public.pem" "$output" 2>&1); then
  fail "positive conductor overwrote an existing handoff"
fi
printf '%s\n' "$overwrite_rejection" | grep -Fq 'output already exists' || fail "existing handoff was rejected for the wrong reason"
snapshot_tree "$output" "$after_no_overwrite"
cmp -s "$before_no_overwrite" "$after_no_overwrite" || fail "failed overwrite attempt changed the signed handoff"

printf '%s\n' release-public > "$workspace/keys/policy-public-overlap.pem"
overlap_key_output="$workspace/output-parent/rejected-overlap-key"
if "$project_root/scripts/release/sign-candidate.sh" \
  --bundle "$bundle" --candidate "$candidate" --releasectl "$fake_releasectl" \
  --release-private-key "$workspace/keys/release-private.pem" --release-public-key "$workspace/keys/release-public.pem" \
  --policy-private-key "$workspace/keys/policy-private.pem" --policy-public-key "$workspace/keys/policy-public-overlap.pem" \
  --distribution-key "$distribution_key" --distribution-public-key "$distribution_public_key" \
  --allowed-signers "$workspace/keys/allowed_signers" --source-root "$workspace/source" \
  --version "$version" --source-commit "$source_commit" --policy-sequence 1 --release-floor 1 --lifecycle-floor 1 \
  --output "$overlap_key_output" >/dev/null 2>&1; then
  fail "overlapping release and policy key IDs were accepted"
fi
test ! -e "$overlap_key_output" || fail "rejected overlapping-key output was created"

overlap_output="$bundle/rejected-output"
if "$project_root/scripts/release/sign-candidate.sh" \
  --bundle "$bundle" --candidate "$candidate" --releasectl "$fake_releasectl" \
  --release-private-key "$workspace/keys/release-private.pem" --release-public-key "$workspace/keys/release-public.pem" \
  --policy-private-key "$workspace/keys/policy-private.pem" --policy-public-key "$workspace/keys/policy-public.pem" \
  --distribution-key "$distribution_key" --distribution-public-key "$distribution_public_key" \
  --allowed-signers "$workspace/keys/allowed_signers" --source-root "$workspace/source" \
  --version "$version" --source-commit "$source_commit" --policy-sequence 1 --release-floor 1 --lifecycle-floor 1 \
  --output "$overlap_output" >/dev/null 2>&1; then
  fail "output nested in the bundle was accepted"
fi
test ! -e "$overlap_output" || fail "rejected nested output was created"

preexisting_output="$workspace/output-parent/preexisting"
mkdir "$preexisting_output"
if "$project_root/scripts/release/sign-candidate.sh" \
  --bundle "$bundle" --candidate "$candidate" --releasectl "$fake_releasectl" \
  --release-private-key "$workspace/keys/release-private.pem" --release-public-key "$workspace/keys/release-public.pem" \
  --policy-private-key "$workspace/keys/policy-private.pem" --policy-public-key "$workspace/keys/policy-public.pem" \
  --distribution-key "$distribution_key" --distribution-public-key "$distribution_public_key" \
  --allowed-signers "$workspace/keys/allowed_signers" --source-root "$workspace/source" \
  --version "$version" --source-commit "$source_commit" --policy-sequence 1 --release-floor 1 --lifecycle-floor 1 \
  --output "$preexisting_output" >/dev/null 2>&1; then
  fail "pre-existing output was accepted"
fi

rewrite_bundle_contract() {
  contract_version=$1
  contract_release_sequence=$2
  contract_lifecycle=$3
  printf '%s\n' \
    "version=$contract_version" \
    "release_id=$release_id" \
    "release_sequence=$contract_release_sequence" \
    "source_commit=$source_commit" \
    "source_date_epoch=$source_date_epoch" \
    "source_manifest_sha256=$source_manifest_sha256" > "$bundle/BUILD-INPUTS"
  printf '%s\n' \
    "{\"schema\":\"owntransit.software-release.v1\",\"product\":\"owntransit\",\"version\":\"$contract_version\",\"release_id\":\"$release_id\",\"sequence\":$contract_release_sequence,\"created_unix\":$source_date_epoch,\"minimum_lifecycle\":$contract_lifecycle,\"source\":{\"repository\":\"https://github.com/sentrybottale/owntransit\",\"commit\":\"$source_commit\",\"dirty\":false,\"source_manifest_sha256\":\"$source_manifest_sha256\"},\"toolchain\":{\"go_version\":\"go1.26.7\",\"builder_image\":\"fixture\"}}" > "$bundle/RELEASE-MANIFEST.json"
  rebuilt_checksums="$workspace/rebuilt-native-SHA256SUMS"
  (
    cd "$bundle"
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done < "$native_paths"
  ) > "$rebuilt_checksums"
  mv "$rebuilt_checksums" "$bundle/SHA256SUMS"
  chmod 0644 "$bundle/SHA256SUMS"
}

expect_stable_freeze_rejection() {
  rejection_name=$1
  expected_error=$2
  selected_release_sequence=$3
  selected_policy_sequence=$4
  selected_release_floor=$5
  selected_lifecycle_floor=$6
  rewrite_bundle_contract 0.1.0 "$selected_release_sequence" "$selected_lifecycle_floor"
  rejection_path="$workspace/output-parent/rejected-stable-$rejection_name"
  if rejection_text=$(invoke_signer "$workspace/keys/policy-public.pem" "$rejection_path" "$workspace/keys/allowed_signers" \
    "$selected_policy_sequence" "$selected_release_floor" "$selected_lifecycle_floor" \
    3 5 1 "$stable_candidate" sha256/policy none 2>&1); then
    fail "0.1.0 stable signing accepted the wrong $rejection_name"
  fi
  printf '%s\n' "$rejection_text" | grep -Fq "$expected_error" ||
    fail "0.1.0 stable $rejection_name was rejected for the wrong reason: $rejection_text"
  test ! -e "$rejection_path" || fail "rejected 0.1.0 stable $rejection_name created output"
}

version=0.1.0
stable_candidate="$workspace/candidate-stable.json"
printf '%s\n' \
  "{\"schema\":\"owntransit.release-candidate-ledger.v1\",\"status\":\"qualification-only\",\"version\":\"$version\",\"release_id\":\"$release_id\",\"release_sequence\":11,\"policy_sequence\":7,\"minimum_release_sequence\":11,\"minimum_lifecycle\":1,\"source_commit\":\"$source_commit\",\"source_date_epoch\":$source_date_epoch}" \
  > "$stable_candidate"
chmod 0600 "$stable_candidate"

stable_rejection_sign_calls_before=$(grep -c '^sign-manifest$' "$workspace/fake-releasectl.calls")
expect_stable_freeze_rejection release-sequence \
  'OwnTransit 0.1.0 requires release sequence 11' 10 7 11 1
expect_stable_freeze_rejection policy-sequence \
  'OwnTransit 0.1.0 requires policy sequence 7' 11 6 11 1
expect_stable_freeze_rejection release-floor \
  'OwnTransit 0.1.0 requires release floor 11' 11 7 10 1
expect_stable_freeze_rejection lifecycle-floor \
  'OwnTransit 0.1.0 requires lifecycle floor 1' 11 7 11 2

expect_stable_anchor_rejection() {
  rejection_name=$1
  expected_error=$2
  selected_anchor_policy_sequence=$3
  selected_anchor_release_floor=$4
  selected_anchor_lifecycle_floor=$5
  rewrite_bundle_contract 0.1.0 11 1
  rejection_path="$workspace/output-parent/rejected-stable-$rejection_name"
  if rejection_text=$(invoke_signer "$workspace/keys/policy-public.pem" "$rejection_path" "$workspace/keys/allowed_signers" \
    7 11 1 "$selected_anchor_policy_sequence" "$selected_anchor_release_floor" "$selected_anchor_lifecycle_floor" \
    "$stable_candidate" sha256/policy none 2>&1); then
    fail "0.1.0 stable signing accepted the wrong $rejection_name"
  fi
  printf '%s\n' "$rejection_text" | grep -Fq "$expected_error" ||
    fail "0.1.0 stable $rejection_name was rejected for the wrong reason: $rejection_text"
  test ! -e "$rejection_path" || fail "rejected 0.1.0 stable $rejection_name created output"
}

expect_stable_anchor_rejection anchor-policy-sequence \
  'OwnTransit 0.1.0 requires RC7 anchor policy sequence 3' 4 5 1
expect_stable_anchor_rejection burned-private-candidate-anchor \
  'OwnTransit 0.1.0 requires RC7 anchor policy sequence 3' 5 9 1
expect_stable_anchor_rejection burned-private-scope-candidate-anchor \
  'OwnTransit 0.1.0 requires RC7 anchor policy sequence 3' 6 10 1
expect_stable_anchor_rejection anchor-release-floor \
  'OwnTransit 0.1.0 requires RC7 anchor release floor 5' 3 6 1
expect_stable_anchor_rejection anchor-lifecycle-floor \
  'candidate policy weakens the persisted lifecycle floor' 3 5 2
test "$(grep -c '^sign-manifest$' "$workspace/fake-releasectl.calls")" = "$stable_rejection_sign_calls_before" ||
  fail "a rejected 0.1.0 stable tuple reached a signing operation"

rewrite_bundle_contract 0.1.0 11 1
stable_output="$workspace/output-parent/stable-candidate"
invoke_signer "$workspace/keys/policy-public.pem" "$stable_output" "$workspace/keys/allowed_signers" \
  7 11 1 3 5 1 "$stable_candidate" sha256/policy none > "$workspace/sign-candidate-stable.out"
grep -Fq "created signed candidate handoff: $stable_output" "$workspace/sign-candidate-stable.out" ||
  fail "exact 0.1.0 stable signing tuple did not produce its atomic handoff"
test "$(cat "$stable_output/assets/RELEASE-POLICY.json")" = \
  '{"schema":"fixture-policy","sequence":7,"minimum_release_sequence":11,"minimum_lifecycle":1}' ||
  fail "0.1.0 stable handoff did not preserve the frozen signed policy tuple"

printf '%s\n' 'sign-candidate full-conductor and fail-closed tests passed'
