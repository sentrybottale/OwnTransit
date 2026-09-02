#!/bin/sh
set -eu

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
umask 077

fail() {
  printf 'install-entrypoint-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)

expect_early_rejection() {
  expected_message=$1
  shift
  if early_rejection=$("$@" 2>&1); then
    fail "entrypoint accepted a request expected to fail before privilege checks: $expected_message"
  fi
  printf '%s\n' "$early_rejection" | grep -Fq -- "$expected_message" ||
    fail "entrypoint rejected an early request for the wrong reason: $expected_message"
}

source_entrypoint="$project_root/scripts/release/install.sh"
expect_early_rejection '--bundle may be specified only once' \
  "$source_entrypoint" --bundle /a --bundle /b --assets /c --trust /d --role provisioner
expect_early_rejection '--assets may be specified only once' \
  "$source_entrypoint" --bundle /a --assets /c --assets /e --trust /d --role provisioner
expect_early_rejection '--trust may be specified only once' \
  "$source_entrypoint" --bundle /a --assets /c --trust /d --trust /e --role provisioner
expect_early_rejection '--role may be specified only once' \
  "$source_entrypoint" --bundle /a --assets /c --trust /d --role provisioner --role provisioner
expect_early_rejection '--client-user may be specified only once' \
  "$source_entrypoint" --bundle /a --assets /c --trust /d --role client \
    --client-user fixtureuser --client-user fixtureuser

if test "$(id -u)" -ne 0; then
  nonroot_output="$project_root/.install-entrypoint-nonroot.$$"
  trap 'rm -f -- "$nonroot_output"' EXIT HUP INT TERM
  if "$project_root/scripts/release/install.sh" \
    --bundle "$project_root" \
    --assets "$project_root" \
    --trust "$project_root" \
    --role provisioner >"$nonroot_output" 2>&1; then
    fail "installer entrypoint accepted non-root execution"
  fi
  grep -Fq 'installation requires root' "$nonroot_output" || fail "non-root execution was rejected for the wrong reason"
  rm -f -- "$nonroot_output"
  trap - EXIT HUP INT TERM
  if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    sudo -n "$0" --root-phase
    exit $?
  fi
  printf '%s\n' 'install entrypoint non-root rejection passed; root fixture skipped because passwordless sudo is unavailable'
  exit 0
fi

case "${1:-}" in ''|--root-phase) ;; *) fail "unknown test argument $1" ;; esac
case "$(uname -s)" in
  Darwin) test_workspace_parent=/var/root ;;
  Linux) test_workspace_parent=/root ;;
  *) fail "focused entrypoint test requires macOS or Linux" ;;
esac
workspace=$(mktemp -d "$test_workspace_parent/.owntransit-install-entrypoint-test.XXXXXX")
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

expect_line() {
  expected_line=$1
  selected_output=$2
  grep -Fqx -- "$expected_line" "$selected_output" || fail "installer invocation omitted: $expected_line"
}

expect_rejection() {
  expected_message=$1
  shift
  rejection_output="$workspace/rejection.out"
  if "$@" >"$rejection_output" 2>&1; then
    fail "entrypoint accepted a request expected to fail: $expected_message"
  fi
  grep -Fq -- "$expected_message" "$rejection_output" || fail "entrypoint rejected a request for the wrong reason: $expected_message"
}

bundle="$workspace/native"
assets="$workspace/assets"
trust="$workspace/trust"
keys="$workspace/keys"
mkdir -m 0755 "$bundle" "$assets" "$trust"
mkdir -m 0700 "$keys"
mkdir -m 0755 "$bundle/artifacts" "$bundle/packaging" "$bundle/packaging/scripts"

cp "$project_root/scripts/release/install.sh" "$bundle/packaging/scripts/install.sh"
chmod 0755 "$bundle/packaging/scripts/install.sh"

for platform_installer in install-linux.sh install-macos.sh; do
  cat > "$bundle/packaging/scripts/$platform_installer" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' MOCK_PLATFORM_INSTALLER
while test "$#" -gt 0; do
  printf '%s\n' "$1"
  shift
done
EOF
  chmod 0755 "$bundle/packaging/scripts/$platform_installer"
done

version=0.1.0
release_id=baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
test "${#release_id}" -eq 52 || fail "fixture release ID length is invalid"
printf '%s\n' \
  "version=$version" \
  "release_id=$release_id" \
  'release_sequence=1' \
  'source_commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  'source_date_epoch=1700000000' \
  'source_manifest_sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc' \
  > "$bundle/BUILD-INPUTS"
printf '%s\n' '{"schema":"owntransit.test-release.v1"}' > "$bundle/RELEASE-MANIFEST.json"

for artifact_name in \
  owntransit-darwin-arm64 \
  owntransit-launcher-darwin-arm64 \
  owntransit-linux-amd64 \
  owntransit-connector-linux-amd64 \
  owntransit-relay-linux-amd64.oci.tar \
  owntransitctl-darwin-arm64 \
  owntransitctl-linux-amd64 \
  owntransit-provision-darwin-arm64 \
  owntransit-provision-linux-amd64; do
  printf 'fixture artifact %s\n' "$artifact_name" > "$bundle/artifacts/$artifact_name"
  chmod 0755 "$bundle/artifacts/$artifact_name"
done
chmod 0644 "$bundle/artifacts/owntransit-relay-linux-amd64.oci.tar"

(
  cd "$bundle"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done > SHA256SUMS
)
chmod 0644 "$bundle/SHA256SUMS"

ssh-keygen -q -t ed25519 -N '' -f "$keys/distribution"
public_fields=$(awk '{print $1 " " $2}' "$keys/distribution.pub")
printf '%s\n' "owntransit-release $public_fields" "owntransit-source $public_fields" > "$trust/allowed_signers"
cp "$keys/distribution.pub" "$trust/distribution-public.key"
printf '%s\n' fixture-release-public > "$trust/release-public.pem"
printf '%s\n' fixture-policy-public > "$trust/policy-public.pem"

ssh-keygen -Y sign -q -f "$keys/distribution" -n owntransit-release-v1 "$bundle/SHA256SUMS" >/dev/null
mv "$bundle/SHA256SUMS.sig" "$assets/NATIVE-SHA256SUMS.sig"
cp "$bundle/RELEASE-MANIFEST.json" "$assets/RELEASE-MANIFEST.json"
printf '%s\n' fixture-candidate > "$assets/RELEASE-CANDIDATE.json"
printf '%s\n' fixture-manifest-signature > "$assets/RELEASE-MANIFEST.sig"
printf '%s\n' fixture-policy > "$assets/RELEASE-POLICY.json"
printf '%s\n' fixture-policy-signature > "$assets/RELEASE-POLICY.sig"
printf '%s\n' fixture-native-archive > "$assets/owntransit-$version-native.tar.gz"
printf '%s\n' fixture-source-archive > "$assets/owntransit-$version-source.tar.gz"
printf '%s\n' fixture-formula > "$assets/owntransit.rb"
(
  cd "$assets"
  find . -type f ! -name SHA256SUMS -print | sed 's|^\./||' | LC_ALL=C sort |
    while IFS= read -r relative; do
      printf '%s  %s\n' "$(sha256_file "$relative")" "$relative"
    done > SHA256SUMS
)
chmod 0644 "$assets/SHA256SUMS"
ssh-keygen -Y sign -q -f "$keys/distribution" -n owntransit-release-v1 "$assets/SHA256SUMS" >/dev/null
mv "$assets/SHA256SUMS.sig" "$trust/SHA256SUMS.sig"
printf '%s\n' \
  'schema=owntransit.release-trust.v1' \
  'product=owntransit' \
  "version=$version" \
  "release_id=$release_id" \
  'source_commit=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  "distribution_public_sha256=$(sha256_file "$trust/distribution-public.key")" \
  "release_public_sha256=$(sha256_file "$trust/release-public.pem")" \
  "policy_public_sha256=$(sha256_file "$trust/policy-public.pem")" \
  "allowed_signers_sha256=$(sha256_file "$trust/allowed_signers")" \
  "outer_sha256sums_sha256=$(sha256_file "$assets/SHA256SUMS")" \
  > "$trust/TRUST-STATEMENT.txt"
ssh-keygen -Y sign -q -f "$keys/distribution" -n owntransit-trust-v1 "$trust/TRUST-STATEMENT.txt" >/dev/null
find "$bundle" "$assets" "$trust" -type d -exec chmod 0755 {} \;
find "$bundle" "$assets" "$trust" -type f -exec chmod go-w {} \;
chmod 0700 "$keys"
chmod 0600 "$keys/distribution"

entrypoint="$bundle/packaging/scripts/install.sh"
common_arguments="--bundle $bundle --assets $assets --trust $trust"

case "$(uname -s)/$(uname -m)" in
  Darwin/arm64)
    runtime_role=client
    runtime_artifact=artifacts/owntransit-darwin-arm64
    lifecycle_artifact=artifacts/owntransitctl-darwin-arm64
    runtime_output="$workspace/client.out"
    # shellcheck disable=SC2086
    "$entrypoint" $common_arguments --role client --client-user fixtureuser > "$runtime_output"
    expect_line MOCK_PLATFORM_INSTALLER "$runtime_output"
    expect_line --launcher-sha256 "$runtime_output"
    expect_line "$(sha256_file "$bundle/artifacts/owntransit-launcher-darwin-arm64")" "$runtime_output"
    expect_line --client-user "$runtime_output"
    expect_line fixtureuser "$runtime_output"
    ;;
  Linux/x86_64|Linux/amd64)
    runtime_role=connector
    runtime_artifact=artifacts/owntransit-connector-linux-amd64
    lifecycle_artifact=artifacts/owntransitctl-linux-amd64
    runtime_output="$workspace/connector.out"
    # shellcheck disable=SC2086
    "$entrypoint" $common_arguments --role connector > "$runtime_output"
    expect_line MOCK_PLATFORM_INSTALLER "$runtime_output"
    ;;
  *) fail "focused entrypoint test requires macOS arm64 or Linux amd64" ;;
esac

expect_line --release-id "$runtime_output"
expect_line "$release_id" "$runtime_output"
expect_line --checksums-sha256 "$runtime_output"
expect_line "$(sha256_file "$bundle/SHA256SUMS")" "$runtime_output"
expect_line --artifact-sha256 "$runtime_output"
expect_line "$(sha256_file "$bundle/$runtime_artifact")" "$runtime_output"
expect_line --lifecycle-sha256 "$runtime_output"
expect_line --manifest-signature "$runtime_output"
expect_line "$assets/RELEASE-MANIFEST.sig" "$runtime_output"
expect_line "$trust/release-public.pem" "$runtime_output"
expect_line "$assets/RELEASE-POLICY.json" "$runtime_output"
expect_line "$trust/policy-public.pem" "$runtime_output"

provisioner_output="$workspace/provisioner.out"
# shellcheck disable=SC2086
"$entrypoint" $common_arguments --role provisioner > "$provisioner_output"
expect_line MOCK_PLATFORM_INSTALLER "$provisioner_output"
expect_line --release-id "$provisioner_output"
expect_line --lifecycle-sha256 "$provisioner_output"
expect_line "$(sha256_file "$bundle/$lifecycle_artifact")" "$provisioner_output"
expect_line --manifest-signature "$provisioner_output"
expect_line "$assets/RELEASE-MANIFEST.sig" "$provisioner_output"
expect_line --policy "$provisioner_output"
expect_line "$assets/RELEASE-POLICY.json" "$provisioner_output"

# shellcheck disable=SC2086
expect_rejection 'trust must remain outside the native bundle' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$bundle" --role provisioner

expect_rejection 'assets must remain outside the native bundle' \
  "$entrypoint" --bundle "$bundle" --assets "$bundle" --trust "$trust" --role provisioner

expect_rejection 'trust must remain outside the assets directory' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$assets" --role provisioner

expect_rejection 'bundle path must be canonical and contain no symlinked component' \
  "$entrypoint" --bundle "$workspace/native/../native" --assets "$assets" --trust "$trust" --role provisioner

ln -s "$workspace" "$workspace/symlinked-parent"
expect_rejection 'bundle path must be canonical and contain no symlinked component' \
  "$entrypoint" --bundle "$workspace/symlinked-parent/native" --assets "$assets" --trust "$trust" --role provisioner
rm -f -- "$workspace/symlinked-parent"

mv "$trust/distribution-public.key" "$keys/distribution-public.key.original"
ln -s "$keys/distribution-public.key.original" "$trust/distribution-public.key"
expect_rejection 'trust tree contains a symlink or non-regular entry' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$trust" --role provisioner
rm -f -- "$trust/distribution-public.key"
mv "$keys/distribution-public.key.original" "$trust/distribution-public.key"

ln "$assets/owntransit.rb" "$assets/unexpected-hardlink"
expect_rejection 'assets file has multiple hard links' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$trust" --role provisioner
rm -f -- "$assets/unexpected-hardlink"

chmod 0666 "$trust/policy-public.pem"
expect_rejection 'protected handoff path is group/world writable' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$trust" --role provisioner
chmod 0644 "$trust/policy-public.pem"

chmod 0777 "$assets"
expect_rejection 'protected handoff path is group/world writable' \
  "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$trust" --role provisioner
chmod 0755 "$assets"

if test "$(uname -s)" = Darwin; then
  chmod +a 'everyone deny write' "$trust/policy-public.pem"
  expect_rejection 'protected handoff path has an extended ACL' \
    "$entrypoint" --bundle "$bundle" --assets "$assets" --trust "$trust" --role provisioner
  chmod -N "$trust/policy-public.pem"
fi

cp "$trust/allowed_signers" "$keys/allowed_signers.original"
ssh-keygen -q -t ed25519 -N '' -f "$keys/wrong-distribution"
wrong_public_fields=$(awk '{print $1 " " $2}' "$keys/wrong-distribution.pub")
printf '%s\n' "owntransit-release $wrong_public_fields" "owntransit-source $wrong_public_fields" > "$trust/allowed_signers"
# shellcheck disable=SC2086
expect_rejection 'allowed-signers release principal is not bound to the distribution public key' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/allowed_signers.original" "$trust/allowed_signers"

printf '%s\n' "owntransit-release $public_fields" "owntransit-source $public_fields" "unexpected-release $public_fields" > "$trust/allowed_signers"
# shellcheck disable=SC2086
expect_rejection 'allowed-signers must contain exactly the two canonical v1 principals' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/allowed_signers.original" "$trust/allowed_signers"

cp "$trust/release-public.pem" "$keys/release-public.pem.original"
printf '%s\n' substituted-release-public > "$trust/release-public.pem"
# shellcheck disable=SC2086
expect_rejection 'trust statement does not bind the release public key' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/release-public.pem.original" "$trust/release-public.pem"

cp "$trust/TRUST-STATEMENT.txt" "$keys/TRUST-STATEMENT.txt.original"
printf '%s\n' tampered >> "$trust/TRUST-STATEMENT.txt"
# shellcheck disable=SC2086
expect_rejection 'trust statement signature did not verify' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/TRUST-STATEMENT.txt.original" "$trust/TRUST-STATEMENT.txt"

cp "$bundle/SHA256SUMS" "$keys/native-SHA256SUMS.original"
printf '%064d  ignored-but-valid-entry\n' 0 >> "$bundle/SHA256SUMS"
# shellcheck disable=SC2086
expect_rejection 'native bundle checksum signature did not verify' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/native-SHA256SUMS.original" "$bundle/SHA256SUMS"

cp "$entrypoint" "$keys/install.sh.original"
printf '%s\n' '# authenticated-entrypoint-tamper' >> "$entrypoint"
# shellcheck disable=SC2086
expect_rejection 'native bundle checksum mismatch: packaging/scripts/install.sh' \
  "$entrypoint" $common_arguments --role provisioner
cp "$keys/install.sh.original" "$entrypoint"
chmod 0755 "$entrypoint"

printf '%s\n' tampered >> "$assets/RELEASE-POLICY.json"
# shellcheck disable=SC2086
expect_rejection 'outer asset inventory checksum mismatch: RELEASE-POLICY.json' \
  "$entrypoint" $common_arguments --role provisioner

printf '%s\n' 'install entrypoint authenticated-derivation and fail-closed tests passed'
