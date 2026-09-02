#!/bin/sh
set -eu

fail() {
  printf 'release-static-check: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$project_root"

for script in scripts/release/*.sh; do
  sh -n "$script" || fail "shell syntax failed: $script"
  test -x "$script" || fail "release script is not executable: $script"
done

require_text() {
  file=$1
  literal=$2
  grep -Fq -- "$literal" "$file" || fail "$file is missing invariant: $literal"
}

for installer in scripts/release/install-linux.sh scripts/release/install-macos.sh; do
  require_text "$installer" 'PATH=/'
  require_text "$installer" 'require_root_owned_protected'
  require_text "$installer" 'bundle path is group/world writable'
  require_text "$installer" 'bundle member has multiple hard links'
  require_text "$installer" 'bundle tree contains a symlink'
  require_text "$installer" 'installer must run directly from the selected protected bundle'
  require_text "$installer" 'test "$0" = "$bundled_installer"'
  require_text "$installer" 'required bundle member is absent from SHA256SUMS'
  require_text "$installer" 'third_party_licenses_path=evidence/THIRD_PARTY_LICENSES.txt'
done
for entrypoint_invariant in \
  'test "$(id -u)" -eq 0 || fail "installation requires root"' \
  'assets must remain outside the native bundle' \
  'trust must remain outside the native bundle' \
  'outer asset checksum signature did not verify under the independently supplied trust' \
  'trust statement signature did not verify' \
  'trust statement does not bind the release public key' \
  'native bundle checksum signature did not verify' \
  'running installer entry point differs from the signed native bundle' \
  'exec "$platform_installer"'; do
  require_text scripts/release/install.sh "$entrypoint_invariant"
done
require_text scripts/release/build-artifacts.sh 'install.sh install-linux.sh'
require_text scripts/release/archive-native.sh 'packaging/scripts/install.sh'
require_text scripts/tests/sign-candidate.sh 'packaging/scripts/install.sh'
require_text scripts/release/releasectl/main.go 'package-install-entrypoint'
require_text scripts/qualify/test-native-archive.sh 'packaging/scripts/install.sh'
require_text scripts/release/install-macos.sh '"$lifecycle_runner" package-apply'
require_text scripts/release/install-macos.sh 'roles_root="$install_root/roles"'
require_text scripts/release/install-macos.sh 'ensure_exact_symlink "$bin_directory/owntransit" "../roles/client/current/owntransit"'
require_text scripts/release/install-macos.sh 'ensure_exact_symlink "$bin_directory/owntransit-provision" "../roles/provisioner/current/owntransit-provision"'
require_text scripts/release/install-macos.sh 'ensure_root_directory /private/var/db/OwnTransit/package-rollback 700'
require_text scripts/release/install-macos.sh 'ensure_root_directory "$install_root/client" 755'
require_text scripts/release/install-macos.sh 'ensure_root_directory /private/var/db/OwnTransit/client 755'
require_text cmd/owntransitctl/package_lifecycle.go '"/private/var/db/OwnTransit/package-rollback"'
require_text scripts/release/install-macos.sh 'release/policy trust input must remain outside the candidate bundle'
require_text scripts/release/uninstall-macos.sh 'roles/client/current'
require_text scripts/release/uninstall-macos.sh 'installed license notices'
require_text packaging/macos/package-pkg.sh 'provisioner .pkg generation is disabled'
require_text scripts/release/uninstall-linux.sh 'for notice in LICENSE THIRD_PARTY_LICENSES.txt'
require_text scripts/release/uninstall-linux.sh 'installed license notices'

require_text scripts/release/install-macos.sh 'require_no_extended_acl'
require_text scripts/release/install-macos.sh 'ensure_root_directory /Library 755'
require_text scripts/release/install-macos.sh 'privileged lifecycle execution remains behind the authenticated per-role current selector'
require_text scripts/release/install-macos.sh 'selected lifecycle executable metadata is invalid'
require_text scripts/release/install-macos.sh '--client-user'
require_text scripts/release/install-macos.sh 'owntransit.macos-client-reader.v1'
require_text scripts/release/install-macos.sh 'identity_directory="$install_root/identity"'
require_text scripts/release/install-macos.sh 'reader_receipt="$identity_directory/client-reader.v1"'
require_text scripts/release/install-macos.sh '/usr/sbin/dseditgroup -q -o create -n . -i "$reader_gid"'
require_text scripts/release/install-macos.sh 'read_directory_list /Search /Groups PrimaryGroupID'
require_text scripts/release/install-macos.sh 'read_directory_list /Search /Users PrimaryGroupID'
require_text scripts/release/install-macos.sh '--launcher-sha256'
require_text scripts/release/install-macos.sh 'artifacts/owntransit-launcher-darwin-arm64'
require_text scripts/release/install-macos.sh 'verify_client_executable_boundary "$release_directory/owntransit" "$release_directory/owntransit-real"'
require_text scripts/release/install-macos.sh 'public_frontend="$bin_directory/owntransit-cli"'
require_text scripts/release/install-macos.sh 'package finalizer did not publish a regular normal client frontend'
require_text scripts/release/install-macos.sh 'normal client frontend activation is invalid'
require_text scripts/release/install-macos.sh 'normal non-setgid setup frontend:'
require_text cmd/owntransitctl/package_finalize_identity.go 'schema=owntransit.macos-client-launcher.v1'
require_text cmd/owntransitctl/package_finalize_darwin.go 'securefs.OpenViewRoot(darwinLauncherAuthRoot, readerGID)'
require_text cmd/owntransitctl/package_frontend_darwin.go 'darwinClientFrontendName      = "owntransit-cli"'
require_text cmd/owntransitctl/package_frontend_darwin.go 'Keep the staging inode root-only until its complete bytes are durable.'
require_text cmd/owntransitctl/package_finalize_darwin.go 'publishDarwinClientFrontend(receipt, result.Runtime)'
require_text scripts/release/install-macos.sh 'ordinary client-user process can read the protected launcher binding'
require_text scripts/release/install-macos.sh '"$client_launcher" --qualify-reader-gid'
require_text scripts/release/install-macos.sh '/usr/bin/sudo -n -u "#$target_uid"'
require_text scripts/release/install-macos.sh 'unrelated user is unexpectedly a reader-group member'
require_text scripts/release/install-macos.sh 'installation root contains a setuid file'
require_text scripts/release/install-macos.sh 'manual residue review is required'
require_text scripts/release/install-macos.sh 'for (field_number = 1; field_number <= NF; field_number++)'
if grep -Eq 'for \(index[[:space:]]*=' scripts/release/install-macos.sh; then
  fail 'macOS installer assigns to the awk index builtin'
fi
require_text scripts/release/uninstall-macos.sh 'manager-owned current/previous selectors'
require_text scripts/release/uninstall-macos.sh 'cmp -s "$release_directory/owntransit-real" "$public_frontend"'
require_text scripts/release/uninstall-macos.sh 'destructive reader-identity purge is intentionally not implemented'
if grep -Eq 'dseditgroup .* -o edit|dseditgroup .* -a |GroupMembership.*client_user|GroupMembers.*client_uuid' scripts/release/install-macos.sh; then
  fail 'macOS client installer grants the selected user direct reader-group membership'
fi
require_text scripts/release/install-linux.sh 'env -i'
require_text scripts/release/install-linux.sh '--client-user'
require_text scripts/release/install-linux.sh '"$lifecycle_runner" package-apply'
require_text scripts/release/install-linux.sh 'lifecycle_runner="$roles_root/$role/releases/$current_release/owntransitctl"'
require_text scripts/release/install-linux.sh 'roles_root="$install_root/roles"'
require_text scripts/release/install-linux.sh 'ensure_root_directory /var/lib/owntransit/package-rollback 700'
require_text scripts/release/install-linux.sh 'ensure_root_directory /var/lib/owntransit/package-supervisor 700'
require_text scripts/release/install-linux.sh 'ensure_exact_symlink "$public_bin/owntransit" "$current_link/owntransit"'
require_text scripts/release/install-linux.sh 'ensure_exact_symlink "$public_bin/owntransit-proxy" "$current_link/owntransit-proxy"'
require_text scripts/release/install-linux.sh 'ensure_exact_symlink "$public_bin/owntransit-provision" "$current_link/owntransit-provision"'
require_text scripts/release/install-linux.sh 'release/policy trust input must remain outside the candidate bundle'
require_text scripts/release/install-linux.sh 'OWNTRANSIT_CONNECTOR_READER_GID='
require_text scripts/release/install-linux.sh 'service identity has an unexpected supplementary group'
require_text scripts/release/install-linux.sh 'one exact local /etc/passwd identity'
require_text scripts/release/install-linux.sh 'client-reader.v1'
require_text scripts/release/uninstall-linux.sh '/etc/owntransit/connector-runtime.env'
require_text scripts/release/uninstall-linux.sh 'roles/$role/current'
require_text scripts/release/install-linux.sh 'packaging/systemd/owntransit-relay-exchange-template.service'
require_text scripts/release/install-linux.sh '/etc/systemd/system/owntransit-relay-exchange@.service'
require_text scripts/release/install-linux.sh 'relay bootstrap exchange unit is not authenticated by SHA256SUMS'
require_text scripts/release/install-linux.sh 'relay bootstrap exchange unit has multiple hard links'
require_text scripts/release/uninstall-linux.sh "'owntransit-relay-exchange@*.service'"
require_text scripts/release/uninstall-linux.sh '/etc/systemd/system/owntransit-relay-exchange@.service'

if grep -Fq -- '$install_root/releases' scripts/release/install-linux.sh scripts/release/uninstall-linux.sh; then
  fail 'Linux role packages must not share a release or selector namespace'
fi
if grep -Fq -- '/usr/local/bin/owntransitctl' scripts/release/install-linux.sh scripts/release/uninstall-linux.sh; then
  fail 'Linux lifecycle authority must remain behind the protected per-role selector'
fi
if grep -Eq '(rm|rmdir).*(release_directory|current_link)' scripts/release/uninstall-linux.sh; then
  fail 'Linux detach must preserve authenticated releases and selectors for recovery'
fi

if grep -Eiq 'curl[[:space:]]*\||wget[[:space:]]*\|' scripts/release/install-*.sh; then
  fail 'installer contains a network-to-shell pattern'
fi
if grep -Eq 'systemctl[[:space:]]+(enable|start)' scripts/release/install-linux.sh; then
  fail 'Linux installer enables or starts a service'
fi

require_text deploy/systemd/owntransit-connector.service '--runtime-root=/var/lib/owntransit/connector/runtime'
require_text deploy/systemd/owntransit-connector.service '--anchor-view-root=/var/lib/owntransit/connector/anchor-view'
require_text deploy/systemd/owntransit-connector.service '--reader-gid=${OWNTRANSIT_CONNECTOR_READER_GID}'
require_text deploy/systemd/owntransit-connector.service 'EnvironmentFile=/etc/owntransit/connector-runtime.env'
require_text deploy/systemd/owntransit-connector.service 'ExecStart=/usr/libexec/owntransit/roles/connector/current/owntransit-connector run'
require_text deploy/systemd/owntransit-connector.service 'ConditionPathExists=!/var/lib/owntransit/package-supervisor/connector.intent'
require_text deploy/systemd/owntransit-connector.service 'InaccessiblePaths=/var/lib/owntransit/connector/private /var/lib/owntransit/connector/authority'
require_text deploy/systemd/owntransit-connector.service 'CapabilityBoundingSet='
require_text deploy/systemd/owntransit-relay.service '--runtime-root=/runtime'
require_text deploy/systemd/owntransit-relay.service '--anchor-view-root=/anchor'
require_text deploy/systemd/owntransit-relay.service '--reader-gid=${OWNTRANSIT_RELAY_READER_GID}'
require_text deploy/systemd/owntransit-relay.service '--user ${OWNTRANSIT_RELAY_UID}:${OWNTRANSIT_RELAY_READER_GID}'
require_text deploy/systemd/owntransit-relay.service '--volume=/var/lib/owntransit/relay/runtime:/runtime:ro,nosuid,nodev,noexec'
require_text deploy/systemd/owntransit-relay.service '--volume=/var/lib/owntransit/relay/anchor-view:/anchor:ro,nosuid,nodev,noexec'
require_text deploy/systemd/owntransit-relay.service 'InaccessiblePaths=/var/lib/owntransit/relay/private /var/lib/owntransit/relay/authority'
require_text deploy/systemd/owntransit-relay.service '--publish=127.0.0.1:9087:9087/tcp'
require_text deploy/systemd/owntransit-relay.service '--memory=256m --env=GOMEMLIMIT=192MiB'
require_text deploy/systemd/owntransit-relay.service '--network=bridge --publish=127.0.0.1:9087:9087/tcp'
require_text deploy/systemd/owntransit-relay.service 'ConditionPathExists=!/var/lib/owntransit/package-supervisor/relay.intent'
require_text deploy/systemd/owntransit-relay-exchange@.service 'Conflicts=owntransit-relay.service'
require_text deploy/systemd/owntransit-relay-exchange@.service 'Before=owntransit-relay.service'
require_text deploy/systemd/owntransit-relay-exchange@.service 'EnvironmentFile=/etc/owntransit/relay-container.env'
require_text deploy/systemd/owntransit-relay-exchange@.service '--read-only --cap-drop=all --security-opt=no-new-privileges'
require_text deploy/systemd/owntransit-relay-exchange@.service '--memory=256m --env=GOMEMLIMIT=192MiB'
require_text deploy/systemd/owntransit-relay-exchange@.service '--user ${OWNTRANSIT_RELAY_UID}:${OWNTRANSIT_RELAY_READER_GID}'
require_text deploy/systemd/owntransit-relay-exchange@.service '--network=bridge --publish=127.0.0.1:9087:9087/tcp'
require_text deploy/systemd/owntransit-relay-exchange@.service 'exchange --allocation-sha256=%i'
require_text deploy/systemd/owntransit-relay-exchange@.service 'InaccessiblePaths=/var/lib/owntransit'
for relay_unit in deploy/systemd/owntransit-relay.service deploy/systemd/owntransit-relay-exchange@.service; do
  relay_exec_start=$(grep '^ExecStart=' "$relay_unit")
  test "$(printf '%s\n' "$relay_exec_start" | grep -o -- '--network=[^[:space:]]*')" = '--network=bridge' ||
    fail "$relay_unit must select exactly the default Podman bridge"
  test "$(printf '%s\n' "$relay_exec_start" | grep -o -- '--publish=[^[:space:]]*')" = '--publish=127.0.0.1:9087:9087/tcp' ||
    fail "$relay_unit must publish exactly one host-loopback relay port"
done
if grep -Eq '^\[Install\]$|^WantedBy=|--(volume|mount|runtime-root|anchor-view-root|state-root|config)(=|[[:space:]])' deploy/systemd/owntransit-relay-exchange@.service; then
  fail 'relay bootstrap exchange unit is enableable or consumes role state/configuration'
fi
require_text Containerfile 'CMD ["run", "--runtime-root=/runtime", "--anchor-view-root=/anchor", "--reader-gid=65532"]'
require_text deploy/vps/Containerfile.relay 'CMD ["run", "--runtime-root=/runtime", "--anchor-view-root=/anchor", "--reader-gid=65532"]'
require_text scripts/release/make-relay-oci.sh '\"--runtime-root=/runtime\",\"--anchor-view-root=/anchor\",\"--reader-gid=65532\"'
require_text scripts/release/make-relay-oci.sh 'licenses owntransit-relay'
require_text scripts/release/make-relay-oci.sh 'licenses/Apache-2.0.txt'
require_text scripts/release/make-relay-oci.sh 'licenses/THIRD_PARTY_NOTICES.md'
require_text scripts/release/make-relay-oci.sh '\"org.opencontainers.image.licenses\":\"Apache-2.0\"'

if grep -Fq -- '--state-root' deploy/systemd/owntransit-connector.service deploy/systemd/owntransit-relay.service Containerfile deploy/vps/Containerfile.relay; then
  fail 'runtime service or relay image still consumes private --state-root'
fi
if grep -Eq 'install -d .*\$workspace/(private|authority|runtime|anchor-view)' scripts/release/install-linux.sh; then
  fail 'installer pre-creates a bootstrap-owned lifecycle or runtime-view root'
fi
if grep -Fq -- '/var/lib/owntransit/relay/private:' deploy/systemd/owntransit-relay.service ||
   grep -Fq -- '/var/lib/owntransit/relay/authority:' deploy/systemd/owntransit-relay.service; then
  fail 'relay unit mounts private lifecycle material'
fi
for inventory in scripts/release/archive-native.sh scripts/qualify/test-native-archive.sh scripts/tests/sign-candidate.sh; do
  require_text "$inventory" 'packaging/systemd/owntransit-relay-exchange-template.service'
done
require_text scripts/release/build-artifacts.sh 'owntransit-relay-exchange@.service'
require_text scripts/release/build-artifacts.sh 'packaging/systemd/owntransit-relay-exchange-template.service'
require_text scripts/release/releasectl/main.go 'systemd-relay-exchange'
require_text scripts/release/releasectl/main.go 'packaging/systemd/owntransit-relay-exchange-template.service'

test -z "$(find deploy/launchd -type f -name '*.plist' -print)" || fail 'v1 macOS client must not install a launchd job'

for artifact in \
  owntransit-darwin-arm64 \
  owntransit-launcher-darwin-arm64 \
  owntransit-linux-amd64 \
  owntransit-connector-linux-amd64 \
  owntransit-relay-linux-amd64.oci.tar \
  owntransitctl-darwin-arm64 \
  owntransitctl-linux-amd64 \
  owntransit-provision-darwin-arm64 \
  owntransit-provision-linux-amd64; do
  require_text scripts/release/build-artifacts.sh "$artifact"
done

for script in \
  scripts/release/archive-native.sh \
  scripts/release/build-artifacts.sh \
  scripts/release/make-relay-oci.sh \
  scripts/release/install-linux.sh \
  scripts/release/install-macos.sh \
  scripts/release/uninstall-linux.sh \
  scripts/release/uninstall-macos.sh; do
  require_text "$script" 'release ID must contain 52 base32 characters'
  require_text "$script" 'release ID has non-canonical unused trailing bits'
  require_text "$script" 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
done

require_text scripts/release/build-artifacts.sh 'go run -mod=readonly ./scripts/release/releasectl'
require_text scripts/release/build-artifacts.sh 'https://github.com/sentrybottale/owntransit'
require_text scripts/release/build-artifacts.sh 'run_release_tool evidence'
require_text scripts/release/build-artifacts.sh 'builder_identity="docker.io/library/golang@$builder_digest"'
require_text scripts/release/build-artifacts.sh '--builder-image $builder_identity'
require_text scripts/release/build-artifacts.sh "Apple Container's BuildKit context synchronization"
require_text scripts/release/build-artifacts.sh '--mount "type=bind,source=$project_root,target=/src,readonly"'
require_text scripts/release/build-artifacts.sh '--mount "type=bind,source=$destination_parent,target=/build"'
require_text scripts/release/build-artifacts.sh 'export GOTOOLCHAIN=local GOWORK=off'
require_text scripts/release/build-artifacts.sh 'go mod verify'
require_text scripts/release/build-artifacts.sh 'case "$TARGETOS/$TARGETARCH" in'
require_text Containerfile 'COPY scripts/release/releasectl ./scripts/release/releasectl'
require_text Containerfile 'gofmt -l cmd internal scripts/release/releasectl'
require_text scripts/release/releasectl/main.go 'case "candidate-verify"'
require_text scripts/release/releasectl/main.go 'clean Git HEAD commit or timestamp does not match the candidate ledger'
require_text scripts/release/releasectl/main.go '"show", "-s", "--format=%ct", commit'
require_text scripts/release/releasectl/main.go 'Git HEAD changed while its identity was sampled'
require_text scripts/release/install-macos.sh 'output is disabled; this installer'
require_text scripts/release/archive-native.sh 'bundle file inventory is not the exact unsigned native staging tree'
require_text scripts/release/archive-native.sh 'SHA256SUMS does not describe the exact native staging file set'
require_text scripts/release/archive-native.sh 'output basename must be exactly $archive_root_name.tar.gz'
require_text scripts/release/archive-native.sh 'builder_image="docker.io/library/golang:1.26.7-bookworm@$builder_digest"'
require_text scripts/release/archive-native.sh '--pull=never'
require_text scripts/release/archive-native.sh '--mount "type=bind,source=$snapshot_parent,target=/input,readonly"'
require_text scripts/release/archive-native.sh '--mount "type=bind,source=$docker_output,target=/output"'
require_text scripts/release/archive-native.sh '--sort=name'
require_text scripts/release/archive-native.sh '--mtime="@$source_date_epoch"'
require_text scripts/release/archive-native.sh 'gzip -n -9'
require_text scripts/release/archive-native.sh 'cmp -s "$first" "$second"'
require_text scripts/release/archive-native.sh 'ln "$first" "$output"'
require_text scripts/release/archive-native.sh 'carries no signature, policy, key, or trust authority'
if grep -Fq 'OWNTRANSIT_GNU_TAR' scripts/release/archive-native.sh; then
  fail 'native archive GNU tar selection must not be redirected through the environment'
fi
if grep -Fq 'source=$temporary,target=/output' scripts/release/archive-native.sh; then
  fail 'native archive Docker output must not expose a writable alias to the read-only snapshot'
fi

require_text scripts/release/sign-candidate.sh 'release and policy public key IDs must be different'
require_text scripts/release/sign-candidate.sh 'the empty-anchor first-release path requires policy sequence 1'
require_text scripts/release/sign-candidate.sh '--anchor-policy-sequence'
require_text scripts/release/sign-candidate.sh '--anchor-policy-key-id'
require_text scripts/release/sign-candidate.sh '--anchor-tombstones none'
require_text scripts/release/sign-candidate.sh '--anchor-release-floor "$anchor_release_floor"'
require_text scripts/release/sign-candidate.sh '--anchor-lifecycle-floor "$anchor_lifecycle_floor"'
require_text scripts/release/sign-candidate.sh 'candidate policy sequence must advance the persisted anchor'
require_text scripts/release/sign-candidate.sh 'policy public key differs from the persisted anchor'
require_text scripts/release/sign-candidate.sh 'explicitly empty persisted tombstone list'
require_text scripts/release/README.md 'This helper does not support policy-key rotation.'
require_text scripts/release/README.md 'policy-anchor JSON does not contain that key identity'
for forwarded_anchor in \
  '--anchor-policy-sequence "$anchor_policy_sequence"' \
  '--anchor-release-floor "$anchor_release_floor"' \
  '--anchor-lifecycle-floor "$anchor_lifecycle_floor"'; do
  test "$(grep -Fc -- "$forwarded_anchor" scripts/release/sign-candidate.sh)" -eq 2 ||
    fail "signing conductor must forward each numeric policy anchor exactly twice"
done
require_text scripts/release/sign-candidate.sh 'output must remain outside the unsigned bundle'
require_text scripts/release/sign-candidate.sh 'output must remain outside every signing/trust input parent'
require_text scripts/release/sign-candidate.sh 'every signing/trust input must remain outside the unsigned bundle'
require_text scripts/release/sign-candidate.sh 'every signing/trust input must remain outside the source tree'
require_text scripts/release/sign-candidate.sh '--source-root "$source_root"'
require_text scripts/release/sign-candidate.sh 'RELEASE-CANDIDATE.json'
require_text scripts/release/sign-candidate.sh 'verified policy anchor does not match the candidate sequences and floors'
require_text scripts/release/sign-candidate.sh 'release public-key identity changed during snapshot'
require_text scripts/release/sign-candidate.sh '--release-public-key "$trusted_release_public"'
require_text scripts/release/sign-candidate.sh '--policy-public-key "$trusted_policy_public"'
require_text scripts/release/sign-candidate.sh '--allowed-signers "$trusted_allowed_signers"'
require_text scripts/release/sign-candidate.sh '--signer-public-key "$trusted_distribution_public"'
require_text scripts/release/sign-candidate.sh 'NATIVE-SHA256SUMS.sig'
require_text scripts/release/sign-candidate.sh 'owntransit-$version-native.tar.gz'
require_text scripts/release/sign-candidate.sh 'owntransit-$version-source.tar.gz'
require_text scripts/release/sign-candidate.sh '--namespace owntransit-release-v1'
require_text scripts/release/sign-candidate.sh 'candidate asset inventory is not the fixed first-release set'
require_text scripts/release/sign-candidate.sh 'outer asset checksum verification failed'
require_text scripts/release/sign-candidate.sh 'allowed-signers must contain exactly the two canonical v1 principals'
require_text scripts/release/sign-candidate.sh 'owntransit-trust-v1'
require_text scripts/release/sign-candidate.sh 'trust_statement_sha256='
require_text scripts/release/sign-candidate.sh 'cannot atomically publish candidate handoff'
if grep -Eq 'ssh-keygen[[:space:]].*-t|openssl[[:space:]].*(genpkey|genrsa|req)' scripts/release/sign-candidate.sh; then
  fail 'candidate signer must never generate a signing key'
fi

require_text scripts/release/sign-qualification-record.sh 'owntransit-qualification-v1'
require_text scripts/release/sign-qualification-record.sh 'qualification output must remain outside the signed asset inventory'
require_text scripts/release/sign-qualification-record.sh 'results file does not contain the exact fixed sorted v1 test set'
require_text scripts/release/sign-qualification-record.sh 'qualification_status=BLOCKED'
require_text scripts/release/sign-qualification-record.sh 'unresolved_critical'
require_text scripts/release/sign-qualification-record.sh 'unresolved_high'
require_text scripts/tests/qualification-record.sh 'qualification record canonical signing and fail-closed tests passed'
if grep -Eq 'ssh-keygen[[:space:]].*-t' scripts/release/sign-qualification-record.sh; then
  fail 'qualification-record signer must never generate a signing key'
fi

if grep -Eq 'chmod.*2750|system.*sudo' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must never setgid or sudo a Cellar binary'
fi
require_text packaging/homebrew/owntransit.rb.in '# frozen_string_literal: true'
require_text packaging/homebrew/owntransit.rb.in 'formula_opt_bin("go@1.26")'
if grep -Fq 'Formula["go@1.26"].opt_bin' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must use the current formula path helper'
fi

require_text scripts/qualify/linux-amd64-vm.sh '--manifest-signature "$manifest_signature"'
require_text scripts/qualify/linux-amd64-vm.sh '--policy-public-key "$policy_public_key"'
require_text scripts/qualify/linux-amd64-vm.sh '/usr/libexec/owntransit/roles/connector/current/owntransitctl'
require_text scripts/qualify/linux-amd64-vm.sh '/usr/libexec/owntransit/roles/connector/current/owntransit-connector'
require_text scripts/qualify/linux-amd64-vm.sh '-relay-listen 0.0.0.0:9087'
require_text scripts/qualify/macos-client-boundary.sh 'role_root="$roles_root/client"'
require_text scripts/qualify/macos-client-boundary.sh '../roles/client/current/owntransit'
if grep -Fq -- '/usr/libexec/owntransit/bin/' scripts/qualify/linux-amd64-vm.sh ||
   grep -Fq -- '/Library/OwnTransit/releases/' scripts/qualify/macos-client-boundary.sh packaging/macos/CLIENT_READER_BOUNDARY.md; then
  fail 'qualification material still references a pre-manager shared release path'
fi

printf '%s\n' 'release packaging static checks passed'
