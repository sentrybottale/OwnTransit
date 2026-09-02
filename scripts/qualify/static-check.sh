#!/bin/sh
set -eu

fail() {
  printf 'qualification-static-check: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$project_root"

for script in packaging/macos/*.sh packaging/homebrew/*.sh scripts/qualify/*.sh; do
  sh -n "$script" || fail "shell syntax failed: $script"
  test -x "$script" || fail "script is not executable: $script"
done

require_text() {
  file=$1
  literal=$2
  grep -Fq -- "$literal" "$file" || fail "$file is missing invariant: $literal"
}

require_text packaging/macos/verify-sshsig.sh 'ssh-keygen -Y verify'
require_text packaging/macos/verify-sshsig.sh 'SHA-256 digest mismatch'
require_text packaging/macos/sign-checksums.sh 'signature output must be outside the checksum staging tree'
for signing_helper in packaging/macos/sign-checksums.sh packaging/homebrew/build-source-archive.sh; do
  require_text "$signing_helper" 'unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY'
  require_text "$signing_helper" 'signing key must be owned by the current effective UID'
  require_text "$signing_helper" 'signing key must have exactly one hard link'
  require_text "$signing_helper" 'signing key mode must be 0400 or 0600'
  require_text "$signing_helper" 'protected key ancestor is group- or world-writable'
  require_text "$signing_helper" 'protected key ancestor has an extended ACL'
  require_text "$signing_helper" 'darwin_mode_raw=$(stat -f %p -- "$1")'
  require_text "$signing_helper" '"$((0$darwin_mode_raw & 07777))"'
  require_text "$signing_helper" 'protected key ancestor has special or invalid mode bits'
  require_text "$signing_helper" 'signing key must be an Ed25519 private key'
  require_text "$signing_helper" 'require_key_outside_tree "$output_parent" output'
done
if grep -Fq '%Lp' \
  packaging/macos/sign-checksums.sh \
  packaging/homebrew/build-source-archive.sh \
  scripts/qualify/test-native-archive.sh \
  scripts/qualify/test-signature-tools.sh; then
  fail 'Darwin qualification or signing mode check hides special permission bits'
fi
require_text scripts/qualify/test-native-archive.sh 'chmod 1644 "$bundle/LICENSE"'
require_text scripts/qualify/test-signature-tools.sh 'chmod 1600 "$workspace/special-mode-key"'
require_text scripts/qualify/test-signature-tools.sh 'chmod 1700 "$workspace/special-mode-ancestor"'
require_text packaging/macos/sign-checksums.sh 'require_key_outside_tree "$subject_parent" "checksum staging"'
require_text packaging/homebrew/build-source-archive.sh 'require_key_outside_tree "$source_root" "source staging"'
require_text packaging/macos/package-pkg.sh 'developer-id package output is disabled until OwnTransit authenticates the final package bytes and BUILD-INPUTS version'
require_text packaging/macos/package-pkg.sh 'client .pkg generation is disabled'
require_text packaging/macos/package-pkg.sh 'explicit local --client-user reader identity'
require_text packaging/homebrew/owntransit.rb.in 'verify_signed_source_tree!'
require_text packaging/homebrew/owntransit.rb.in 'signed manifest does not exactly cover OwnTransit Go build inputs'
require_text packaging/homebrew/owntransit.rb.in 'depends_on "go@1.26" => :build'
require_text packaging/homebrew/owntransit.rb.in 'formula_opt_bin("go@1.26")/"go"'
if grep -Fq 'Formula["go@1.26"].opt_bin' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must use the current formula path helper'
fi
require_text packaging/homebrew/owntransit.rb.in 'pkgshare.install "LICENSE", "THIRD_PARTY_NOTICES.md"'
require_text packaging/homebrew/owntransit.rb.in 'assert_predicate pkgshare/"LICENSE", :file?'
require_text packaging/homebrew/owntransit.rb.in 'assert_predicate pkgshare/"THIRD_PARTY_NOTICES.md", :file?'
require_text packaging/homebrew/owntransit.rb.in 'intentionally does not install owntransitctl'
require_text packaging/homebrew/owntransit.rb.in '/Library/OwnTransit/roles/client/current/owntransitctl'
require_text packaging/homebrew/owntransit.rb.in 'signed qualification record reports PASS'
require_text packaging/homebrew/owntransit.rb.in 'any hard gate is not PASS'
if grep -Fq './cmd/owntransitctl' packaging/homebrew/owntransit.rb.in ||
   grep -Fq 'bin/"owntransitctl"' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must not build, install, or test a Cellar lifecycle executable'
fi
require_text packaging/homebrew/render-formula.sh 'formula output basename must be owntransit.rb'
require_text scripts/qualify/linux-amd64-vm.sh 'OWNTRANSIT_DISPOSABLE_VM=1'
require_text scripts/qualify/linux-amd64-vm.sh 'kernel boot ID did not change'
require_text scripts/qualify/linux-amd64-vm.sh 'connector process owns a TCP listener'
require_text scripts/qualify/linux-amd64-vm.sh 'wss://127.0.0.1:65535/connects'
require_text scripts/qualify/linux-amd64-vm.sh '"cold_boot_verified":true'
require_text scripts/qualify/linux-amd64-vm.sh 'installer pre-created bootstrap-owned root'
require_text scripts/qualify/linux-amd64-vm.sh '--state-root /var/lib/owntransit/connector/private'
require_text scripts/qualify/linux-amd64-vm.sh '--runtime-root /var/lib/owntransit/connector/runtime'
require_text scripts/qualify/linux-amd64-vm.sh '--anchor-view-root /var/lib/owntransit/connector/anchor-view'
require_text scripts/qualify/linux-amd64-vm.sh '--reader-gid "$connector_reader_gid"'
require_text scripts/qualify/linux-amd64-vm.sh 'connector service owns an entry in its role tree'
require_text scripts/qualify/linux-amd64-vm.sh 'connector created a file in a published view'
require_text scripts/qualify/linux-amd64-vm.sh 'connector replaced published material'
require_text scripts/qualify/linux-amd64-vm.sh 'connector renamed published material'
require_text scripts/qualify/linux-amd64-vm.sh 'connector unlinked published material'
require_text scripts/qualify/linux-amd64-vm.sh 'connector chown succeeded on published material'
require_text scripts/qualify/linux-amd64-vm.sh 'private lifecycle root is not root:root 0700'
require_text scripts/qualify/linux-amd64-vm.sh 'runtime view root is not root:reader 0750'
require_text scripts/qualify/README.md 'owntransit-relay-exchange@.service'
require_text scripts/qualify/README.md '`podman port owntransit-relay-exchange 9087/tcp`'
require_text scripts/qualify/README.md '`127.0.0.1:9087`'
require_text scripts/qualify/README.md 'at least one create/read-or-write mailbox'
require_text scripts/qualify/README.md "Probe the host's non-loopback"
require_text scripts/qualify/README.md 'NATIVE-SHA256SUMS.sig'
require_text scripts/qualify/README.md 'OWNTRANSIT_RELAY_EXCHANGE_DISPOSABLE=1'
require_text scripts/qualify/linux-relay-exchange.sh 'OWNTRANSIT_RELAY_EXCHANGE_DISPOSABLE=1'
require_text scripts/qualify/linux-relay-exchange.sh '--native-checksums-signature'
require_text scripts/qualify/linux-relay-exchange.sh 'require_protected_bundle_descendants'
require_text scripts/qualify/linux-relay-exchange.sh 'require_protected_ancestor_chain "$trust_input"'
require_text scripts/qualify/linux-relay-exchange.sh 'stage_executable "$bundle/artifacts/owntransit-linux-amd64"'
require_text scripts/qualify/linux-relay-exchange.sh '"$installed_lifecycle" package-apply'
require_text scripts/qualify/linux-relay-exchange.sh '"idempotent":true'
require_text scripts/qualify/linux-relay-exchange.sh 'relay endpoint state already exists; qualification requires a pristine un-enrolled role'
require_text scripts/qualify/linux-relay-exchange.sh 'one-time disposable marker was not consumed'
require_text scripts/qualify/linux-relay-exchange.sh "podman info --format '{{.Host.Security.Rootless}}'"
require_text scripts/qualify/linux-relay-exchange.sh "podman info --format '{{.Host.ServiceIsRemote}}'"
require_text scripts/qualify/linux-relay-exchange.sh 'podman port owntransit-relay-exchange 9087/tcp'
require_text scripts/qualify/linux-relay-exchange.sh 'test "$non_loopback_result" -eq 7'
require_text scripts/qualify/linux-relay-exchange.sh 'courier-register --registration'
require_text scripts/qualify/linux-relay-exchange.sh 'courier-upload-response --registration'
require_text scripts/qualify/linux-relay-exchange.sh 'mailbox accepted a conflicting second opaque response'
require_text scripts/qualify/linux-relay-exchange.sh '"target_response_read_qualified":false'
require_text scripts/qualify/linux-relay-exchange.sh '"endpoint_recorded":false'
require_text scripts/qualify/linux-relay-exchange.sh '"$uninstaller" --role relay --release-id "$release_id"'
require_text packaging/macos/README.md 'rejects every extended ACL and fails'
require_text scripts/qualify/macos-client-boundary.sh '--client-user'
require_text scripts/qualify/macos-client-boundary.sh '--reader-gid'
require_text scripts/qualify/macos-client-boundary.sh 'owntransit.macos-client-reader.v1'
require_text scripts/qualify/macos-client-boundary.sh 'reader group contains a named member or malformed membership attribute'
require_text scripts/qualify/macos-client-boundary.sh 'reader group contains a UUID member or malformed member attribute'
require_text scripts/qualify/macos-client-boundary.sh 'reader group contains nesting or a malformed nesting attribute'
require_text scripts/qualify/macos-client-boundary.sh '/usr/bin/sudo -n -u "#$probe_uid"'
require_text scripts/qualify/macos-client-boundary.sh 'ordinary target-user process read protected bytes'
require_text scripts/qualify/macos-client-boundary.sh '"$client_launcher" --qualify-reader-gid'
require_text scripts/qualify/macos-client-boundary.sh 'wrong real UID passed launcher authorization'
require_text scripts/qualify/macos-client-boundary.sh 'target user can create a replacement inode in the release directory'
require_text scripts/qualify/macos-client-boundary.sh 'normal client frontend is not root:wheel 0755'
require_text scripts/qualify/macos-client-boundary.sh 'normal client frontend differs from the authenticated client artifact'
require_text scripts/qualify/macos-client-boundary.sh 'normal client frontend exposed the protected proxy command'
require_text scripts/qualify/macos-client-boundary.sh 'installation root contains an unexpected setgid file'
require_text scripts/qualify/macos-client-boundary.sh 'installation root contains a setuid file'
require_text scripts/qualify/macos-client-boundary.sh 'macos_mode_raw=$(stat -f %p -- "$1")'
require_text scripts/qualify/macos-client-boundary.sh '"$((0$macos_mode_raw & 07777))"'
require_text scripts/qualify/macos-client-boundary.sh '"ship_qualification":false'
if grep -Fq '%Lp' scripts/qualify/macos-client-boundary.sh; then
  fail 'macOS boundary qualification mode check hides special permission bits'
fi
require_text packaging/macos/CLIENT_READER_BOUNDARY.md 'client-reader.v1'
require_text packaging/macos/CLIENT_READER_BOUNDARY.md '`package-pkg.sh` fails closed for the'
require_text cmd/owntransit-launcher/main.go 'clientRealName      = "owntransit-real"'
require_text cmd/owntransit-launcher/main.go 'arguments are not accepted by the fixed client launcher'
require_text cmd/owntransit-launcher/main.go 'reader GID is present in the caller supplementary groups'
require_text cmd/owntransit-launcher/main.go 'live user GeneratedUID does not match the protected binding'
require_text cmd/owntransit-launcher/main.go '[]string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}'
require_text cmd/owntransit-launcher/main.go 'markExtraFileDescriptorsCloseOnExec'
require_text cmd/owntransit-launcher/identity_darwin.go 'mbr_uid_to_uuid'
require_text cmd/owntransit/main.go 'executable, err := os.Executable()'
require_text cmd/owntransit/main.go 'installed client frontend command rejected'

if grep -Eq 'dseditgroup|dscl .* -(create|append|merge|delete|change|edit)' scripts/qualify/macos-client-boundary.sh; then
  fail 'macOS client boundary qualification mutates Directory Services'
fi

if grep -Eq 'runuser -u owntransit-connector -- .*owntransitctl' scripts/qualify/linux-amd64-vm.sh; then
  fail 'Linux qualification runs root-only lifecycle as the connector service'
fi
if grep -Fq -- '--state-root=/var/lib/owntransit/connector/state' scripts/qualify/linux-amd64-vm.sh; then
  fail 'Linux qualification uses the retired service-owned state root'
fi

if grep -Eq '^[[:space:]]*((/usr/sbin/|/sbin/)?reboot|systemctl[[:space:]]+reboot)([[:space:]]|$)' scripts/qualify/linux-amd64-vm.sh; then
  fail 'Linux qualification harness must not invoke reboot'
fi
if grep -REiq 'curl[[:space:]]*\||wget[[:space:]]*\|' packaging/macos packaging/homebrew scripts/qualify; then
  fail 'platform tooling contains a network-to-shell pattern'
fi

if command -v ruby >/dev/null 2>&1; then
  ruby -c packaging/homebrew/owntransit.rb.in >/dev/null || fail 'Homebrew template has invalid Ruby syntax'
fi

if client_pkg_output=$(packaging/macos/package-pkg.sh --mode unsigned --role client 2>&1); then
  fail 'macOS package tool emitted or accepted a client package lane'
fi
printf '%s\n' "$client_pkg_output" | grep -Fq 'client .pkg generation is disabled' ||
  fail 'macOS package tool did not fail client generation at the reader-identity boundary'

if provisioner_pkg_output=$(packaging/macos/package-pkg.sh --mode unsigned --role provisioner 2>&1); then
  fail 'macOS package tool emitted a provisioner package outside the manager-bound release transaction'
fi
printf '%s\n' "$provisioner_pkg_output" | grep -Fq 'provisioner .pkg generation is disabled' ||
  fail 'macOS package tool did not fail provisioner generation at the manager-bound package boundary'

if developer_pkg_output=$(packaging/macos/package-pkg.sh --mode developer-id --role provisioner 2>&1); then
  fail 'macOS package tool accepted the unauthenticated Developer ID output lane'
fi
printf '%s\n' "$developer_pkg_output" | grep -Fq 'developer-id package output is disabled' ||
  fail 'macOS package tool did not fail the Developer ID lane at final-byte authentication'

printf '%s\n' 'platform qualification static checks passed'
