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

sh -n install-linux.sh || fail 'simple Linux installer has invalid shell syntax'
test -x install-linux.sh || fail 'simple Linux installer is not executable'
require_text install-linux.sh 'release_base=https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.0'
require_text install-linux.sh 'stage=$(mktemp -d /var/lib/owntransit-install-v0.1.0.XXXXXXXX)'
require_text install-linux.sh 'TRUST-STATEMENT.txt 629 e5049fc6f3c6be061992d74f83b84506950a7abb1d3f0117f7b452ed47b31a4b'
require_text install-linux.sh 'owntransit-0.1.0-native.tar.gz 35719170 d5f9ec458fc00c6a47a0eb7c46e2a0a5bade7e2ab95c5ad6e34c5fc256c1b2bc'
require_text install-linux.sh 'client_user=${SUDO_USER-}'
require_text install-linux.sh 'sudo_uid=${SUDO_UID-}'
require_text install-linux.sh 'test "$resolved_sudo_uid" = "$sudo_uid"'
require_text install-linux.sh 'test "$resolved_sudo_user" = "$client_user"'
require_text install-linux.sh 'Connector package installed. Existing service state was preserved. If this is a fresh connector, enroll it before enabling the service.'
require_text install-linux.sh 'ulimit -f 131072'
require_text install-linux.sh 'env -i PATH="$PATH" LC_ALL=C'
require_text install-linux.sh 'pending connector package recovery exists; do not delete its supervisor record; finish authenticated package recovery, then retry'
require_text install-linux.sh 'pending relay package recovery exists; do not delete its supervisor record; finish authenticated package recovery, then retry'
require_text install-linux.sh 'sudo ./install-linux.sh relay'
require_text install-linux.sh 'sudo ./install-linux.sh provisioner'
require_text install-linux.sh '/usr/bin/apt-get -qq update'
require_text install-linux.sh '--no-install-recommends install podman'
require_text install-linux.sh 'existing Podman uses an unsupported path:'
require_text install-linux.sh 'caller_path=${PATH-}'
require_text install-linux.sh 'caller_podman=$(PATH=$caller_path command -v podman'
require_text install-linux.sh 'NEEDRESTART_MODE=l'
require_text install-linux.sh '--no-remove --no-install-recommends install podman'
require_text install-linux.sh 'install the OpenSSH client tools manually'
if grep -Eq 'apt-get[^;]*(dist-upgrade|full-upgrade|[[:space:]]upgrade)|^[[:space:]]*(nginx|ufw|iptables|ip6tables|nft|firewall-cmd)[[:space:]]' install-linux.sh; then
  fail 'simple Linux installer must not upgrade the host or change web-server/firewall configuration'
fi
test "$(sed -n '2p' install-linux.sh)" = 'main() {' ||
  fail 'simple Linux installer must defer all executable work into main'
test "$(tail -n 1 install-linux.sh)" = 'main "$@"' ||
  fail 'simple Linux installer must invoke main only after the complete stream is parsed'
test "$(grep -c '^fetch_pinned ' install-linux.sh | tr -d '[:space:]')" = 17 ||
  fail 'simple Linux installer does not pin the exact seventeen-file handoff'
simple_pin_set_sha256=$(grep '^fetch_pinned ' install-linux.sh | sha256sum | awk '{print $1}')
test "$simple_pin_set_sha256" = dba413c348bb998bbdd5c25e43d667d111f5ac6a5f9eb85f60e86c65d1062dee ||
  fail 'simple Linux installer pinned handoff changed unexpectedly'
simple_archive_check_line=$(grep -nF 'test "$(sha256sum "$native_archive"' install-linux.sh | cut -d: -f1)
simple_extract_line=$(grep -nF 'tar --extract --gzip --no-same-owner' install-linux.sh | cut -d: -f1)
test -n "$simple_archive_check_line" && test -n "$simple_extract_line" &&
  test "$simple_archive_check_line" -lt "$simple_extract_line" ||
  fail 'simple Linux installer must authenticate the native archive before extraction'
simple_apt_line=$(grep -nF '/usr/bin/apt-get -qq update' install-linux.sh | cut -d: -f1)
simple_bundle_ready_line=$(grep -nF 'authenticated native bundle has no installer' install-linux.sh | cut -d: -f1)
test "$simple_bundle_ready_line" -lt "$simple_apt_line" ||
  fail 'simple Linux installer must verify and stage its release before installing dependencies'
if grep -Eq 'systemctl[[:space:]]+(enable|start|restart)|enable[[:space:]]+--now' install-linux.sh; then
  fail 'simple Linux installer must not enable or start a service'
fi
if grep -Eq 'curl[^|]*\|[[:space:]]*(sh|bash)' install-linux.sh; then
  fail 'simple Linux installation must not document or implement curl piped to a shell'
fi
if ./install-linux.sh unsupported-role >/dev/null 2>&1 ||
  ./install-linux.sh relay unexpected >/dev/null 2>&1 ||
  ./install-linux.sh provisioner unexpected >/dev/null 2>&1 ||
  ./install-linux.sh connector unexpected >/dev/null 2>&1 ||
  ./install-linux.sh client root >/dev/null 2>&1; then
  fail 'simple Linux installer accepted an unsupported role or unsafe arguments'
fi
./install-linux.sh --help >/dev/null 2>&1 ||
  fail 'simple Linux installer help is unavailable offline'
sed '$d' install-linux.sh | sh -s -- connector >/dev/null 2>&1 ||
  fail 'complete streamed function definition without the final main call was not inert'
sh scripts/tests/install-linux-bootstrap.sh

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
  require_text "$installer" 'inspect_canonical_lifecycle_version()'
  require_text "$installer" '"$lifecycle_executable" version'
  require_text "$installer" '$28 != "lifecycle"'
  require_text "$installer" 'candidate_version=${build_version_line#version=}'
  require_text "$installer" 'test "$candidate_version" = 0.1.0 && is_owntransit_010_release_candidate "$selected_version"'
  require_text "$installer" 'cannot be replaced by stable 0.1.0. Do not purge it: preserve the retained role state for recovery; use a different unused role state or another host for this role'
done
if grep -Eq '\$bundle/\$lifecycle_path"[[:space:]]+version' scripts/release/install-linux.sh scripts/release/install-macos.sh; then
  fail 'installer executes candidate lifecycle code before manager authorization'
fi

linux_prerelease_guard_line=$(grep -n '^guard_retained_prerelease_install$' scripts/release/install-linux.sh | cut -d: -f1)
linux_first_persistent_mutation_line=$(grep -nF 'ensure_root_directory /var/lib/owntransit 755' scripts/release/install-linux.sh | cut -d: -f1)
test -n "$linux_prerelease_guard_line" && test -n "$linux_first_persistent_mutation_line" &&
  test "$linux_prerelease_guard_line" -lt "$linux_first_persistent_mutation_line" ||
  fail 'Linux retained-prerelease guard must run before persistent host mutation'
linux_selected_metadata_line=$(grep -nF 'test "$(stat -c %a "$selected_lifecycle")" = 700' scripts/release/install-linux.sh | cut -d: -f1)
linux_selected_version_line=$(grep -nF 'selected_version=$(inspect_canonical_lifecycle_version "$selected_lifecycle"' scripts/release/install-linux.sh | cut -d: -f1)
test -n "$linux_selected_metadata_line" && test -n "$linux_selected_version_line" &&
  test "$linux_selected_metadata_line" -lt "$linux_selected_version_line" ||
  fail 'Linux installer must validate selected lifecycle metadata before executing version'

macos_prerelease_guard_line=$(grep -n '^guard_retained_prerelease_install$' scripts/release/install-macos.sh | cut -d: -f1)
macos_first_persistent_mutation_line=$(grep -nF 'ensure_root_directory /Library 755' scripts/release/install-macos.sh | cut -d: -f1)
test -n "$macos_prerelease_guard_line" && test -n "$macos_first_persistent_mutation_line" &&
  test "$macos_prerelease_guard_line" -lt "$macos_first_persistent_mutation_line" ||
  fail 'macOS retained-prerelease guard must run before persistent host mutation'
macos_selected_metadata_line=$(grep -nF 'test "$(macos_mode "$selected_lifecycle")" = 700' scripts/release/install-macos.sh | cut -d: -f1)
macos_selected_version_line=$(grep -nF 'selected_version=$(inspect_canonical_lifecycle_version "$selected_lifecycle"' scripts/release/install-macos.sh | cut -d: -f1)
test -n "$macos_selected_metadata_line" && test -n "$macos_selected_version_line" &&
  test "$macos_selected_metadata_line" -lt "$macos_selected_version_line" ||
  fail 'macOS installer must validate selected lifecycle metadata and ACL before executing version'
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
for full_mode_script in \
  scripts/release/install.sh \
  scripts/release/archive-native.sh \
  scripts/release/sign-candidate.sh \
  scripts/release/sign-qualification-record.sh \
  scripts/tests/sign-candidate.sh; do
  require_text "$full_mode_script" 'stat -f %p -- "$1"'
  require_text "$full_mode_script" '& 07777'
done
if grep -Fq '%Lp' \
  scripts/release/install.sh \
  scripts/release/archive-native.sh \
  scripts/release/sign-candidate.sh \
  scripts/release/sign-qualification-record.sh \
  scripts/tests/sign-candidate.sh; then
  fail 'Darwin release mode check hides special permission bits'
fi
require_text scripts/tests/install-entrypoint.sh 'chmod 1644 "$trust/policy-public.pem"'
require_text scripts/tests/sign-candidate.sh 'chmod 1644 "$bundle/LICENSE"'
require_text scripts/tests/qualification-record.sh 'chmod 1600 "$workspace/keys/distribution"'
require_text scripts/release/install-macos.sh '"$lifecycle_runner" package-apply'
require_text scripts/release/install-macos.sh 'roles_root="$install_root/roles"'
require_text cmd/owntransitctl/package_finalize_darwin.go 'publishDarwinProvisionerFrontend(result.Runtime)'
if grep -Fq 'ensure_exact_symlink "$bin_directory/owntransit-provision"' scripts/release/install-macos.sh; then
  fail 'macOS provisioner frontend must be a distinct public copy, not a protected-tree symlink'
fi
if grep -Fq 'ensure_exact_symlink "$bin_directory/owntransit"' scripts/release/install-macos.sh; then
  fail 'macOS client public launcher must be a distinct regular inode, not a selector symlink'
fi
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
require_text scripts/release/install-macos.sh 'ensure_root_directory "$launcher_stage_directory" 700'
require_text scripts/release/install-macos.sh '"$release_directory/owntransitctl" package-recover --role "$role"'
require_text scripts/release/install-macos.sh 'verify_client_executable_boundary "$release_directory/owntransit" "$public_launcher" "$release_directory/owntransit-real"'
require_text scripts/release/install-macos.sh 'client launcher is not a regular non-symlink file: $client_launcher'
require_text scripts/release/install-macos.sh 'test "$(macos_mode "$client_launcher")" = 2751'
require_text scripts/release/install-macos.sh 'test "$(sha256_file "$public_launcher")" = "$launcher_sha256"'
require_text scripts/release/install-macos.sh 'public launcher is a hard link to the protected release launcher'
require_text scripts/release/install-macos.sh 'private launcher stage contains missing or unexpected transaction state'
require_text scripts/release/install-macos.sh 'package-mutation.v1.lock'
require_text scripts/release/install-macos.sh 'test "$(stat -f %z "$mutation_lock")" -eq 0'
require_text scripts/release/install-macos.sh 'legacy_unlocked_lifecycle=no'
require_text scripts/release/install-macos.sh '5dcdpm6bdsp5jxlw3vdgljhyapr5uhah5aewm42lqgjlmsca6s7a:31dd7799d78a53079c6f651864655706364e6aa27adcc223433a2dbc5eb9ba30'
require_text scripts/release/install-macos.sh 'resy4feogxdah3vtv3fnctmh7thp2vkopf5p3c45b7jrzxaj4nta:317ecb9eb24adfb2b0e70a600309209ddc9dd8ee0b2132bdfa9bed0b58f33c19'
require_text scripts/release/install-macos.sh 'aceg34dlxq7yo7tdbtmzbwwvlhdhfaeuis2dcct4k32kar5dj3na:a6793d0acc506e6824d76a0841beb29d30fc18ade0d8cc0f3fec818a1d49f653'
require_text scripts/release/install-macos.sh 'current_release" = "$release_id'
require_text scripts/release/install-macos.sh 'selected predecessor is not an authenticated supported macOS upgrade source'
require_text scripts/release/install-macos.sh '(set -C; : > "$mutation_lock")'
require_text scripts/release/install-macos.sh '/usr/bin/lockf -k -n -t 0 "$mutation_lock"'
require_text scripts/release/install-macos.sh 'provisioner release directory metadata is invalid'
require_text scripts/release/install-macos.sh 'public_frontend="$bin_directory/owntransit-cli"'
require_text scripts/release/install-macos.sh 'package finalizer did not publish a regular normal client frontend'
require_text scripts/release/install-macos.sh 'normal client frontend activation is invalid'
require_text scripts/release/install-macos.sh 'normal non-setgid setup frontend:'
require_text cmd/owntransitctl/package_finalize_identity.go 'schema=owntransit.macos-client-launcher.v1'
require_text cmd/owntransitctl/package_finalize_darwin.go 'securefs.OpenViewRoot(darwinLauncherAuthRoot, readerGID)'
require_text cmd/owntransitctl/package_finalize_darwin.go 'publishDarwinClientLauncher(receipt, result.Runtime)'
require_text cmd/owntransitctl/package_frontend_darwin.go 'darwinClientFrontendName      = "owntransit-cli"'
require_text cmd/owntransitctl/package_frontend_darwin.go 'darwinClientFrontendStageName = "client-frontend.v1.stage"'
require_text cmd/owntransitctl/package_frontend_darwin.go 'openDarwinOwnedDirectory(darwinClientLauncherStageRoot, 0, 0, 0o700)'
require_text cmd/owntransitctl/package_frontend_darwin.go 'removeRecoverableDarwinFrontendStage(int(stage.Fd()))'
require_text cmd/owntransitctl/package_frontend_darwin.go 'unix.Renameat(int(stage.Fd()), darwinClientFrontendStageName, int(bin.Fd()), darwinClientFrontendName)'
require_text cmd/owntransitctl/package_finalize_darwin.go 'publishDarwinClientFrontend(receipt, result.Runtime)'
require_text cmd/owntransitctl/package_provisioner_darwin.go 'darwinProvisionerFrontendStageName  = "provisioner-frontend.v1.stage"'
require_text cmd/owntransitctl/package_provisioner_darwin.go 'darwinLegacyProvisionerFrontendLink = "../roles/provisioner/current/owntransit-provision"'
require_text cmd/owntransitctl/package_provisioner_darwin.go 'published Darwin provisioner is a hard link to the protected release artifact'
require_text cmd/owntransitctl/package_launcher_darwin.go 'darwinClientLauncherStageRoot  = "/Library/OwnTransit/launcher-stage"'
require_text cmd/owntransitctl/package_launcher_darwin.go 'openDarwinOwnedDirectory(darwinClientLauncherStageRoot, 0, 0, 0o700)'
require_text cmd/owntransitctl/package_launcher_darwin.go 'unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600'
require_text cmd/owntransitctl/package_launcher_darwin.go '// chown must precede chmod: changing ownership clears setgid on macOS.'
require_text cmd/owntransitctl/package_launcher_darwin.go 'unix.Fchown(fd, 0, int(identity.readerGID))'
require_text cmd/owntransitctl/package_launcher_darwin.go 'unix.Fchmod(fd, 0o2751)'
require_text cmd/owntransitctl/package_launcher_darwin.go 'published Darwin launcher is a hard link to the protected release launcher'
require_text cmd/owntransitctl/package_launcher_darwin.go 'runtimeIdentity.LauncherSHA256'
require_text cmd/owntransitctl/package_launcher_darwin.go 'stat.Gid == readerGID && permissions == 0o600 && stat.Size > 0'
require_text cmd/owntransitctl/package_launcher_darwin.go 'opened.Nlink < 1'
launcher_chown_line=$(grep -nF 'unix.Fchown(fd, 0, int(identity.readerGID))' cmd/owntransitctl/package_launcher_darwin.go | cut -d: -f1)
launcher_chmod_line=$(grep -nF 'unix.Fchmod(fd, 0o2751)' cmd/owntransitctl/package_launcher_darwin.go | cut -d: -f1)
test "$launcher_chown_line" -lt "$launcher_chmod_line" || fail 'Darwin launcher staging must change ownership before applying setgid mode'
require_text internal/packagetxn/runtime_identity_unix.go 'LauncherSHA256: launcherDigest'
require_text internal/packagetxn/runtime_identity_unix.go 'file.ArtifactName != "launcher-darwin-arm64"'
require_text internal/packagetxn/transaction_unix.go 'func packageDirectoryProfile(manager *Manager) (uint32, uint32)'
require_text internal/packagetxn/transaction_unix.go 'manager.role == "provisioner" && manager.platformOS == "linux"'
require_text internal/packagetxn/transaction_unix.go 'return manager.ownerGID, 0o755'
require_text internal/packagetxn/transaction_unix.go 'return manager.readerGID, 0o750'
provisioner_installer=scripts/release/install-linux.sh
require_text "$provisioner_installer" 'require_provisioner_package_directory()'
require_text "$provisioner_installer" 'migrate_legacy_provisioner_directories()'
require_text "$provisioner_installer" '750|755) ;;'
require_text "$provisioner_installer" 'test "$role" = provisioner && test "$current_release" = "$release_id"'
require_text "$provisioner_installer" 'test "$(sha256_file "$lifecycle_runner")" = "$lifecycle_sha256"; then'
require_text "$provisioner_installer" 'chmod 0755 "$provisioner_release_directory"'
require_text "$provisioner_installer" 'chmod 0755 "$provisioner_releases_directory"'
require_text "$provisioner_installer" 'chmod 0755 "$provisioner_role_directory"'
test "$(grep -Fc 'migrate_legacy_provisioner_directories' "$provisioner_installer")" -eq 3 ||
  fail "$provisioner_installer must define, resume and post-apply the provisioner directory migration"
provisioner_release_chmod=$(grep -nF 'chmod 0755 "$provisioner_release_directory"' "$provisioner_installer" | cut -d: -f1)
provisioner_releases_chmod=$(grep -nF 'chmod 0755 "$provisioner_releases_directory"' "$provisioner_installer" | cut -d: -f1)
provisioner_role_chmod=$(grep -nF 'chmod 0755 "$provisioner_role_directory"' "$provisioner_installer" | cut -d: -f1)
test "$provisioner_release_chmod" -lt "$provisioner_releases_chmod" &&
  test "$provisioner_releases_chmod" -lt "$provisioner_role_chmod" ||
  fail "$provisioner_installer must migrate provisioner package directories inner-first"
if grep -Fq 'migrate_legacy_provisioner_directories' scripts/release/install-macos.sh; then
  fail 'macOS provisioner package tree must remain protected rather than migrated public'
fi
require_text internal/packagetxn/lifecycle_unix.go 'manager.verifyRunningLifecycle(snapshot, decision{})'
require_text cmd/owntransitctl/package_lifecycle.go 'guard, err := acquireNativePackageMutationGuard(options.role)'
require_text cmd/owntransitctl/package_mutation_guard_darwin.go 'darwinPackageMutationLockName = "package-mutation.v1.lock"'
require_text cmd/owntransitctl/package_mutation_guard_darwin.go 'unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)'
require_text cmd/owntransitctl/package_mutation_guard_linux.go 'fs.protected_hardlinks=1'
require_text scripts/release/install-linux.sh 'Linux provisioner installation requires fs.protected_hardlinks=1'
recover_complete_block=$(awk '
  /if snapshot.state.journal == nil \|\| snapshot.state.journal.Phase == phaseComplete \{/ { capture = 1 }
  capture { print }
  capture && /return resultForSnapshot/ { exit }
' internal/packagetxn/lifecycle_unix.go)
printf '%s\n' "$recover_complete_block" | grep -Fq 'manager.verifyRunningLifecycle(snapshot, decision{})' ||
  fail 'idempotent package recovery does not authenticate the running lifecycle'
require_text cmd/owntransit-launcher/main.go 'validateCurrent: validateInstalledCurrentRelease'
require_text cmd/owntransit-launcher/main.go 'launcherExecutable  = "/Library/OwnTransit/bin/owntransit"'
require_text cmd/owntransit-launcher/main.go 'validateSelf:    validateInstalledLauncherSelf'
require_text cmd/owntransit-launcher/main.go 'executable != launcherExecutable'
require_text cmd/owntransit-launcher/main.go 'stat.Nlink >= 1'
require_text cmd/owntransitctl/setup_identity_darwin.go 'stat.Nlink < 1'
require_text cmd/owntransit-launcher/main.go 'roleRoot.ReadRootSymlink(clientCurrentName, len(want))'
require_text cmd/owntransit-launcher/main.go 'installed client is not a single-link root:reader 0750 bounded regular file'
require_text cmd/owntransit-launcher/main.go 'os.Open("/dev/fd")'
require_text cmd/owntransit-launcher/main.go 'directory.Readdirnames(-1)'
require_text cmd/owntransit-launcher/main.go 'unix.F_SETFD, unix.FD_CLOEXEC'
require_text scripts/release/install-macos.sh 'ordinary client-user process can read the protected launcher binding'
require_text scripts/release/install-macos.sh '"$public_launcher" --qualify-reader-gid'
require_text scripts/release/install-macos.sh '/usr/bin/sudo -n -u "#$target_uid"'
require_text scripts/release/install-macos.sh 'unrelated user is unexpectedly a reader-group member'
require_text scripts/release/install-macos.sh 'installation root contains a setuid file'
require_text scripts/release/install-macos.sh 'manual residue review is required'
require_text scripts/release/install-macos.sh 'macos_mode_raw=$(stat -f %p -- "$1")'
require_text scripts/release/install-macos.sh '"$((0$macos_mode_raw & 07777))"'
require_text scripts/release/install-macos.sh 'for (field_number = 1; field_number <= NF; field_number++)'
if grep -Eq 'for \(index[[:space:]]*=' scripts/release/install-macos.sh; then
  fail 'macOS installer assigns to the awk index builtin'
fi
require_text scripts/release/uninstall-macos.sh 'manager-owned current/previous selectors'
require_text scripts/release/uninstall-macos.sh '"$release_directory/owntransitctl" package-detach --role "$role"'
require_text scripts/release/uninstall-macos.sh 'package detach left the public role entry'
require_text cmd/owntransitctl/package_detach_darwin.go '[]uint32{0o2751, 0o751}'
require_text cmd/owntransitctl/package_detach_darwin.go 'deactivates every retained hard-link alias'
require_text cmd/owntransitctl/package_detach_darwin.go 'syncDetachedDarwinName'
require_text scripts/release/uninstall-macos.sh 'destructive reader-identity purge is intentionally not implemented'
require_text scripts/release/uninstall-macos.sh 'macos_mode_raw=$(stat -f %p -- "$1")'
require_text scripts/release/uninstall-macos.sh '"$((0$macos_mode_raw & 07777))"'
if grep -Fq '%Lp' scripts/release/install-macos.sh scripts/release/uninstall-macos.sh; then
  fail 'macOS install or uninstall mode check hides special permission bits'
fi
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
for linux_package_script in scripts/release/install-linux.sh scripts/release/uninstall-linux.sh; do
  require_text "$linux_package_script" '/var/lib/owntransit/package-supervisor'
  require_text "$linux_package_script" 'platform.v1.lock'
  require_text "$linux_package_script" '/usr/bin/flock -n 9'
  require_text "$linux_package_script" "/proc/\$\$/fd/9"
  require_text "$linux_package_script" "stat -Lc '%d:%i:%u:%g:%a:%h:%s'"
done
require_text scripts/release/install-linux.sh 'ensure_root_directory /var/lib/owntransit/package-supervisor 700'
require_text scripts/release/uninstall-linux.sh '"$selected_lifecycle" package-recover --role "$role"'
require_text scripts/release/uninstall-linux.sh '/usr/bin/flock -n 8'
require_text scripts/release/uninstall-linux.sh 'assert_selected_release'
require_text scripts/release/uninstall-linux.sh 'validate_integration_residue'
require_text scripts/release/uninstall-linux.sh 'client launcher remains after detach'
require_text scripts/release/uninstall-linux.sh 'relay exchange unit remains after detach'

install_lock_line=$(grep -nF 'acquire_platform_mutation_lock' scripts/release/install-linux.sh | tail -1 | cut -d: -f1)
install_mutation_line=$(grep -nF 'ensure_root_directory /usr/local 755' scripts/release/install-linux.sh | cut -d: -f1)
test -n "$install_lock_line" && test -n "$install_mutation_line" && test "$install_lock_line" -lt "$install_mutation_line" ||
  fail 'Linux installer must hold the platform lock before package integration mutation'
uninstall_lock_line=$(grep -nF '/usr/bin/flock -n 9' scripts/release/uninstall-linux.sh | cut -d: -f1)
uninstall_selector_line=$(grep -nF 'current_link="$install_root/roles/$role/current"' scripts/release/uninstall-linux.sh | cut -d: -f1)
test -n "$uninstall_lock_line" && test -n "$uninstall_selector_line" && test "$uninstall_lock_line" -lt "$uninstall_selector_line" ||
  fail 'Linux uninstaller must hold the platform lock before selector inspection'
uninstall_role_lock_line=$(grep -nF '/usr/bin/flock -n 8' scripts/release/uninstall-linux.sh | cut -d: -f1)
uninstall_service_mutation_line=$(grep -nF 'exchange_units=$(systemctl list-units' scripts/release/uninstall-linux.sh | cut -d: -f1)
test -n "$uninstall_role_lock_line" && test -n "$uninstall_service_mutation_line" && test "$uninstall_role_lock_line" -lt "$uninstall_service_mutation_line" ||
  fail 'Linux service-role detach must hold the supervisor lock before systemd mutation'
if grep -Eq '^[[:space:]]*(rm|rmdir)[[:space:]].*(platform\.v1\.lock|package-supervisor)' scripts/release/install-linux.sh scripts/release/uninstall-linux.sh; then
  fail 'Linux platform mutation lock and its root must persist across install and uninstall'
fi

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
require_text cmd/owntransitctl/package_supervisor_linux.go 'transitionPackageSupervisorRecord(supervisor.intentRoot, supervisor.role, "intent", "restart")'
require_text cmd/owntransitctl/package_supervisor_linux.go 'transitionPackageSupervisorRecord(supervisor.intentRoot, supervisor.role, "restart", "intent")'
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
require_text deploy/vps/Containerfile.relay 'Legacy amd64-only POC wrapper; it is not a release packaging path.'
require_text scripts/build-relay-amd64.sh 'Legacy amd64-only POC helper.'
require_text scripts/build-native-connector-amd64.sh 'Legacy amd64-only POC helper.'
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
  owntransit-provision-linux-amd64 \
  owntransit-linux-arm64 \
  owntransit-connector-linux-arm64 \
  owntransit-relay-linux-arm64.oci.tar \
  owntransitctl-linux-arm64 \
  owntransit-provision-linux-arm64; do
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
require_text scripts/release/build-artifacts.sh 'linux/amd64|linux/arm64)'
require_text scripts/release/build-artifacts.sh 'exact fourteen-artifact matrix'
require_text scripts/release/make-relay-oci.sh 'architecture must be amd64 or arm64'
require_text scripts/release/make-relay-oci.sh '\"architecture\":\"$architecture\"'
require_text scripts/release/install.sh 'Linux/aarch64|Linux/arm64)'
require_text scripts/release/install.sh 'lifecycle_path="artifacts/owntransitctl-$platform-$platform_arch"'
require_text scripts/release/install-linux.sh 'aarch64|arm64) platform_arch=arm64'
require_text scripts/release/install-linux.sh 'artifact_name="owntransit-connector-linux-$platform_arch"'
require_text scripts/release/install-linux.sh 'lifecycle_path="artifacts/owntransitctl-linux-$platform_arch"'
require_text internal/enrollment/request.go 'binding.OS == "linux" && supportedLinuxArch(binding.Arch)'
require_text internal/packagetxn/lifecycle_unix.go 'case "connector/linux/arm64":'
require_text cmd/owntransitctl/relay_oci_linux.go 'relayOCIPlatform{Architecture: expectedArch, OS: "linux"}'
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
require_text scripts/release/archive-native.sh 'elif command -v container >/dev/null 2>&1; then'
require_text scripts/release/archive-native.sh '--mount "type=bind,source=$container_output,target=/output"'
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
  fail 'native archive container output must not expose a writable alias to the read-only snapshot'
fi

require_text scripts/release/sign-candidate.sh 'release and policy public key IDs must be different'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires release sequence 13'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires policy sequence 9'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires release floor 13'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires lifecycle floor 1'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires RC7 anchor policy sequence 3'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires RC7 anchor release floor 5'
require_text scripts/release/sign-candidate.sh 'OwnTransit 0.1.0 requires RC7 anchor lifecycle floor 1'
require_text scripts/release/sign-candidate.sh 'Signature issuance consumes its release and policy sequences even'
require_text scripts/tests/sign-candidate.sh 'a rejected 0.1.0 stable tuple reached a signing operation'
require_text scripts/tests/sign-candidate.sh 'burned-private-scope-candidate-anchor'
require_text scripts/tests/sign-candidate.sh 'burned-private-live-candidate-anchor'
require_text scripts/tests/sign-candidate.sh 'burned-private-custody-candidate-anchor'
require_text packaging/macos/sign-checksums.sh '--preflight-only'
require_text scripts/release/sign-candidate.sh 'distribution key custody preflight failed'
require_text scripts/release/sign-candidate.sh 'verify-keypair --private-key "$release_private_key"'
require_text scripts/release/sign-candidate.sh 'verify-keypair --private-key "$policy_private_key"'
require_text scripts/release/sign-candidate.sh 'candidate signing preflight passed:'

release_keypair_preflight_line=$(grep -nF 'verify-keypair --private-key "$release_private_key"' scripts/release/sign-candidate.sh | head -n 1 | cut -d: -f1)
policy_keypair_preflight_line=$(grep -nF 'verify-keypair --private-key "$policy_private_key"' scripts/release/sign-candidate.sh | head -n 1 | cut -d: -f1)
distribution_custody_preflight_line=$(grep -nF 'fail "distribution key custody preflight failed"' scripts/release/sign-candidate.sh | head -n 1 | cut -d: -f1)
first_candidate_signature_line=$(grep -nF '"$releasectl" sign-manifest' scripts/release/sign-candidate.sh | head -n 1 | cut -d: -f1)
for preflight_line in "$release_keypair_preflight_line" "$policy_keypair_preflight_line" "$distribution_custody_preflight_line"; do
  test -n "$preflight_line" && test -n "$first_candidate_signature_line" &&
    test "$preflight_line" -lt "$first_candidate_signature_line" ||
    fail 'candidate key preflight must run before the first sequence-consuming signature'
done
require_text scripts/release/build-artifacts.sh 'committed CHANGELOG.md has no exact release heading for $version'
require_text scripts/release/build-artifacts.sh 'git -C "$checkout_root" archive --format=tar --output="$source_archive" "$source_commit"'
require_text scripts/release/build-artifacts.sh 'project_root=$source_root'
require_text scripts/release/sign-candidate.sh 'committed CHANGELOG.md has no exact release heading for $version'
require_text scripts/release/sign-candidate.sh 'git -C "$source_root" ls-tree "$source_commit" -- CHANGELOG.md'
require_text scripts/tests/sign-candidate.sh 'candidate signing accepted a commit without its exact changelog release heading'
require_text .github/workflows/release-candidate.yml 'runs-on: macos-15'
require_text .github/workflows/release-candidate.yml 'test "$(uname -m)" = arm64'
require_text .github/workflows/release-candidate.yml 'runner: ubuntu-24.04-arm'
require_text .github/workflows/release-candidate.yml 'arch: arm64'
require_text .github/workflows/release-candidate.yml 'go-version: 1.26.7'
require_text .github/workflows/release-candidate.yml 'go test -mod=readonly -race ./...'
require_text .github/workflows/release-candidate.yml 'go test -mod=readonly -race -tags=owntransit_poc_ssh ./...'
require_text .github/workflows/release-candidate.yml 'go vet -mod=readonly ./...'
require_text .github/workflows/release-candidate.yml 'go vet -mod=readonly -tags=owntransit_poc_ssh ./...'
grep -Fxq '    name: Go security profiles' .github/workflows/release-candidate.yml ||
  fail 'workflow is missing the stable required Go security aggregate context'
grep -Fxq '    name: rendered Homebrew formula' .github/workflows/release-candidate.yml ||
  fail 'workflow is missing the stable required Homebrew context'
require_text .github/workflows/release-candidate.yml 'MATRIX_RESULT: ${{ needs.go-security.result }}'
require_text scripts/security-check.sh 'for linux_arch in amd64 arm64; do'
test "$(grep -Fc 'container build --progress plain --platform "linux/$linux_arch"' scripts/security-check.sh)" -eq 5 ||
  fail 'Apple Container full security gates must run all five stages for each supported Linux architecture'
test "$(grep -Fc 'docker buildx build --progress plain --platform "linux/$linux_arch"' scripts/security-check.sh)" -eq 5 ||
  fail 'Docker full security gates must run all five stages for each supported Linux architecture'
require_text Containerfile 'AS linux-verify'
require_text Containerfile 'case "$TARGETOS/$TARGETARCH" in linux/amd64|linux/arm64)'
require_text Containerfile 'test "$(go env GOOS)/$(go env GOARCH)" = "$TARGETOS/$TARGETARCH"'
test "$(grep -Ec '^FROM linux-verify AS (test|test-poc|vet|vulncheck|dependency-licenses)$' Containerfile)" -eq 5 ||
  fail 'all five verification stages must execute from the exact supported Linux target-platform source stage'
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
require_text scripts/release/sign-qualification-record.sh 'results file does not contain the exact fixed sorted stable 0.1.0 gate set'
require_text scripts/release/sign-qualification-record.sh 'schema=owntransit.qualification.v1'
require_text scripts/release/sign-qualification-record.sh 'gate_set=owntransit-0.1.0-minimal.v1'
require_text scripts/release/sign-qualification-record.sh '--native-checksums'
require_text scripts/release/sign-qualification-record.sh '--trust-root'
require_text scripts/release/sign-qualification-record.sh '--evidence-root'
require_text scripts/release/sign-qualification-record.sh 'native asset inventory authentication failed'
require_text scripts/release/sign-qualification-record.sh 'handoff trust statement authentication failed'
require_text scripts/release/sign-qualification-record.sh 'validate-qualification-evidence.sh'
require_text scripts/release/sign-qualification-record.sh 'validated evidence digest does not match the results file'
require_text scripts/release/sign-qualification-record.sh 'evidence root contains an unexpected entry'
require_text scripts/release/sign-qualification-record.sh 'results file contains a non-canonical byte'
require_text scripts/release/validate-qualification-evidence.sh 'schema owntransit.qualification-evidence.v1'
require_text scripts/tests/testdata/qualification-evidence/supported-artifact-execution.txt 'artifact_connector_linux_amd64_sha256='
require_text scripts/tests/testdata/qualification-evidence/supported-artifact-execution.txt 'artifact_connector_linux_arm64_sha256='
require_text scripts/release/validate-qualification-evidence.sh 'running connector digest does not match the signed connector artifact'
require_text scripts/release/validate-qualification-evidence.sh 'macos_arm64_client_lifecycle'
require_text scripts/release/validate-qualification-evidence.sh 'macos_provisioner_package_lifecycle'
require_text scripts/release/validate-qualification-evidence.sh 'linux_client_package_lifecycle'
require_text scripts/release/validate-qualification-evidence.sh 'linux_provisioner_package_lifecycle'
require_text scripts/release/validate-qualification-evidence.sh 'macos_arm64_system_mutation NONE'
require_text scripts/release/validate-qualification-evidence.sh 'client_configuration_unchanged'
require_text scripts/release/validate-qualification-evidence.sh 'operator_ssh_key_unchanged'
require_text scripts/release/validate-qualification-evidence.sh 'connector_configuration_unchanged'
require_text scripts/release/validate-qualification-evidence.sh 'connector_endpoint_credentials_unchanged'
require_text scripts/release/validate-qualification-evidence.sh 'linux_relay_package_lifecycle'
require_text scripts/release/validate-qualification-evidence.sh 'pristine_host'
require_text scripts/release/validate-qualification-evidence.sh 'enrollment'
require_text scripts/release/validate-qualification-evidence.sh 'does not match the authenticated inventory'
require_text scripts/release/validate-qualification-evidence.sh 'contains a non-canonical byte'
for qualification_gate in \
  live-ssh-scp-path \
  release-signatures \
  source-security-publication \
  supported-artifact-execution; do
  require_text scripts/release/sign-qualification-record.sh "$qualification_gate"
  require_text scripts/tests/qualification-record.sh "$qualification_gate|PASS|"
done
require_text scripts/release/sign-qualification-record.sh 'qualification_status=BLOCKED'
require_text scripts/release/sign-qualification-record.sh 'unresolved_critical'
require_text scripts/release/sign-qualification-record.sh 'unresolved_high'
require_text scripts/tests/qualification-record.sh 'qualification record canonical signing and fail-closed tests passed'
require_text scripts/tests/qualification-evidence.sh 'qualification evidence canonical validation and fail-closed tests passed'
if grep -Eq 'ssh-keygen[[:space:]].*-t' \
  scripts/release/sign-qualification-record.sh \
  scripts/release/validate-qualification-evidence.sh; then
  fail 'qualification record helpers must never generate a signing key'
fi

if grep -Eq 'chmod.*2750|system.*sudo' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must never setgid or sudo a Cellar binary'
fi
require_text packaging/homebrew/owntransit.rb.in '# frozen_string_literal: true'
require_text packaging/homebrew/owntransit.rb.in 'formula_opt_bin("go@1.26")'
if grep -Fq 'Formula["go@1.26"].opt_bin' packaging/homebrew/owntransit.rb.in; then
  fail 'Homebrew formula must use the current formula path helper'
fi

require_text scripts/qualify/linux-vm-core.sh '--manifest-signature "$manifest_signature"'
require_text scripts/qualify/linux-vm-core.sh '--policy-public-key "$policy_public_key"'
require_text scripts/qualify/linux-vm-core.sh '/usr/libexec/owntransit/roles/connector/current/owntransitctl'
require_text scripts/qualify/linux-vm-core.sh '/usr/libexec/owntransit/roles/connector/current/owntransit-connector'
require_text scripts/qualify/linux-vm-core.sh '-relay-listen 0.0.0.0:9087'
require_text scripts/qualify/macos-client-boundary.sh 'role_root="$roles_root/client"'
require_text scripts/qualify/macos-client-boundary.sh 'public_launcher="$bin_directory/owntransit"'
require_text scripts/qualify/macos-client-boundary.sh 'test -f "$public_launcher" && test ! -L "$public_launcher"'
if grep -Fq -- '/usr/libexec/owntransit/bin/' scripts/qualify/linux-vm-core.sh ||
   grep -Fq -- '/Library/OwnTransit/releases/' scripts/qualify/macos-client-boundary.sh packaging/macos/CLIENT_READER_BOUNDARY.md; then
  fail 'qualification material still references a pre-manager shared release path'
fi

printf '%s\n' 'release packaging static checks passed'
