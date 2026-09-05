#!/bin/sh
set -eu

fail() {
  printf 'install-linux-bootstrap-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
source_installer=$project_root/install-linux.sh
test -f "$source_installer" || fail "root Linux installer is missing"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-linux-bootstrap-test.XXXXXX") ||
  fail "cannot create test root"
case "$test_root" in
  *[!A-Za-z0-9_./-]*) fail "test root contains unsafe characters" ;;
esac
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  case "$test_root" in
    "${TMPDIR:-/tmp}"/owntransit-linux-bootstrap-test.*)
      rm -rf -- "$test_root" || status=1
      ;;
    *)
      printf 'install-linux-bootstrap-test: refusing unsafe cleanup: %s\n' "$test_root" >&2
      status=1
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT HUP INT TERM

fake_bin=$test_root/tools
stage_root=$test_root/staging-root
systemd_root=$test_root/systemd-system
podman_bin=$fake_bin/podman-system
podman_path=$podman_bin/podman
custom_podman_path=$fake_bin/podman
podman_alias_bin=$fake_bin/usr-merge-alias
podman_alias_path=$podman_alias_bin/podman
local_bin_podman=$test_root/usr-local-bin-podman
local_sbin_podman=$test_root/usr-local-sbin-podman
snap_bin_podman=$test_root/snap-bin-podman
protected_hardlinks=$test_root/protected_hardlinks
apt_get_path=$fake_bin/apt-get
debian_marker=$test_root/debian-version
ca_bundle=$test_root/ca-certificates.crt
output_root=$test_root/output
mkdir -p "$fake_bin" "$podman_bin" "$podman_alias_bin" "$stage_root" "$systemd_root" "$output_root"
printf '%s\n' test-debian > "$debian_marker"
printf '%s\n' test-ca-bundle > "$ca_bundle"

cat > "$fake_bin/id" <<'EOF'
#!/bin/sh
case "$1:$#" in
  -u:1)
    printf '0\n'
    ;;
  -u:2)
    case "$2" in
      alice) printf '1000\n' ;;
      bob) printf '1001\n' ;;
      *) exit 1 ;;
    esac
    ;;
  -un:2)
    if test -n "${OT_TEST_CANONICAL_USER-}"; then
      printf '%s\n' "$OT_TEST_CANONICAL_USER"
    else
      case "$2" in
        1000) printf 'alice\n' ;;
        1001) printf 'bob\n' ;;
        *) exit 1 ;;
      esac
    fi
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$fake_bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 1 ;;
esac
EOF

cat > "$fake_bin/stat" <<'EOF'
#!/bin/sh
test "$#" -eq 3 && test "$1" = -c || exit 1
case "$2" in
  %u) printf '0\n' ;;
  %h) printf '1\n' ;;
  %a)
    case "$3" in
      "$OT_TEST_STAGE_ROOT"/owntransit-install-v0.1.0.*) printf '700\n' ;;
      *) printf '755\n' ;;
    esac
    ;;
  *) exit 1 ;;
esac
EOF

cat > "$fake_bin/mktemp" <<'EOF'
#!/bin/sh
test "$#" -eq 2 && test "$1" = -d || exit 1
case "$2" in
  *XXXXXXXX) destination=${2%XXXXXXXX}TEST0001 ;;
  *) exit 1 ;;
esac
mkdir "$destination" || exit 1
printf '%s\n' "$destination"
EOF

cat > "$fake_bin/install" <<'EOF'
#!/bin/sh
test "$#" -ge 2 && test "$1" = -d || exit 90
for argument in "$@"; do
  case "$argument" in
    "$OT_TEST_STAGE_ROOT"/*) mkdir -p "$argument" || exit 1 ;;
  esac
done
EOF

cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
output=
while test "$#" -gt 0; do
  case "$1" in
    --output)
      test "$#" -ge 2 || exit 2
      output=$2
      shift 2
      ;;
    *) shift ;;
  esac
done
test -n "$output" || exit 2
fixture_bin=$(dirname "$0")
printf '%s\n' download >> "$fixture_bin/events"
case "$(cat "$fixture_bin/curl-mode")" in
  bad-size)
    printf x > "$output"
    ;;
  bad-hash)
    awk 'BEGIN { for (i = 0; i < 318; i++) printf "x" }' > "$output"
    ;;
  valid)
    printf x > "$output"
    ;;
  *) exit 2 ;;
esac
EOF

cat > "$fake_bin/tar" <<'EOF'
#!/bin/sh
fixture_bin=$(dirname "$0")
printf '%s\n' extract >> "$fixture_bin/events"
test "$(cat "$fixture_bin/curl-mode")" = valid || exit 91
destination=
while test "$#" -gt 0; do
  case "$1" in
    --directory)
      test "$#" -ge 2 || exit 2
      destination=$2
      shift 2
      ;;
    *) shift ;;
  esac
done
test -n "$destination" || exit 2
entrypoint=$destination/owntransit-0.1.0-native/packaging/scripts/install.sh
mkdir -p "$(dirname "$entrypoint")" || exit 1
cat > "$entrypoint" <<'INNER'
#!/bin/sh
fixture_bin=${PATH%%:*}
printf 'signed-install' >> "$fixture_bin/events"
for argument in "$@"; do
  printf ':%s' "$argument" >> "$fixture_bin/events"
done
printf '\n' >> "$fixture_bin/events"
exit 94
INNER
chmod 0755 "$entrypoint"
EOF

write_fake_apt_get() {
  cat > "$apt_get_path" <<'EOF'
#!/bin/sh
fixture_bin=$(dirname "$0")
mode=$(cat "$fixture_bin/apt-mode")
test "${NEEDRESTART_MODE-}" = l || exit 43
case " $* " in
  *' update '*)
    printf '%s\n' apt:update >> "$fixture_bin/events"
    test "$mode" != update-fail || exit 40
    ;;
  *' install '*)
    {
      printf 'apt:install'
      for argument in "$@"; do
        printf ':%s' "$argument"
      done
      printf '\n'
    } >> "$fixture_bin/events"
    test "$mode" != install-fail || exit 41
    case " $* " in
      *' podman '*)
        podman_target=$(cat "$fixture_bin/podman-target")
        printf '%s\n' '#!/bin/sh' 'exit 93' > "$podman_target"
        chmod 0755 "$podman_target"
        ;;
    esac
    ;;
  *) exit 42 ;;
esac
EOF
  chmod 0755 "$apt_get_path"
}

write_fake_podman() {
  printf '%s\n' '#!/bin/sh' 'exit 93' > "$podman_path"
  chmod 0755 "$podman_path"
}

if command -v sha256sum >/dev/null 2>&1; then
  digest_tool=$(command -v sha256sum)
  cat > "$fake_bin/sha256sum" <<EOF
#!/bin/sh
exec "$digest_tool" "\$@"
EOF
elif command -v shasum >/dev/null 2>&1; then
  digest_tool=$(command -v shasum)
  cat > "$fake_bin/sha256sum" <<EOF
#!/bin/sh
exec "$digest_tool" -a 256 "\$@"
EOF
else
  fail "a SHA-256 utility is required for the offline test"
fi

# These utilities are Linux installer preflight dependencies but are not
# reached by the download-failure scenarios. Always shadow their host copies:
# an accidental future invocation must fail inside the fixture, never operate
# on the machine running this offline test.
for command_name in flock getent groupadd useradd usermod systemctl; do
  cat > "$fake_bin/$command_name" <<'EOF'
#!/bin/sh
exit 92
EOF
done

chmod 0755 "$fake_bin"/*
printf '%s\n' "$podman_path" > "$fake_bin/podman-target"
printf '%s\n' bad-size > "$fake_bin/curl-mode"
: > "$fake_bin/events"

fixture_installer=$test_root/install-linux.fixture.sh
# Lookup scenarios must not inherit a real Podman from the runner's PATH.
# The executable PATH below still provides ordinary host utilities.
sed \
  -e "s#^caller_path=.*#caller_path=\${OT_TEST_CALLER_PATH-$podman_bin}#" \
  -e "s#^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$#PATH=$fake_bin:$podman_bin:/usr/sbin:/usr/bin:/sbin:/bin#" \
  -e "s#^require_protected_ancestor /var\$#require_protected_ancestor $stage_root#" \
  -e "s#/run/systemd/system#$systemd_root#g" \
  -e "s#/usr/local/bin/podman#$local_bin_podman#g" \
  -e "s#/usr/local/sbin/podman#$local_sbin_podman#g" \
  -e "s#/snap/bin/podman#$snap_bin_podman#g" \
  -e "s#/usr/bin/podman#$podman_path#g" \
  -e "s#/bin/podman#$podman_alias_path#g" \
  -e "s#/proc/sys/fs/protected_hardlinks#$protected_hardlinks#g" \
  -e "s#/usr/bin/apt-get#$apt_get_path#g" \
  -e "s#/etc/debian_version#$debian_marker#g" \
  -e "s#/etc/ssl/certs/ca-certificates.crt#$ca_bundle#g" \
  -e "s#/var/lib#$stage_root#g" \
  "$source_installer" > "$fixture_installer"
chmod 0755 "$fixture_installer"

authenticated_fixture_installer=$test_root/install-linux.authenticated-fixture.sh
fixture_byte_sha256=2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881
sed -E \
  -e "/^fetch_pinned / s/ [0-9]+ [0-9a-f]{64}$/ 1 $fixture_byte_sha256/" \
  -e "s#d5f9ec458fc00c6a47a0eb7c46e2a0a5bade7e2ab95c5ad6e34c5fc256c1b2bc#$fixture_byte_sha256#g" \
  "$fixture_installer" > "$authenticated_fixture_installer"
chmod 0755 "$authenticated_fixture_installer"

export OT_TEST_STAGE_ROOT="$stage_root"
OT_TEST_CANONICAL_USER=alice
export OT_TEST_CANONICAL_USER

assert_no_download_or_stage() {
  test ! -s "$fake_bin/events" || fail "$1 reached a download or extraction"
  test -z "$(find "$stage_root" ! -path "$stage_root" -print)" ||
    fail "$1 left a staging tree"
}

assert_no_bootstrap_stage() {
  test ! -s "$fake_bin/events" || fail "$1 reached a download or extraction"
  test -z "$(find "$stage_root" -name 'owntransit-install-v0.1.0.*' -print)" ||
    fail "$1 created a bootstrap staging tree"
}

assert_clean_temporary_stage() {
  test -z "$(find "$stage_root" -name 'owntransit-install-v0.1.0.*' -print)" ||
    fail "$1 did not clean its bootstrap staging tree"
}

expect_failure() {
  case_name=$1
  expected_text=$2
  shift 2
  stdout=$output_root/$case_name.stdout
  stderr=$output_root/$case_name.stderr
  set +e
  "$@" > "$stdout" 2> "$stderr"
  result=$?
  set -e
  test "$result" -ne 0 || fail "$case_name unexpectedly succeeded"
  grep -Fq -- "$expected_text" "$stderr" || {
    cat "$stderr" >&2
    fail "$case_name failed for the wrong reason"
  }
}

: > "$fake_bin/events"
expect_failure missing-sudo-user 'client needs an explicit existing non-root local user' \
  env SUDO_USER= SUDO_UID= sh "$fixture_installer" client
assert_no_download_or_stage missing-sudo-user

: > "$fake_bin/events"
expect_failure missing-sudo-uid 'sudo did not provide a valid non-root caller identity' \
  env SUDO_USER=alice SUDO_UID= sh "$fixture_installer" client
assert_no_download_or_stage missing-sudo-uid

: > "$fake_bin/events"
expect_failure mismatched-sudo-identity 'sudo caller user and UID do not match' \
  env SUDO_USER=alice SUDO_UID=1001 sh "$fixture_installer" client
assert_no_download_or_stage mismatched-sudo-identity

: > "$fake_bin/events"
OT_TEST_CANONICAL_USER=bob
export OT_TEST_CANONICAL_USER
expect_failure noncanonical-sudo-identity 'sudo caller UID is not canonical for the client user' \
  env SUDO_USER=alice SUDO_UID=1000 OT_TEST_CANONICAL_USER=bob sh "$fixture_installer" client
assert_no_download_or_stage noncanonical-sudo-identity
OT_TEST_CANONICAL_USER=alice
export OT_TEST_CANONICAL_USER

: > "$fake_bin/events"
expect_failure missing-explicit-user 'client user does not exist: nobody-here' \
  env SUDO_USER= SUDO_UID= sh "$fixture_installer" client nobody-here
assert_no_download_or_stage missing-explicit-user

: > "$fake_bin/events"
expect_failure rejected-role 'usage:' sh "$fixture_installer" server
assert_no_download_or_stage rejected-role

: > "$fake_bin/events"
expect_failure connector-extra-argument 'usage:' sh "$fixture_installer" connector unexpected
assert_no_download_or_stage connector-extra-argument

: > "$fake_bin/events"
expect_failure client-extra-argument 'usage:' sh "$fixture_installer" client alice unexpected
assert_no_download_or_stage client-extra-argument

: > "$fake_bin/events"
expect_failure relay-extra-argument 'usage:' sh "$fixture_installer" relay unexpected
assert_no_download_or_stage relay-extra-argument

: > "$fake_bin/events"
expect_failure provisioner-extra-argument 'usage:' sh "$fixture_installer" provisioner unexpected
assert_no_download_or_stage provisioner-extra-argument

rmdir "$systemd_root"
: > "$fake_bin/events"
expect_failure connector-without-systemd 'the connector requires Linux running systemd' \
  sh "$fixture_installer" connector
assert_no_download_or_stage connector-without-systemd
mkdir "$systemd_root"

rm -f -- "$podman_path" "$custom_podman_path" "$podman_alias_path" \
  "$local_bin_podman" "$local_sbin_podman" "$apt_get_path"
: > "$fake_bin/events"
printf '%s\n' '#!/bin/sh' 'exit 93' > "$custom_podman_path"
chmod 0755 "$custom_podman_path"
expect_failure relay-with-custom-podman 'existing Podman uses an unsupported path:' \
  env OT_TEST_CALLER_PATH="$fake_bin:$podman_bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$fixture_installer" relay
assert_no_download_or_stage relay-with-custom-podman
rm -- "$custom_podman_path"

: > "$fake_bin/events"
printf '%s\n' '#!/bin/sh' 'exit 93' > "$local_bin_podman"
chmod 0755 "$local_bin_podman"
expect_failure relay-with-explicit-custom-podman 'existing Podman uses an unsupported path:' \
  sh "$fixture_installer" relay
assert_no_download_or_stage relay-with-explicit-custom-podman
rm -- "$local_bin_podman"

: > "$fake_bin/events"
expect_failure relay-without-supported-package-manager 'automatic Podman installation requires Debian or Ubuntu' \
  sh "$fixture_installer" relay
assert_no_download_or_stage relay-without-supported-package-manager

write_fake_apt_get
printf '%s\n' success > "$fake_bin/apt-mode"
printf '%s\n' bad-size > "$fake_bin/curl-mode"
: > "$fake_bin/events"
expect_failure corrupt-relay-release-does-not-install-podman 'download size mismatch: NATIVE-SHA256SUMS.sig' \
  sh "$fixture_installer" relay
test "$(cat "$fake_bin/events")" = download ||
  fail "corrupt relay release invoked apt, extraction, or installation"
test ! -e "$podman_path" || fail "corrupt relay release installed Podman"
assert_clean_temporary_stage corrupt-relay-release-does-not-install-podman

assert_authenticated_release_prefix() {
  event_file=$1
  case_name=$2
  test "$(grep -c '^download$' "$event_file" | tr -d '[:space:]')" = 17 ||
    fail "$case_name did not validate all seventeen pinned downloads before apt"
  test "$(sed -n '18p' "$event_file")" = extract ||
    fail "$case_name invoked apt before authenticated archive extraction"
}

printf '%s\n' update-fail > "$fake_bin/apt-mode"
printf '%s\n' valid > "$fake_bin/curl-mode"
: > "$fake_bin/events"
expect_failure relay-apt-update-failure 'apt-get update failed while preparing Podman' \
  sh "$authenticated_fixture_installer" relay
assert_authenticated_release_prefix "$fake_bin/events" relay-apt-update-failure
test "$(sed -n '19p' "$fake_bin/events")" = apt:update ||
  fail "relay apt update did not follow authenticated archive extraction"
test "$(wc -l < "$fake_bin/events" | tr -d '[:space:]')" = 19 ||
  fail "relay apt update failure performed an unexpected later action"
assert_clean_temporary_stage relay-apt-update-failure

printf '%s\n' install-fail > "$fake_bin/apt-mode"
: > "$fake_bin/events"
expect_failure relay-apt-install-failure 'apt-get could not install required package: podman' \
  sh "$authenticated_fixture_installer" relay
assert_authenticated_release_prefix "$fake_bin/events" relay-apt-install-failure
test "$(sed -n '19p' "$fake_bin/events")" = apt:update &&
  test "$(sed -n '20p' "$fake_bin/events")" = \
    'apt:install:-y:-qq:--no-remove:--no-install-recommends:install:podman' ||
  fail "relay apt install failure used an unexpected package operation"
test "$(wc -l < "$fake_bin/events" | tr -d '[:space:]')" = 20 ||
  fail "relay apt install failure reached the signed installer"
assert_clean_temporary_stage relay-apt-install-failure

printf '%s\n' success > "$fake_bin/apt-mode"
: > "$fake_bin/events"
expect_failure relay-installs-only-podman 'installation failed; see the details above' \
  sh "$authenticated_fixture_installer" relay
assert_authenticated_release_prefix "$fake_bin/events" relay-installs-only-podman
test "$(sed -n '19p' "$fake_bin/events")" = apt:update &&
  test "$(sed -n '20p' "$fake_bin/events")" = \
    'apt:install:-y:-qq:--no-remove:--no-install-recommends:install:podman' &&
  grep -Fq 'signed-install:' "$fake_bin/events" &&
  grep -Fq ':--role:relay' "$fake_bin/events" ||
  fail "missing-Podman relay bootstrap did not install only Podman before the signed role installer"
test -x "$podman_path" || fail "successful Podman prerequisite installation was not revalidated"
assert_clean_temporary_stage relay-installs-only-podman

printf '%s\n' bad-size > "$fake_bin/curl-mode"
: > "$fake_bin/events"
expect_failure relay-with-existing-dependencies 'download size mismatch: NATIVE-SHA256SUMS.sig' \
  sh "$fixture_installer" relay
test "$(cat "$fake_bin/events")" = download ||
  fail "relay with existing dependencies unexpectedly invoked apt or Podman"
assert_clean_temporary_stage relay-with-existing-dependencies

ln -s "$podman_path" "$podman_alias_path"
: > "$fake_bin/events"
expect_failure relay-with-usr-merge-alias 'download size mismatch: NATIVE-SHA256SUMS.sig' \
  env OT_TEST_CALLER_PATH="$podman_alias_bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    sh "$fixture_installer" relay
test "$(cat "$fake_bin/events")" = download ||
  fail "canonical usr-merge Podman alias was rejected or executed"
assert_clean_temporary_stage relay-with-usr-merge-alias
rm -- "$podman_alias_path"

rm -f -- "$protected_hardlinks"
: > "$fake_bin/events"
expect_failure provisioner-without-hardlink-policy 'the provisioner requires fs.protected_hardlinks=1' \
  sh "$fixture_installer" provisioner
assert_no_download_or_stage provisioner-without-hardlink-policy
printf '%s\n' 0 > "$protected_hardlinks"
: > "$fake_bin/events"
expect_failure provisioner-with-disabled-hardlink-policy 'the provisioner requires fs.protected_hardlinks=1' \
  sh "$fixture_installer" provisioner
assert_no_download_or_stage provisioner-with-disabled-hardlink-policy
printf '%s\n' 1 > "$protected_hardlinks"

supervisor_root=$stage_root/owntransit/package-supervisor
mkdir -p "$supervisor_root"
for pending_role in connector relay; do
  if test "$pending_role" = relay; then
    rm -f -- "$podman_path" "$custom_podman_path"
  fi
  for pending_state in intent restart; do
    pending_record=$supervisor_root/$pending_role.$pending_state
    printf '%s\n' 'preserve-this-recovery-record' > "$pending_record"
    before_record=$(cat "$pending_record")
    : > "$fake_bin/events"
    expect_failure "pending-$pending_role-$pending_state" "pending $pending_role package recovery exists" \
      sh "$fixture_installer" "$pending_role"
    assert_no_bootstrap_stage "pending-$pending_role-$pending_state"
    test -f "$pending_record" && test "$(cat "$pending_record")" = "$before_record" ||
      fail "pending-$pending_role-$pending_state altered or deleted the supervisor record"
    rm -- "$pending_record"
  done
done
rmdir "$supervisor_root" "$stage_root/owntransit"
write_fake_podman

assert_download_failure() {
  mode=$1
  expected_text=$2
  printf '%s\n' "$mode" > "$fake_bin/curl-mode"
  : > "$fake_bin/events"
  expect_failure "download-$mode" "$expected_text" \
    env SUDO_USER=alice SUDO_UID=1000 OT_TEST_CANONICAL_USER=alice \
      sh "$fixture_installer" client
  test "$(cat "$fake_bin/events")" = download ||
    fail "download-$mode reached extraction or an unexpected operation"
  test -z "$(find "$stage_root" ! -path "$stage_root" -print)" ||
    fail "download-$mode did not clean its exact staging tree"
}

assert_download_failure bad-size 'download size mismatch: NATIVE-SHA256SUMS.sig'
assert_download_failure bad-hash 'download checksum mismatch: NATIVE-SHA256SUMS.sig'

assert_role_reaches_download() {
  tested_role=$1
  : > "$fake_bin/events"
  printf '%s\n' bad-size > "$fake_bin/curl-mode"
  expect_failure "$tested_role-download" 'download size mismatch: NATIVE-SHA256SUMS.sig' \
    sh "$fixture_installer" "$tested_role"
  test "$(cat "$fake_bin/events")" = download ||
    fail "$tested_role did not reach its byte-pinned download without extra actions"
  assert_clean_temporary_stage "$tested_role-download"
}

assert_role_reaches_download connector
assert_role_reaches_download relay
assert_role_reaches_download provisioner

if grep -Eq '/etc/(nginx|ssh)|iptables|nft[[:space:]]|ufw|firewall-cmd|systemctl[[:space:]]+(enable|start)|--publish' "$source_installer"; then
  fail "simple bootstrap contains network, reverse-proxy, firewall, SSH, listener, or service-start automation"
fi

printf '%s\n' 'simple Linux bootstrap behavioral tests passed'
