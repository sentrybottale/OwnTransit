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

fake_bin=$test_root/bin
stage_root=$test_root/staging-root
systemd_root=$test_root/systemd-system
output_root=$test_root/output
mkdir -p "$fake_bin" "$stage_root" "$systemd_root" "$output_root"

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
  *) exit 2 ;;
esac
EOF

cat > "$fake_bin/tar" <<'EOF'
#!/bin/sh
fixture_bin=$(dirname "$0")
printf '%s\n' extract >> "$fixture_bin/events"
exit 91
EOF

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
# reached by the download-failure scenarios. Supply inert command-presence
# fixtures only when the test host does not provide them in the fixed path.
for command_name in flock getent groupadd useradd usermod systemctl; do
  if ! PATH=/usr/sbin:/usr/bin:/sbin:/bin command -v "$command_name" >/dev/null 2>&1; then
    cat > "$fake_bin/$command_name" <<'EOF'
#!/bin/sh
exit 92
EOF
  fi
done

chmod 0755 "$fake_bin"/*
printf '%s\n' bad-size > "$fake_bin/curl-mode"
: > "$fake_bin/events"

fixture_installer=$test_root/install-linux.fixture.sh
sed \
  -e "s#^PATH=/usr/sbin:/usr/bin:/sbin:/bin\$#PATH=$fake_bin:/usr/sbin:/usr/bin:/sbin:/bin#" \
  -e "s#^require_protected_ancestor /var\$#require_protected_ancestor $stage_root#" \
  -e "s#/run/systemd/system#$systemd_root#g" \
  -e "s#/var/lib#$stage_root#g" \
  "$source_installer" > "$fixture_installer"
chmod 0755 "$fixture_installer"

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
expect_failure rejected-role 'usage:' sh "$fixture_installer" relay
assert_no_download_or_stage rejected-role

: > "$fake_bin/events"
expect_failure connector-extra-argument 'usage:' sh "$fixture_installer" connector unexpected
assert_no_download_or_stage connector-extra-argument

: > "$fake_bin/events"
expect_failure client-extra-argument 'usage:' sh "$fixture_installer" client alice unexpected
assert_no_download_or_stage client-extra-argument

supervisor_root=$stage_root/owntransit/package-supervisor
mkdir -p "$supervisor_root"
for pending_state in intent restart; do
  pending_record=$supervisor_root/connector.$pending_state
  printf '%s\n' 'preserve-this-recovery-record' > "$pending_record"
  before_record=$(cat "$pending_record")
  : > "$fake_bin/events"
  expect_failure "pending-$pending_state" 'pending connector package recovery exists' \
    env SUDO_USER=alice SUDO_UID=1000 OT_TEST_CANONICAL_USER=alice \
      sh "$fixture_installer" connector
  assert_no_bootstrap_stage "pending-$pending_state"
  test -f "$pending_record" && test "$(cat "$pending_record")" = "$before_record" ||
    fail "pending-$pending_state altered or deleted the supervisor record"
  rm -- "$pending_record"
done
rmdir "$supervisor_root" "$stage_root/owntransit"

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

printf '%s\n' 'simple Linux bootstrap behavioral tests passed'
