#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail() {
  printf 'verify-sshsig: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: verify-sshsig.sh \
  --subject ABSOLUTE_REGULAR_FILE \
  --sha256 64_LOWERCASE_HEX \
  --signature ABSOLUTE_REGULAR_FILE \
  --allowed-signers ABSOLUTE_REGULAR_FILE \
  --signer SAFE_IDENTITY \
  --namespace SAFE_NAMESPACE

Verifies an independently supplied SHA-256 digest and an OpenSSH detached
signature. The allowed-signers file is a trust anchor and must itself arrive
through an authenticated channel. No network access is performed.
EOF
}

subject=
expected_sha256=
signature=
allowed_signers=
signer=
namespace=

while test "$#" -gt 0; do
  case "$1" in
    --subject|--sha256|--signature|--allowed-signers|--signer|--namespace)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --subject) subject=$value ;;
        --sha256) expected_sha256=$value ;;
        --signature) signature=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --signer) signer=$value ;;
        --namespace) namespace=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

valid_digest() {
  digest_value=$1
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest_value}" -eq 64
}

valid_digest "$expected_sha256" || fail "--sha256 must be 64 lowercase hexadecimal characters"
case "$signer" in
  ''|*[!A-Za-z0-9._@+-]*) fail "--signer is not a safe identity" ;;
esac
test "${#signer}" -le 128 || fail "--signer is too long"
case "$namespace" in
  ''|*[!A-Za-z0-9._+-]*) fail "--namespace is not a safe token" ;;
esac
test "${#namespace}" -le 128 || fail "--namespace is too long"

canonical_regular() {
  input_path=$1
  label=$2
  case "$input_path" in
    /*) ;;
    *) fail "$label path must be absolute" ;;
  esac
  test -f "$input_path" && test ! -L "$input_path" || fail "$label must be a regular non-symlink file"
  input_parent=$(dirname "$input_path")
  input_base=$(basename "$input_path")
  resolved_parent=$(CDPATH= cd -P -- "$input_parent" && pwd) || fail "cannot resolve $label parent"
  resolved_path="$resolved_parent/$input_base"
  test "$resolved_path" = "$input_path" || fail "$label path must be canonical"
  if test "$(uname -s)" = Darwin; then
    test "$(stat -f %l "$input_path")" -eq 1 || fail "$label must have exactly one hard link"
  else
    test "$(stat -c %h "$input_path")" -eq 1 || fail "$label must have exactly one hard link"
  fi
}

canonical_regular "$subject" subject
canonical_regular "$signature" signature
canonical_regular "$allowed_signers" allowed-signers
test -s "$subject" || fail "subject is empty"
test -s "$signature" || fail "signature is empty"
test -s "$allowed_signers" || fail "allowed-signers is empty"
test "$(wc -c < "$signature" | tr -d '[:space:]')" -le 16384 || fail "signature is unexpectedly large"
test "$(wc -c < "$allowed_signers" | tr -d '[:space:]')" -le 65536 || fail "allowed-signers is unexpectedly large"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$subject" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256=$(shasum -a 256 "$subject" | awk '{print $1}')
else
  fail "sha256sum or shasum is required"
fi
test "$actual_sha256" = "$expected_sha256" || fail "SHA-256 digest mismatch"

command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen with SSHSIG support is required"
ssh-keygen -Y verify \
  -f "$allowed_signers" \
  -I "$signer" \
  -n "$namespace" \
  -s "$signature" \
  < "$subject" >/dev/null || fail "detached signature verification failed"

printf 'verified sha256=%s signer=%s namespace=%s\n' "$actual_sha256" "$signer" "$namespace"
