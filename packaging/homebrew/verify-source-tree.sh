#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

fail() {
  printf 'verify-source-tree: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: verify-source-tree.sh \
  --source ABSOLUTE_SOURCE_ROOT \
  --allowed-signers ABSOLUTE_FILE \
  --signer SAFE_IDENTITY

Verifies SOURCE-MANIFEST.txt, its owntransit-source-v1 OpenSSH signature,
every listed Go build input, and the absence of unlisted Go build inputs.
EOF
}

source_root=
allowed_signers=
signer=
while test "$#" -gt 0; do
  case "$1" in
    --source|--allowed-signers|--signer)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --source) source_root=$value ;;
        --allowed-signers) allowed_signers=$value ;;
        --signer) signer=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

test "$signer" = owntransit-source || fail "source signer identity must be exactly owntransit-source"

case "$source_root" in
  /*) ;;
  *) fail "source path must be absolute" ;;
esac
test -d "$source_root" && test ! -L "$source_root" || fail "source must be a regular non-symlink directory"
source_resolved=$(CDPATH= cd -P -- "$source_root" && pwd) || fail "cannot resolve source"
test "$source_resolved" = "$source_root" || fail "source path must be canonical"

for required in go.mod go.sum cmd internal SOURCE-MANIFEST.txt SOURCE-MANIFEST.txt.sig; do
  test -e "$source_root/$required" && test ! -L "$source_root/$required" || fail "required source member is absent or a symlink: $required"
done
test -f "$source_root/go.mod" && test -f "$source_root/go.sum" || fail "go.mod and go.sum must be regular files"
test -d "$source_root/cmd" && test -d "$source_root/internal" || fail "cmd and internal must be directories"
test -f "$source_root/SOURCE-MANIFEST.txt" && test -f "$source_root/SOURCE-MANIFEST.txt.sig" || fail "source manifest and signature must be regular files"

unexpected=$(find "$source_root/cmd" "$source_root/internal" ! -type f ! -type d -print)
test -z "$unexpected" || fail "Go build tree contains a symlink or special entry"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
manifest="$source_root/SOURCE-MANIFEST.txt"
manifest_digest=$(sha256_file "$manifest")
"$project_root/packaging/macos/verify-sshsig.sh" \
  --subject "$manifest" \
  --sha256 "$manifest_digest" \
  --signature "$source_root/SOURCE-MANIFEST.txt.sig" \
  --allowed-signers "$allowed_signers" \
  --signer "$signer" \
  --namespace owntransit-source-v1 >/dev/null

workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-source-verify.XXXXXX") || fail "cannot create verification workspace"
cleanup() { rm -rf -- "$workspace"; }
trap cleanup EXIT HUP INT TERM
listed="$workspace/listed"
actual="$workspace/actual"
: > "$listed"

valid_digest() {
  digest_value=$1
  case "$digest_value" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest_value}" -eq 64
}

entry_count=0
while read -r expected path extra; do
  test -z "${extra:-}" || fail "source manifest contains an invalid line"
  valid_digest "${expected:-}" || fail "source manifest contains a non-canonical digest"
  case "${path:-}" in
    go.mod|go.sum|cmd/*|internal/*) ;;
    *) fail "source manifest contains an out-of-scope path" ;;
  esac
  case "$path" in
    *[!A-Za-z0-9._/+:-]*|/*) fail "source manifest contains an unsafe path" ;;
  esac
  case "/$path/" in
    */../*|*/./*|*//*) fail "source manifest contains path traversal" ;;
  esac
  grep -Fqx "$path" "$listed" && fail "source manifest contains a duplicate path"
  candidate="$source_root/$path"
  test -f "$candidate" && test ! -L "$candidate" || fail "manifest member is absent or not a regular file: $path"
  test "$(sha256_file "$candidate")" = "$expected" || fail "source checksum mismatch: $path"
  printf '%s\n' "$path" >> "$listed"
  entry_count=$((entry_count + 1))
done < "$manifest"
test "$entry_count" -gt 2 || fail "source manifest is incomplete"

(
  cd "$source_root"
  find go.mod go.sum cmd internal -type f -print | LC_ALL=C sort
) > "$actual"
LC_ALL=C sort -o "$listed" "$listed"
cmp -s "$listed" "$actual" || fail "signed source manifest does not exactly cover the Go build input set"

printf 'verified OwnTransit source tree entries=%s manifest_sha256=%s\n' "$entry_count" "$manifest_digest"
