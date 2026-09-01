#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

fail() {
  printf 'render-formula: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: render-formula.sh \
  --github-owner OWNER \
  --source-repository REPOSITORY \
  --license SPDX_ID \
  --version SAFE_VERSION \
  --source-sha256 64_HEX \
  --release-id 52_CHAR_CANONICAL_BASE32 \
  --source-commit 40_OR_64_HEX \
  --go-version go1.X.Y \
  --signer-public-key ABSOLUTE_ED25519_SSH_PUBLIC_KEY \
  --output ABSOLUTE_NEW_owntransit.rb

Renders a source-building formula for OWNER/homebrew-owntransit. The release
asset URL is derived as:
https://github.com/OWNER/REPOSITORY/releases/download/vVERSION/owntransit-VERSION-source.tar.gz
EOF
}

github_owner=
source_repository=
license=
version=
source_sha256=
release_id=
source_commit=
go_version=
signer_public_key=
output=
while test "$#" -gt 0; do
  case "$1" in
    --github-owner|--source-repository|--license|--version|--source-sha256|--release-id|--source-commit|--go-version|--signer-public-key|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --github-owner) github_owner=$value ;;
        --source-repository) source_repository=$value ;;
        --license) license=$value ;;
        --version) version=$value ;;
        --source-sha256) source_sha256=$value ;;
        --release-id) release_id=$value ;;
        --source-commit) source_commit=$value ;;
        --go-version) go_version=$value ;;
        --signer-public-key) signer_public_key=$value ;;
        --output) output=$value ;;
      esac
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument $1" ;;
  esac
done

case "$github_owner" in ''|*[!A-Za-z0-9-]*) fail "GitHub owner is not a safe repository owner" ;; esac
test "${#github_owner}" -le 39 || fail "GitHub owner is too long"
case "$source_repository" in ''|*[!A-Za-z0-9._-]*) fail "source repository is not a safe repository name" ;; esac
test "${#source_repository}" -le 100 || fail "source repository is too long"
case "$license" in ''|*[!A-Za-z0-9.+-]*) fail "license must be one explicit SPDX identifier" ;; esac
case "$version" in ''|*[!A-Za-z0-9._+-]*) fail "version contains an unsafe character" ;; esac
case "$version" in [A-Za-z0-9]*) ;; *) fail "version must begin with an alphanumeric character" ;; esac
test "${#version}" -le 128 || fail "version is too long"

valid_digest() {
  digest_value=$1
  case "$digest_value" in ''|*[!0-9a-f]*) return 1 ;; esac
  test "${#digest_value}" -eq 64
}
valid_digest "$source_sha256" || fail "source SHA-256 is invalid"
case "$release_id" in ''|*[!a-z2-7]*) fail "release ID must be lowercase unpadded base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical trailing base32 bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"
case "$source_commit" in ''|*[!0-9a-f]*) fail "source commit must be lowercase hexadecimal" ;; esac
case "${#source_commit}" in 40|64) ;; *) fail "source commit must contain 40 or 64 hexadecimal characters" ;; esac
case "$go_version" in
  go1.*.*) ;;
  *) fail "Go version must have the form go1.X.Y" ;;
esac
case "$go_version" in *[!A-Za-z0-9.]*) fail "Go version contains an unsafe character" ;; esac

case "$signer_public_key" in /*) ;; *) fail "signer public key path must be absolute" ;; esac
test -f "$signer_public_key" && test ! -L "$signer_public_key" || fail "signer public key must be a regular non-symlink file"
public_parent=$(CDPATH= cd -P -- "$(dirname "$signer_public_key")" && pwd) || fail "cannot resolve signer public key parent"
test "$public_parent/$(basename "$signer_public_key")" = "$signer_public_key" || fail "signer public key path must be canonical"
test "$(wc -l < "$signer_public_key" | tr -d '[:space:]')" -eq 1 || fail "signer public key must contain exactly one line"
read -r key_type key_data key_comment < "$signer_public_key" || fail "cannot read signer public key"
test "$key_type" = ssh-ed25519 || fail "source signer must use an Ed25519 SSH key"
case "$key_data" in ''|*[!A-Za-z0-9+/=]*) fail "signer public key encoding is invalid" ;; esac
ssh-keygen -l -f "$signer_public_key" >/dev/null 2>&1 || fail "signer public key is invalid"

case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "cannot resolve output parent"
test "$output_parent/$(basename "$output")" = "$output" || fail "output path must be canonical"
test "$(basename "$output")" = owntransit.rb || fail "formula output basename must be owntransit.rb"

source_url="https://github.com/$github_owner/$source_repository/releases/download/v$version/owntransit-$version-source.tar.gz"
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
template="$project_root/packaging/homebrew/owntransit.rb.in"
test -f "$template" || fail "formula template is absent"
temporary=$(mktemp "$output_parent/.owntransit.rb.XXXXXX") || fail "cannot create formula staging file"
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

awk \
  -v github_owner="$github_owner" \
  -v source_repository="$source_repository" \
  -v source_url="$source_url" \
  -v version="$version" \
  -v source_sha256="$source_sha256" \
  -v license="$license" \
  -v go_version="$go_version" \
  -v release_id="$release_id" \
  -v source_commit="$source_commit" \
  -v key_type="$key_type" \
  -v key_data="$key_data" '
  {
    gsub(/\{\{GITHUB_OWNER\}\}/, github_owner)
    gsub(/\{\{SOURCE_REPOSITORY\}\}/, source_repository)
    gsub(/\{\{SOURCE_URL\}\}/, source_url)
    gsub(/\{\{VERSION\}\}/, version)
    gsub(/\{\{SOURCE_SHA256\}\}/, source_sha256)
    gsub(/\{\{LICENSE\}\}/, license)
    gsub(/\{\{GO_VERSION\}\}/, go_version)
    gsub(/\{\{RELEASE_ID\}\}/, release_id)
    gsub(/\{\{SOURCE_COMMIT\}\}/, source_commit)
    gsub(/\{\{SIGNER_KEY_TYPE\}\}/, key_type)
    gsub(/\{\{SIGNER_KEY_DATA\}\}/, key_data)
    print
  }' "$template" > "$temporary"

test -z "$(grep -E '\{\{[A-Z0-9_]+\}\}' "$temporary" || true)" || fail "formula contains an unresolved template value"
if command -v ruby >/dev/null 2>&1; then
  ruby -c "$temporary" >/dev/null || fail "rendered formula has invalid Ruby syntax"
fi
chmod 0644 "$temporary"
mv "$temporary" "$output"
trap - EXIT HUP INT TERM
printf 'rendered Homebrew formula: %s\n' "$output"
printf 'tap_install=brew install %s/owntransit/owntransit\n' "$github_owner"
