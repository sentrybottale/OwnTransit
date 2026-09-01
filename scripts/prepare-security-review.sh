#!/bin/sh
set -eu

fail() {
  printf 'prepare-security-review: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: prepare-security-review.sh --revision FULL_COMMIT --output ABSOLUTE_NEW_DIRECTORY

Creates an immutable, checksummed source-review handoff from a clean sanitized
public-root history. It never includes ignored files, credentials or build
artifacts and it does not claim that an independent review occurred.
EOF
}

revision=
output=
while test "$#" -gt 0; do
  case "$1" in
    --revision|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --revision) revision=$value ;;
        --output) output=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown argument $1" ;;
  esac
done

test -n "$revision" || fail '--revision is required'
test -n "$output" || fail '--output is required'
case "$revision" in
  *[!0-9a-f]*|'') fail 'revision must be lowercase hexadecimal' ;;
esac
test "${#revision}" -eq 40 || fail 'revision must be one full 40-character commit ID'
case "$output" in
  /*) ;;
  *) fail 'output must be an absolute path' ;;
esac
test ! -e "$output" && test ! -L "$output" || fail 'output already exists'

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

test "$(git rev-parse --verify HEAD)" = "$revision" || fail 'revision is not the checked-out HEAD'
test -z "$(git status --porcelain=v1 --untracked-files=all)" || fail 'review target must be completely clean'
git cat-file -e "$revision^{commit}" || fail 'revision is not a commit'

./scripts/security-check.sh
./scripts/publication-check.sh --history
./scripts/release/static-check.sh

output_parent_input=$(dirname "$output")
output_parent=$(CDPATH= cd -P -- "$output_parent_input" && pwd) || fail 'cannot resolve output parent'
output_base=$(basename "$output")
case "$output_base" in
  *[!A-Za-z0-9._+-]*|'') fail 'output basename contains an unsafe character' ;;
esac
resolved_output="$output_parent/$output_base"
test "$output_parent" != / || resolved_output="/$output_base"
test "$resolved_output" = "$output" || fail 'output path must be canonical'

stage=$(mktemp -d "$output_parent/.${output_base}.XXXXXX") || fail 'cannot create staging directory'
cleanup() {
  rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM

git archive --format=tar --prefix=owntransit-source/ --output="$stage/owntransit-source.tar" "$revision"
./scripts/source-manifest.sh > "$stage/SOURCE-MANIFEST.txt"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail 'sha256sum or shasum is required'
  fi
}

source_sha=$(sha256_file "$stage/owntransit-source.tar")
manifest_sha=$(sha256_file "$stage/SOURCE-MANIFEST.txt")
containerfile_sha=$(sha256_file Containerfile)
cat > "$stage/REVIEW-TARGET" <<EOF
schema=owntransit.security-review-target.v1
revision=$revision
source_archive_sha256=$source_sha
source_manifest_sha256=$manifest_sha
containerfile_sha256=$containerfile_sha
EOF
chmod 0644 "$stage/REVIEW-TARGET" "$stage/SOURCE-MANIFEST.txt" "$stage/owntransit-source.tar"

(
  cd "$stage"
  for file in REVIEW-TARGET SOURCE-MANIFEST.txt owntransit-source.tar; do
    digest=$(sha256_file "$file")
    printf '%s  %s\n' "$digest" "$file"
  done > SHA256SUMS
)
chmod 0644 "$stage/SHA256SUMS"

mv -- "$stage" "$output"
trap - EXIT HUP INT TERM
printf 'security review handoff created: %s\n' "$output"
printf 'verify SHA256SUMS before reviewing any file\n'
