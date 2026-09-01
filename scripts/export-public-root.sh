#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_COUNT=0
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT

usage() {
  cat <<'EOF'
usage: scripts/export-public-root.sh OUTPUT_DIRECTORY

Create a new, staged, one-root-ready Git repository containing only the
prospective public OwnTransit tree. OUTPUT_DIRECTORY must not already exist
and must not be inside the current working repository. The script never
commits, tags, adds a remote, or publishes anything.
EOF
}

fail() {
  echo "PUBLIC_EXPORT_FAILED: $*" >&2
  exit 1
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

test "$#" -eq 1 || {
  usage >&2
  exit 2
}

output_arg=$1
output_parent=$(dirname -- "$output_arg")
output_name=$(basename -- "$output_arg")

test "$output_name" != . && test "$output_name" != .. && test -n "$output_name" ||
  fail "invalid output directory"
case "$output_name" in
  [A-Za-z0-9]*) ;;
  *) fail "output directory name must begin with an alphanumeric character" ;;
esac
case "$output_name" in
  *[!A-Za-z0-9._+-]*) fail "output directory name must use only portable publication characters" ;;
esac
test -d "$output_parent" || fail "output parent does not exist: $output_parent"

output_parent=$(CDPATH= cd -- "$output_parent" && pwd -P)
output_root=$output_parent/$output_name

test ! -e "$output_root" && test ! -L "$output_root" ||
  fail "output path already exists: $output_root"

case "$output_root/" in
  "$project_root/"*) fail "output directory must be outside the working repository" ;;
esac

cd "$project_root"
./scripts/publication-check.sh
./scripts/security-check.sh

file_list=$(mktemp "${TMPDIR:-/tmp}/owntransit-public-files.XXXXXX")
file_list_after=$(mktemp "${TMPDIR:-/tmp}/owntransit-public-files-after.XXXXXX")
source_manifest=$(mktemp "${TMPDIR:-/tmp}/owntransit-public-source.XXXXXX")
source_manifest_after=$(mktemp "${TMPDIR:-/tmp}/owntransit-public-source-after.XXXXXX")
index_manifest=$(mktemp "${TMPDIR:-/tmp}/owntransit-public-index.XXXXXX")
empty_template=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-empty-git-template.XXXXXX")
output_created=no
cleanup() {
  rm -f -- "$file_list" "$file_list_after" "$source_manifest" "$source_manifest_after" "$index_manifest"
  rm -rf -- "$empty_template"
  if test "$output_created" = yes; then
    rm -rf -- "$output_root"
  fi
}
trap cleanup EXIT HUP INT TERM

write_file_list() {
  list_output=$1
  {
    git ls-files --cached
    # Repository publication policy is .gitignore. Do not let a developer's
    # global excludes or .git/info/exclude silently omit untracked source.
    git -c core.excludesFile=/dev/null ls-files --others --exclude-per-directory=.gitignore
  } |
    LC_ALL=C sort -u |
    while IFS= read -r file; do
      if test -e "$file" || test -L "$file"; then
        printf '%s\n' "$file"
      fi
    done >"$list_output"
}

write_manifest() {
  list_input=$1
  manifest_output=$2
  : >"$manifest_output"
  while IFS= read -r file; do
    test -f "$file" && test ! -L "$file" || fail "public source entry changed type: $file"
    digest=$(shasum -a 256 "$file" | awk '{ print $1 }')
    size=$(wc -c <"$file" | tr -d '[:space:]')
    if test -x "$file"; then
      executable=yes
    else
      executable=no
    fi
    printf '%s %s %s %s\n' "$digest" "$size" "$executable" "$file" >>"$manifest_output"
  done <"$list_input"
}

write_file_list "$file_list"

test -s "$file_list" || fail "prospective public tree is empty"
test "$(LC_ALL=C sort -u "$file_list" | wc -l | tr -d '[:space:]')" = "$(wc -l <"$file_list" | tr -d '[:space:]')" ||
  fail "prospective public tree contains duplicate paths"
write_manifest "$file_list" "$source_manifest"

mkdir -m 0700 -- "$output_root"
output_created=yes
COPYFILE_DISABLE=1 tar -cf - -T "$file_list" |
  COPYFILE_DISABLE=1 tar -C "$output_root" -xf -

(
  cd "$output_root"
  find . ! -type d -print | sed 's|^\./||' | LC_ALL=C sort -u
) >"$file_list_after"
cmp -s "$file_list" "$file_list_after" ||
  fail "exported filesystem contains an omitted, extra, or non-regular entry"

write_file_list "$file_list_after"
cmp -s "$file_list" "$file_list_after" || fail "Git-visible file set changed during export"
write_manifest "$file_list_after" "$source_manifest_after"
cmp -s "$source_manifest" "$source_manifest_after" || fail "Git-visible bytes or executable modes changed during export"

while IFS= read -r file; do
  test -f "$output_root/$file" && test ! -L "$output_root/$file" ||
    fail "exported entry is absent or not regular: $file"
  cmp -s "$file" "$output_root/$file" || fail "exported bytes differ: $file"
  if test -x "$file"; then
    test -x "$output_root/$file" || fail "export lost executable mode: $file"
  else
    test ! -x "$output_root/$file" || fail "export gained executable mode: $file"
  fi
done <"$file_list"

GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
  git init -q --template="$empty_template" "$output_root"
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
  git -C "$output_root" symbolic-ref HEAD refs/heads/main

# Populate the index with raw blobs through plumbing. This avoids line-ending,
# clean-filter, global-attributes and hook transformations between the reviewed
# files and the candidate root commit.
while IFS= read -r file; do
  if test -x "$output_root/$file"; then
    mode=100755
  else
    mode=100644
  fi
  object_id=$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
    git -C "$output_root" hash-object -w --no-filters -- "$file")
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
    git -C "$output_root" update-index --add --cacheinfo "$mode,$object_id,$file"
done <"$file_list"

GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
  git -C "$output_root" diff --cached --check ||
  fail "staged public root contains Git whitespace errors"
git -C "$output_root" ls-files | LC_ALL=C sort -u >"$file_list_after"
cmp -s "$file_list" "$file_list_after" || fail "staged public root differs from the reviewed file set"

: >"$index_manifest"
while IFS= read -r file; do
  if test -x "$output_root/$file"; then
    mode=100755
  else
    mode=100644
  fi
  object_id=$(GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
    git -C "$output_root" hash-object --no-filters -- "$file")
  printf '%s %s 0\t%s\n' "$mode" "$object_id" "$file" >>"$index_manifest"
done <"$file_list"
GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 \
  git -C "$output_root" ls-files --stage >"$file_list_after"
cmp -s "$index_manifest" "$file_list_after" ||
  fail "staged public bytes or executable modes differ from the reviewed snapshot"
test -z "$(git -C "$output_root" status --porcelain=v1 --untracked-files=all | grep '^??' || true)" ||
  fail "exported public root contains an unstaged extra file"
if git -C "$output_root" rev-parse --verify HEAD >/dev/null 2>&1; then
  fail "export unexpectedly inherited a commit"
fi
test -z "$(git -C "$output_root" remote)" || fail "export unexpectedly inherited a remote"
test -z "$(git -C "$output_root" tag --list)" || fail "export unexpectedly inherited a tag"

(
  cd "$output_root"
  ./scripts/publication-check.sh
  ./scripts/security-check.sh
)

output_created=no

cat <<EOF
PUBLIC_EXPORT_OK path=$output_root

The sanitized OwnTransit tree is staged on a new main branch with no commits,
tags, remotes, or inherited history. Git-visible untracked source was included;
ignored local/runtime material was excluded. Inspect the exact staged snapshot,
rerun the checks, then create the single public root commit.
EOF
