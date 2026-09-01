#!/bin/sh
set -eu

fail() {
  printf 'publication-tools-test: %s\n' "$*" >&2
  exit 1
}

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd -P)
workspace=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-publication-test.XXXXXX") ||
  fail "cannot create test workspace"
cleanup() {
  rm -rf -- "$workspace"
}
trap cleanup EXIT HUP INT TERM

first="$workspace/public-one"
second="$workspace/public-two"
whitespace="$workspace/public-whitespace"
"$project_root/scripts/export-public-root.sh" "$first" >/dev/null

test -d "$first/.git" || fail "export has no independent Git directory"
test "$(git -C "$first" symbolic-ref --short HEAD)" = main || fail "export is not on main"
if git -C "$first" rev-parse --verify HEAD >/dev/null 2>&1; then
  fail "export inherited a commit"
fi
test -z "$(git -C "$first" remote)" || fail "export inherited a remote"
test -z "$(git -C "$first" tag --list)" || fail "export inherited a tag"
test -z "$(git -C "$first" status --short | grep '^??' || true)" ||
  fail "export left Git-visible source unstaged"
test ! -e "$first/dist" && test ! -L "$first/dist" || fail "export copied ignored artifacts"
test ! -e "$first/.private" && test ! -L "$first/.private" || fail "export copied ignored private state"

if "$project_root/scripts/export-public-root.sh" "$first" >/dev/null 2>&1; then
  fail "exporter accepted an existing destination"
fi
nested="$project_root/PublicExportNestedTest$$"
if "$project_root/scripts/export-public-root.sh" "$nested" >/dev/null 2>&1; then
  fail "exporter accepted a destination inside its source repository"
fi
test ! -e "$nested" && test ! -L "$nested" || fail "nested-path rejection created residue"

ln -s README.md "$first/PUBLICATION_LINK_TEST"
if (cd "$first" && ./scripts/publication-check.sh >/dev/null 2>&1); then
  fail "publication checker accepted a Git-visible symlink"
fi
rm -f -- "$first/PUBLICATION_LINK_TEST"

ln "$first/README.md" "$first/PUBLICATION_HARDLINK_TEST"
if (cd "$first" && ./scripts/publication-check.sh >/dev/null 2>&1); then
  fail "publication checker accepted a Git-visible hard link"
fi
rm -f -- "$first/PUBLICATION_HARDLINK_TEST"

printf '%s%s\n' 'AGE-SECRET-' 'KEY-1TESTPUBLICATIONFIXTURE' >"$first/PRIVATE_MARKER_TEST.txt"
if (cd "$first" && ./scripts/publication-check.sh >/dev/null 2>&1); then
  fail "publication checker accepted a private-key marker"
fi
rm -f -- "$first/PRIVATE_MARKER_TEST.txt"

printf '%s%s\n' 'path := "/' 'Users/"+selectedUser' >"$first/DYNAMIC_HOME_TEST.txt"
(cd "$first" && ./scripts/publication-check.sh >/dev/null) ||
  fail "publication checker mistook a constructed platform account path for a private home"
printf '%s%s\n' 'private path: /' 'Users/example-user/.ssh/config' >"$first/DYNAMIC_HOME_TEST.txt"
if (cd "$first" && ./scripts/publication-check.sh >/dev/null 2>&1); then
  fail "publication checker accepted a concrete user home path"
fi
rm -f -- "$first/DYNAMIC_HOME_TEST.txt"

printf '%s\n' \
  'name: unpinned-test' \
  'permissions:' \
  '  contents: read' \
  'jobs:' \
  '  test:' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - uses: actions/checkout@v7' \
  >"$first/.github/workflows/unpinned-test.yml"
if (cd "$first" && ./scripts/publication-check.sh >/dev/null 2>&1); then
  fail "publication checker accepted a tag-pinned action"
fi
rm -f -- "$first/.github/workflows/unpinned-test.yml"

printf 'staged whitespace must fail %s\n' '   ' >"$first/WHITESPACE_EXPORT_TEST.txt"
if "$first/scripts/export-public-root.sh" "$whitespace" >"$workspace/whitespace.stdout" 2>"$workspace/whitespace.stderr"; then
  fail "exporter accepted a staged-root whitespace error"
fi
grep -Fq 'PUBLIC_EXPORT_FAILED: staged public root contains Git whitespace errors' \
  "$workspace/whitespace.stderr" ||
  fail "exporter did not diagnose a staged-root whitespace error"
test ! -e "$whitespace" && test ! -L "$whitespace" ||
  fail "failed whitespace export left a partial destination"
rm -f -- "$first/WHITESPACE_EXPORT_TEST.txt"

printf '%s\n' 'Git-visible untracked export fixture.' >"$first/UNTRACKED_EXPORT_TEST.txt"
printf '%s\n' 'Locally excluded but public export fixture.' >"$first/INFO_EXCLUDED_EXPORT_TEST.txt"
mkdir -p "$first/.git/info"
printf '%s\n' 'INFO_EXCLUDED_EXPORT_TEST.txt' >>"$first/.git/info/exclude"
printf '%s\n' 'Globally excluded but public export fixture.' >"$first/GLOBAL_EXCLUDED_EXPORT_TEST.txt"
printf '%s\n' 'GLOBAL_EXCLUDED_EXPORT_TEST.txt' >"$workspace/global-excludes"
git -C "$first" config core.excludesFile "$workspace/global-excludes"
mkdir -p "$first/dist"
printf '%s\n' 'ignored export fixture' >"$first/dist/IGNORED_EXPORT_TEST.txt"
mkdir -p "$first/.private" "$first/poc/runtime" "$first/poc/secrets" "$first/poc/live-secrets"
printf '%s\n' 'ignored private fixture' >"$first/.private/IGNORED_EXPORT_TEST.txt"
printf '%s\n' 'ignored runtime fixture' >"$first/poc/runtime/IGNORED_EXPORT_TEST.txt"
printf '%s\n' 'ignored secret fixture' >"$first/poc/secrets/IGNORED_EXPORT_TEST.txt"
printf '%s\n' 'ignored live secret fixture' >"$first/poc/live-secrets/IGNORED_EXPORT_TEST.txt"
printf '%s\n' 'ignored private note fixture' >"$first/operator.private.md"
"$first/scripts/export-public-root.sh" "$second" >/dev/null
test -f "$second/UNTRACKED_EXPORT_TEST.txt" || fail "export omitted Git-visible untracked source"
test -f "$second/INFO_EXCLUDED_EXPORT_TEST.txt" || fail "local info exclude silently omitted public source"
test -f "$second/GLOBAL_EXCLUDED_EXPORT_TEST.txt" || fail "global exclude silently omitted public source"
test ! -e "$second/dist" && test ! -L "$second/dist" || fail "export included ignored local material"
test ! -e "$second/.private" && test ! -L "$second/.private" || fail "export included ignored private state"
test ! -e "$second/poc/runtime" && test ! -L "$second/poc/runtime" || fail "export included ignored runtime state"
test ! -e "$second/poc/secrets" && test ! -L "$second/poc/secrets" || fail "export included ignored secret state"
test ! -e "$second/poc/live-secrets" && test ! -L "$second/poc/live-secrets" || fail "export included ignored live secret state"
test ! -e "$second/operator.private.md" && test ! -L "$second/operator.private.md" || fail "export included ignored private note"

rm -f -- "$first/UNTRACKED_EXPORT_TEST.txt" "$first/INFO_EXCLUDED_EXPORT_TEST.txt" "$first/GLOBAL_EXCLUDED_EXPORT_TEST.txt" "$first/operator.private.md"
rm -rf -- "$first/dist" "$first/.private" "$first/poc/runtime" "$first/poc/secrets" "$first/poc/live-secrets"
git -C "$first" config --unset core.excludesFile
git -C "$first" config user.name OwnTransit-Publication-Test
git -C "$first" config user.email publication-test@example.invalid
git -C "$first" config commit.gpgsign false
git -C "$first" commit -q -m 'sanitized public root'
(cd "$first" && ./scripts/publication-check.sh --history >/dev/null) ||
  fail "clean one-root history failed publication verification"

printf '%s\n' 'historical private-path fixture' >"$first/operator.private.md"
git -C "$first" add -f operator.private.md
git -C "$first" commit -q -m 'add rejected private path'
git -C "$first" rm -q operator.private.md
git -C "$first" commit -q -m 'remove rejected private path'
if (cd "$first" && ./scripts/publication-check.sh --history >/dev/null 2>&1); then
  fail "history checker forgot a deleted private path"
fi

printf '%s\n' 'publication exporter and history boundary tests passed'
