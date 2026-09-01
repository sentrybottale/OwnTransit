#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-tree}

# Review the repository selected by the script path, never an alternate index,
# object store or work tree injected by the invoking environment. User/system
# Git preferences are not publication policy.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_COUNT=0
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT

case "$mode" in
  tree)
    ;;
  --history)
    mode=history
    ;;
  -h|--help)
    echo "usage: $0 [--history]"
    echo "  tree: verify the prospective public working tree"
    echo "  --history: also inspect every reachable public commit"
    exit 0
    ;;
  *)
    echo "usage: $0 [--history]" >&2
    exit 2
    ;;
esac

cd "$project_root"

fail() {
  echo "PUBLICATION_CHECK_FAILED: $*" >&2
  exit 1
}

# Assemble private-key sentinels at runtime so an independent secret scanner
# does not mistake this checker for the material it is designed to reject.
private_key_prefix='-----BEGIN '
private_key_suffix='PRIVATE KEY-----'
age_private_prefix='AGE-SECRET-'
age_private_suffix='KEY-1'
private_key_pattern="${private_key_prefix}([A-Z0-9 ]+ )?${private_key_suffix}|${age_private_prefix}${age_private_suffix}"

visible_files() {
  {
    git ls-files --cached
    # Deliberately ignore core.excludesFile and .git/info/exclude. A local Git
    # preference must not make intentional untracked source disappear from the
    # reviewed public snapshot; publication exclusions belong in .gitignore.
    git -c core.excludesFile=/dev/null ls-files --others --exclude-per-directory=.gitignore
  } |
    LC_ALL=C sort -u |
    while IFS= read -r file; do
      if test -e "$file" || test -L "$file"; then
        printf '%s\n' "$file"
      fi
    done
}

tracked_ignored=$(git ls-files --cached --ignored --exclude-per-directory=.gitignore)
if [ -n "$tracked_ignored" ]; then
  printf '%s\n' "$tracked_ignored" >&2
  fail "tracked files match the repository's publication-ignore policy"
fi

unsafe_paths=$(
  visible_files |
    LC_ALL=C grep -Ev '^[.A-Za-z0-9][A-Za-z0-9._/@+-]*(/[A-Za-z0-9._@+-]+)*$' || true
)
if [ -n "$unsafe_paths" ]; then
  printf '%s\n' "$unsafe_paths" >&2
  fail "Git-visible paths must use the portable publication alphabet"
fi

casefold_collisions=$(
  visible_files |
    LC_ALL=C awk '
      {
        folded = tolower($0)
        if (folded in original && original[folded] != $0) {
          print original[folded]
          print $0
        } else {
          original[folded] = $0
        }
      }
    ' |
    LC_ALL=C sort -u
)
if [ -n "$casefold_collisions" ]; then
  printf '%s\n' "$casefold_collisions" >&2
  fail "Git-visible paths collide on a case-insensitive filesystem"
fi

special_paths=$(
  visible_files |
    LC_ALL=C grep -E '(^|/)(\.\.?|\.git)(/|$)' || true
)
if [ -n "$special_paths" ]; then
  printf '%s\n' "$special_paths" >&2
  fail "Git-visible path contains a reserved component"
fi

non_regular_paths=$(
  visible_files |
    while IFS= read -r file; do
      if test -L "$file" || ! test -f "$file"; then
        printf '%s\n' "$file"
      fi
    done
)
if [ -n "$non_regular_paths" ]; then
  printf '%s\n' "$non_regular_paths" >&2
  fail "public source entries must be regular non-symlink files"
fi

multi_link_paths=$(
  visible_files |
    while IFS= read -r file; do
      if find "$file" -type f -links +1 -print -quit | grep -q .; then
        printf '%s\n' "$file"
      fi
    done
)
if [ -n "$multi_link_paths" ]; then
  printf '%s\n' "$multi_link_paths" >&2
  fail "public source entries must have exactly one hard link"
fi

test -z "$(git ls-files --unmerged)" || fail "the prospective public tree has unmerged index entries"
test ! -e .gitmodules && test ! -L .gitmodules || fail "public source must not depend on Git submodules"
gitlinks=$(git ls-files --stage | awk '$1 == "160000" { print $4 }')
if [ -n "$gitlinks" ]; then
  printf '%s\n' "$gitlinks" >&2
  fail "public source must not contain Git links"
fi

tracked_private=$(git ls-files -- '.private/**' '*.private.md' 'dist/**' 'poc/runtime/**' 'poc/secrets/**' 'poc/live-secrets/**')
test -z "$tracked_private" || {
  printf '%s\n' "$tracked_private" >&2
  fail "private or generated state is tracked"
}

# Reject operational documents by purpose rather than maintaining a list of
# historical private filenames in the public checker.
suspicious_paths=$(
  visible_files |
    LC_ALL=C grep -Ei '(^|/)(current[-_]?state|poc[-_]?runbook|ssh[-_]?access|vps[-_]?security|security[-_]?audit|[^/]*(access|recovery)[-_]?ssh[^/]*)(\.[^/]*)?$' || true
)
if [ -n "$suspicious_paths" ]; then
  printf '%s\n' "$suspicious_paths" >&2
  fail "Git-visible tree contains private operations material"
fi

bad_home_paths=$(
  visible_files |
    while IFS= read -r file; do
      test -f "$file" || continue
      test "$file" = scripts/publication-check.sh && continue
      LC_ALL=C grep -IlE '(/Users/[A-Za-z0-9._-]+([/"`[:space:]]|$)|/home/[A-Za-z0-9._-]+([/"`[:space:]]|$))' "$file" 2>/dev/null || true
    done
)
if [ -n "$bad_home_paths" ]; then
  printf '%s\n' "$bad_home_paths" >&2
  fail "Git-visible files contain user-specific absolute home paths"
fi

# Public product, artifact, and comparison branding is OwnTransit-only. The
# pre-release wire profile is an authenticated compatibility boundary, so its
# exact historical bytes are confined to one implementation package, its
# regression test, the compatibility note, and the illustrative manifest.
forbidden_brand_paths=$(
  visible_files |
    LC_ALL=C grep -Ei 'twingate|fortigate|dockerjump|forthgate|(^|/)forth[-_]' || true
)
if [ -n "$forbidden_brand_paths" ]; then
  printf '%s\n' "$forbidden_brand_paths" >&2
  fail "Git-visible path contains retired or third-party product branding"
fi

forbidden_vendor_files=$(
  visible_files |
    while IFS= read -r file; do
      test -f "$file" || continue
      test "$file" = scripts/publication-check.sh && continue
      LC_ALL=C grep -IlEi 'twingate|fortigate|dockerjump' "$file" 2>/dev/null || true
    done
)
if [ -n "$forbidden_vendor_files" ]; then
  printf '%s\n' "$forbidden_vendor_files" >&2
  fail "Git-visible content contains third-party product or private-tool branding"
fi

retired_brand_files=$(
  visible_files |
    while IFS= read -r file; do
      test -f "$file" || continue
      if test "$file" = scripts/publication-check.sh ||
        test "$file" = COMPATIBILITY.md ||
        test "$file" = RELEASE_MANIFEST.example.json ||
        test "$file" = internal/wireprofile/legacy_v1.go ||
        test "$file" = internal/wireprofile/legacy_v1_test.go; then
        continue
      fi
      LC_ALL=C grep -IlEi 'forthgate|forth[-_]|(/|")forth("|[[:space:]]|$)' "$file" 2>/dev/null || true
    done
)
if [ -n "$retired_brand_files" ]; then
  printf '%s\n' "$retired_brand_files" >&2
  fail "retired branding escaped the authenticated compatibility allowlist"
fi

private_key_markers=$(
  visible_files |
    while IFS= read -r file; do
      test -f "$file" || continue
      test "$file" = scripts/publication-check.sh && continue
      LC_ALL=C grep -IlE -- "$private_key_pattern" "$file" 2>/dev/null || true
    done
)
if [ -n "$private_key_markers" ]; then
  printf '%s\n' "$private_key_markers" >&2
  fail "Git-visible files contain private-key markers"
fi

for required in \
  .github/workflows/release-candidate.yml \
  README.md \
  ARCHITECTURE.md \
  CHANGELOG.md \
  SECURITY.md \
  SECURITY_REVIEW.md \
  CREDENTIALS.md \
  ENROLLMENT_EXCHANGE.md \
  INSTALL.md \
  CONTRIBUTING.md \
  COMPATIBILITY.md \
  PROVENANCE.md \
  ROADMAP.md \
  OWNTRANSIT_SHIPPING_PLAN.md \
  PUBLISHING.md \
  RELEASE_CHECKLIST.md \
  LICENSE \
  THIRD_PARTY_NOTICES.md \
  RELEASE_MANIFEST.example.json
do
  test -f "$required" || fail "missing public document $required"
done

test "$(shasum -a 256 LICENSE | awk '{ print $1 }')" = cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30 ||
  fail "LICENSE is not the reviewed canonical Apache-2.0 text"
grep -Fqx 'module github.com/sentrybottale/owntransit' go.mod ||
  fail "go.mod does not use the canonical public module path"

workflow_action_violations=$(
  find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print |
    LC_ALL=C sort |
    while IFS= read -r workflow; do
      LC_ALL=C grep -n 'uses:' "$workflow" 2>/dev/null |
        LC_ALL=C grep -Ev '^[0-9]+:[[:space:]]*(-[[:space:]]+)?uses:[[:space:]]*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}([[:space:]]*#.*)?$' |
        while IFS= read -r violation; do
          printf '%s:%s\n' "$workflow" "$violation"
        done || true
    done
)
if [ -n "$workflow_action_violations" ]; then
  printf '%s\n' "$workflow_action_violations" >&2
  fail "GitHub Actions dependencies must be pinned to full commit IDs"
fi

workflow_authority_violations=$(
  LC_ALL=C grep -REn \
    'pull_request_target|secrets[.[]|[A-Za-z0-9_-]+:[[:space:]]*write([[:space:]},]|$)|^[[:space:]]*permissions:[[:space:]]*(write-all|read-all)([[:space:]}]|$)' \
    .github/workflows 2>/dev/null || true
)
if [ -n "$workflow_authority_violations" ]; then
  printf '%s\n' "$workflow_authority_violations" >&2
  fail "release-candidate workflows request unsafe event or write authority"
fi
workflow_permission_violations=$(
  find .github/workflows -type f \( -name '*.yml' -o -name '*.yaml' \) -print |
    LC_ALL=C sort |
    while IFS= read -r workflow; do
      if ! LC_ALL=C grep -Eq '^permissions:[[:space:]]*$' "$workflow" ||
         ! LC_ALL=C grep -Eq '^[[:space:]]+contents:[[:space:]]+read([[:space:]]|$)' "$workflow"; then
        printf '%s\n' "$workflow"
      fi
    done
)
if [ -n "$workflow_permission_violations" ]; then
  printf '%s\n' "$workflow_permission_violations" >&2
  fail "every workflow must declare a read-only contents permission boundary"
fi

if [ "$mode" = history ]; then
  test "$(git rev-parse --is-shallow-repository)" = false ||
    fail "history verification requires a complete non-shallow repository"
  alternates_path=$(git rev-parse --git-path objects/info/alternates)
  test ! -s "$alternates_path" ||
    fail "public history must not borrow objects through an alternate store"
  test -z "$(git replace -l)" || fail "public history must not use replacement objects"
  root_count=$(git rev-list --max-parents=0 --all | LC_ALL=C wc -l | tr -d '[:space:]')
  test "$root_count" = 1 || fail "candidate public history must have exactly one root commit"
  git fsck --full --strict --no-reflogs >/dev/null || fail "public object graph failed strict Git verification"

  non_commit_refs=$(
    git for-each-ref --format='%(refname)' |
      while IFS= read -r ref; do
        target=$(git rev-parse -q --verify "$ref^{}" 2>/dev/null || true)
        if test -z "$target" || test "$(git cat-file -t "$target" 2>/dev/null || true)" != commit; then
          printf '%s\n' "$ref"
        fi
      done
  )
  if [ -n "$non_commit_refs" ]; then
    printf '%s\n' "$non_commit_refs" >&2
    fail "every public ref must ultimately select a commit"
  fi

  if {
    git log --all --format='%B'
    git for-each-ref --format='%(refname) %(objecttype)' refs/tags |
      while IFS=' ' read -r ref object_type; do
        test "$object_type" = tag || continue
        git cat-file tag "$ref"
      done
  } | LC_ALL=C grep -Eiq -- "twingate|fortigate|dockerjump|forthgate|${private_key_pattern}|(/Users/[A-Za-z0-9._-]+([/\"\`[:space:]]|$)|/home/[A-Za-z0-9._-]+([/\"\`[:space:]]|$))"; then
    fail "commit or annotated-tag metadata contains private or retired material"
  fi

  historical_paths=$(
    git log --all --name-only --format= |
      LC_ALL=C sort -u |
      LC_ALL=C grep -Ei '(^|/)(\.private|bin|dist|poc/(runtime|secrets|live-secrets)|credentials|secrets)(/|$)|(^|/)([^/]*-key\.pem|[^/]*\.key|id_ed25519(_[^/]*)?|ssh_host_[^/]*_key|authorized_keys|known_hosts[^/]*|\.env(\.[^/]*)?|coverage\.txt|[^/]*\.(private\.md|out|test))$|(^|/)\.gitmodules$|(^|/)(current[-_]?state|poc[-_]?runbook|ssh[-_]?access|vps[-_]?security|security[-_]?audit|[^/]*(access|recovery)[-_]?ssh[^/]*)(\.[^/]*)?$' || true
  )
  if [ -n "$historical_paths" ]; then
    printf '%s\n' "$historical_paths" >&2
    fail "history contains private operations paths; publish a new sanitized root history"
  fi

  historical_brand_paths=$(
    git log --all --name-only --format= |
      LC_ALL=C sort -u |
      LC_ALL=C grep -Ei 'twingate|fortigate|dockerjump|forthgate|(^|/)forth[-_]' || true
  )
  if [ -n "$historical_brand_paths" ]; then
    printf '%s\n' "$historical_brand_paths" >&2
    fail "history contains retired or third-party product branding in a path"
  fi

  historical_vendor_files=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git grep -IlEi 'twingate|fortigate|dockerjump' "$commit" -- 2>/dev/null || true
      done |
      LC_ALL=C grep -v ':scripts/publication-check.sh$' |
      LC_ALL=C sort -u || true
  )
  if [ -n "$historical_vendor_files" ]; then
    printf '%s\n' "$historical_vendor_files" >&2
    fail "history contains third-party product or private-tool branding"
  fi

  historical_retired_brand_files=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git grep -IlEi 'forthgate|forth[-_]|(/|")forth("|[[:space:]]|$)' "$commit" -- 2>/dev/null || true
      done |
      LC_ALL=C grep -Ev ':(scripts/publication-check\.sh|COMPATIBILITY\.md|RELEASE_MANIFEST\.example\.json|internal/wireprofile/legacy_v1\.go|internal/wireprofile/legacy_v1_test\.go)$' |
      LC_ALL=C sort -u || true
  )
  if [ -n "$historical_retired_brand_files" ]; then
    printf '%s\n' "$historical_retired_brand_files" >&2
    fail "retired branding escaped the historical compatibility allowlist"
  fi

  historical_key_markers=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git grep -IlE -- "$private_key_pattern" "$commit" -- 2>/dev/null || true
      done |
      LC_ALL=C grep -v ':scripts/publication-check.sh$' |
      LC_ALL=C sort -u || true
  )
  if [ -n "$historical_key_markers" ]; then
    printf '%s\n' "$historical_key_markers" >&2
    fail "history contains private-key markers; publish a new sanitized root history"
  fi

  historical_home_paths=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git grep -IlE '(/Users/[A-Za-z0-9._-]+([/"`[:space:]]|$)|/home/[A-Za-z0-9._-]+([/"`[:space:]]|$))' "$commit" -- 2>/dev/null || true
      done |
      LC_ALL=C grep -v ':scripts/publication-check.sh$' |
      LC_ALL=C sort -u || true
  )
  if [ -n "$historical_home_paths" ]; then
    printf '%s\n' "$historical_home_paths" >&2
    fail "history contains user-specific absolute home paths; publish a new sanitized root history"
  fi

  historical_unsafe_paths=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git ls-tree -r --name-only "$commit" |
          LC_ALL=C grep -Ev '^[.A-Za-z0-9][A-Za-z0-9._/@+-]*(/[A-Za-z0-9._@+-]+)*$' || true
      done |
      LC_ALL=C sort -u
  )
  if [ -n "$historical_unsafe_paths" ]; then
    printf '%s\n' "$historical_unsafe_paths" >&2
    fail "history contains a non-portable source path"
  fi

  historical_casefold_collisions=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git ls-tree -r --name-only "$commit" |
          LC_ALL=C awk -v commit="$commit" '
            {
              folded = tolower($0)
              if (folded in original && original[folded] != $0) {
                print commit ":" original[folded]
                print commit ":" $0
              } else {
                original[folded] = $0
              }
            }
          '
      done |
      LC_ALL=C sort -u
  )
  if [ -n "$historical_casefold_collisions" ]; then
    printf '%s\n' "$historical_casefold_collisions" >&2
    fail "history contains paths that collide on a case-insensitive filesystem"
  fi

  historical_non_regular_entries=$(
    git rev-list --all |
      while IFS= read -r commit; do
        git ls-tree -r "$commit" | awk '$1 != "100644" && $1 != "100755" { print $4 }'
      done |
      LC_ALL=C sort -u
  )
  if [ -n "$historical_non_regular_entries" ]; then
    printf '%s\n' "$historical_non_regular_entries" >&2
    fail "history contains a symlink, Git link, or other non-regular entry"
  fi
fi

echo "PUBLICATION_CHECK_OK mode=$mode"
