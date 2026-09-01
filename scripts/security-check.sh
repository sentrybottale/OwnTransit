#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-quick}

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_COUNT=0
export GIT_CONFIG_NOSYSTEM GIT_CONFIG_GLOBAL GIT_CONFIG_COUNT

case "$mode" in
  quick)
    ;;
  --full)
    mode=full
    ;;
  -h|--help)
    echo "usage: $0 [--full]"
    echo "  quick: repository, secret-marker, shell, publication, and diff checks"
    echo "  --full: quick checks plus both race/vet profiles, pinned govulncheck, release/qualification static gates, and signature-tool tests"
    exit 0
    ;;
  *)
    echo "usage: $0 [--full]" >&2
    exit 2
    ;;
esac

cd "$project_root"

fail() {
  echo "SECURITY_CHECK_FAILED: $*" >&2
  exit 1
}

tracked_private=$(git ls-files -- '.private/**' 'dist/**' 'poc/runtime/**' 'poc/secrets/**' 'poc/live-secrets/**' '*.private.md')
if [ -n "$tracked_private" ]; then
  printf '%s\n' "$tracked_private" >&2
  fail "private operator state, credentials, or artifacts are tracked"
fi

tracked_ignored=$(git ls-files --cached --ignored --exclude-per-directory=.gitignore)
if [ -n "$tracked_ignored" ]; then
  printf '%s\n' "$tracked_ignored" >&2
  fail "tracked files match the repository's ignore-based custody boundary"
fi

for ignored_probe in \
  .private/operator-archive/example \
  dist/owntransit-linux-amd64 \
  poc/runtime/example \
  poc/secrets/example \
  poc/live-secrets/example \
  operator.private.md \
  scratch/example-key.pem \
  scratch/example.key \
  scratch/id_ed25519 \
  scratch/id_ed25519_example \
  scratch/ssh_host_ed25519_key \
  scratch/authorized_keys \
  scratch/known_hosts \
  scratch/.env \
  scratch/.env.local \
  scratch/credentials/example \
  scratch/secrets/example
do
  git check-ignore -q "$ignored_probe" || fail "$ignored_probe is not ignored"
done

private_prefix='-----BEGIN '
private_suffix='PRIVATE KEY-----'
age_private_prefix='AGE-SECRET-'
age_private_suffix='KEY-1'
private_pattern="${private_prefix}([A-Z0-9 ]+ )?${private_suffix}|${age_private_prefix}${age_private_suffix}"
visible_private_files=$(
  {
    git ls-files --cached
    git -c core.excludesFile=/dev/null ls-files --others --exclude-per-directory=.gitignore
  } |
    while IFS= read -r file; do
      test -f "$file" || continue
      test "$file" = scripts/publication-check.sh && continue
      if LC_ALL=C grep -Iq . "$file" && LC_ALL=C grep -Eq -- "$private_pattern" "$file"; then
        printf '%s\n' "$file"
      fi
    done
)
if [ -n "$visible_private_files" ]; then
  printf '%s\n' "$visible_private_files" >&2
  fail "a Git-visible file contains a private-key marker"
fi

test "$(sed -n '1p' .dockerignore)" = '# Deny by default. A build receives only source needed by Containerfile.' ||
  fail ".dockerignore no longer starts with the deny-by-default policy"
test "$(sed -n '2p' .dockerignore)" = '**' ||
  fail ".dockerignore deny-all rule is missing"

find scripts deploy -type f -name '*.sh' -print |
  while IFS= read -r script; do
    sh -n "$script" || fail "shell syntax failed for $script"
  done

./scripts/publication-check.sh
./scripts/tests/nginx-boundary.sh
./scripts/tests/dependency-licenses.sh

grep -Fqx '//go:build !owntransit_poc_ssh' internal/config/connector_target_native.go ||
  fail "production connector target is not the untagged/default build"
grep -Fqx 'const ConnectorSSHTarget = "127.0.0.1:22"' internal/config/connector_target_native.go ||
  fail "production connector target is not literal IPv4 loopback port 22"
grep -Fqx '//go:build owntransit_poc_ssh' internal/config/connector_target_poc.go ||
  fail "POC connector target is not behind its explicit build tag"
grep -Fqx 'const ConnectorSSHTarget = "127.0.0.1:2222"' internal/config/connector_target_poc.go ||
  fail "POC connector target changed unexpectedly"
test -f internal/securitysurface/surface_test.go ||
  fail "incomplete security-boundary surface guard is missing"
grep -Fq 'TestIncompleteSecurityBoundariesRemainPrivate' internal/securitysurface/surface_test.go ||
  fail "incomplete security-boundary surface guard was replaced"
git diff --check

if [ "$mode" = full ]; then
  if command -v go >/dev/null 2>&1; then
    test "$(go env GOVERSION)" = go1.26.7 ||
      fail "full checks require the pinned Go 1.26.7 toolchain"
    test "$(go env GOWORK)" = off || fail "full checks require GOWORK=off"
    go mod verify
    ./scripts/tests/dependency-licenses.sh --full
    gofmt_files=$(gofmt -l cmd internal scripts/release/releasectl)
    test -z "$gofmt_files" || {
      printf '%s\n' "$gofmt_files" >&2
      fail "Go source is not gofmt-normalized"
    }
    go test -mod=readonly -race ./...
    go test -mod=readonly -race -tags=owntransit_poc_ssh ./...
    go vet -mod=readonly ./...
    go vet -mod=readonly -tags=owntransit_poc_ssh ./...
    (
      vuln_bin=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-govulncheck.XXXXXX")
      trap 'rm -rf -- "$vuln_bin"' EXIT HUP INT TERM
      GOBIN="$vuln_bin" go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
      "$vuln_bin/govulncheck" ./...
      "$vuln_bin/govulncheck" -tags=owntransit_poc_ssh ./...
    )
  elif command -v container >/dev/null 2>&1; then
    container system start
    container build --progress plain --file Containerfile --target test --tag owntransit-test:security-production .
    container build --progress plain --file Containerfile --target test-poc --tag owntransit-test:security-poc .
    container build --progress plain --file Containerfile --target vet --tag owntransit-vet:security .
    container build --progress plain --file Containerfile --target vulncheck --tag owntransit-vulncheck:security .
    container build --progress plain --file Containerfile --target dependency-licenses --tag owntransit-dependency-licenses:security .
  elif command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
    docker buildx build --progress plain --file Containerfile --target test --load --tag owntransit-test:security-production .
    docker buildx build --progress plain --file Containerfile --target test-poc --load --tag owntransit-test:security-poc .
    docker buildx build --progress plain --file Containerfile --target vet --load --tag owntransit-vet:security .
    docker buildx build --progress plain --file Containerfile --target vulncheck --load --tag owntransit-vulncheck:security .
    docker buildx build --progress plain --file Containerfile --target dependency-licenses --load --tag owntransit-dependency-licenses:security .
  else
    fail "full checks require Go, Apple Container, or Docker Buildx"
  fi

  ./scripts/release/static-check.sh
  ./scripts/qualify/static-check.sh
  ./scripts/qualify/test-signature-tools.sh
  ./scripts/qualify/test-native-archive.sh
  ./scripts/tests/sign-candidate.sh
fi

echo "SECURITY_CHECK_OK mode=$mode"
