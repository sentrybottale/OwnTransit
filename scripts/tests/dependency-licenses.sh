#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
mode=${1:-quick}

case "$mode" in
  quick)
    ;;
  --full)
    mode=full
    ;;
  -h|--help)
    printf '%s\n' "usage: $0 [--full]"
    printf '%s\n' "  quick: deterministic source and pinned-inventory checks"
    printf '%s\n' "  --full: quick checks plus production graph and upstream license-file verification"
    exit 0
    ;;
  *)
    printf '%s\n' "usage: $0 [--full]" >&2
    exit 2
    ;;
esac

cd "$project_root"

fail() {
  printf 'dependency-license-check: %s\n' "$*" >&2
  exit 1
}

require_text() {
  file=$1
  literal=$2
  grep -Fq -- "$literal" "$file" || fail "$file is missing invariant: $literal"
}

expected_modules='filippo.io/age v1.3.2
filippo.io/hpke v0.4.0
github.com/coder/websocket v1.8.15
golang.org/x/crypto v0.55.0
golang.org/x/sys v0.47.0'

test "$(shasum -a 256 THIRD_PARTY_NOTICES.md | awk '{ print $1 }')" = \
  e33d371224ddd98793822f1cbfb8bc25a196753791f187fc02bab63bca00e79c ||
  fail 'THIRD_PARTY_NOTICES.md differs from the reviewed complete notice set'
for notice_marker in \
  'Copyright 2019 The age Authors' \
  'Neither the name of the age project nor the names of its contributors' \
  'Copyright 2009 The Go Authors.' \
  'Neither the name of Google LLC nor the names of its contributors' \
  'Additional IP Rights Grant (Patents)' \
  'Google hereby grants to You a perpetual, worldwide, non-exclusive' \
  'Copyright (c) 2025 Coder' \
  'Permission to use, copy, modify, and distribute this software for any purpose' \
  'ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt' \
  '7fe0b034ec967b52a5a28276419117326df93263/bip-0039.mediawiki' \
  'Copyright (c) 2013 BIP-39 authors' \
  'Permission is hereby granted, free of charge, to any person obtaining a copy'
do
  require_text THIRD_PARTY_NOTICES.md "$notice_marker"
done

printf '%s\n' "$expected_modules" |
  while IFS=' ' read -r module version; do
    awk -v module="$module" -v version="$version" '
      $1 == module && $2 == version &&
        (NF == 2 || (NF == 4 && $3 == "//" && $4 == "indirect")) { found = 1 }
      END { exit !found }
    ' go.mod ||
      fail "go.mod is missing exact production dependency $module $version"
    require_text THIRD_PARTY_NOTICES.md "| \`$module\` | \`$version\` |"
  done

release_tool=scripts/release/releasectl/main.go
require_text "$release_tool" 'arguments := []string{"list", "-mod=readonly", "-buildvcs=false", "-deps", "-json"}'
require_text "$release_tool" 'if pkg.Module.Replace != nil {'
require_text "$release_tool" 'arguments := append([]string{"mod", "download", "-json"}, requested...)'
require_text "$release_tool" 'if module.Dir == "" || module.Sum == "" || module.GoModSum == "" {'
require_text "$release_tool" 'strings.HasPrefix(upper, "LICENSE")'
require_text "$release_tool" 'strings.HasPrefix(upper, "COPYING")'
require_text "$release_tool" 'strings.HasPrefix(upper, "NOTICE")'
require_text "$release_tool" 'strings.HasPrefix(upper, "PATENTS")'
require_text "$release_tool" 'return errors.New("no top-level license evidence found")'
require_text "$release_tool" 'writeNew(filepath.Join(evidenceDir, "THIRD_PARTY_LICENSES.txt"), licenses, 0o644)'
require_text "$release_tool" 'wordListNotice, err := readBounded("THIRD_PARTY_NOTICES.md", 64<<10, false)'
require_text internal/release/manifest.go 'evidence.Name == "third-party-licenses"'
require_text internal/release/manifest.go 'evidence.Kind == "licenses"'
require_text .dockerignore '!THIRD_PARTY_NOTICES.md'
require_text Containerfile 'COPY LICENSE THIRD_PARTY_NOTICES.md RELEASE_MANIFEST.example.json ./'
require_text Containerfile 'COPY --from=build /src/LICENSE /licenses/Apache-2.0.txt'
require_text Containerfile 'COPY --from=build /src/THIRD_PARTY_NOTICES.md /licenses/THIRD_PARTY_NOTICES.md'
require_text Containerfile 'FROM build AS dependency-licenses'
require_text Containerfile 'RUN /bin/sh ./scripts/tests/dependency-licenses.sh --full'
require_text scripts/security-check.sh '--target dependency-licenses --tag owntransit-dependency-licenses:security'
require_text scripts/release/make-relay-oci.sh 'install -m 0644 "$project_license" "$rootfs/licenses/Apache-2.0.txt"'
require_text scripts/release/make-relay-oci.sh 'install -m 0644 "$third_party_notices" "$rootfs/licenses/THIRD_PARTY_NOTICES.md"'
require_text scripts/release/make-relay-oci.sh 'cmp -s "$project_license" "$license_roundtrip"'
require_text scripts/release/make-relay-oci.sh 'cmp -s "$third_party_notices" "$notice_roundtrip"'
require_text scripts/release/make-relay-oci.sh '\"org.opencontainers.image.licenses\":\"Apache-2.0\"'

if [ "$mode" != full ]; then
  printf '%s\n' 'dependency license static and pinned-inventory checks passed'
  exit 0
fi

command -v go >/dev/null 2>&1 || fail 'full check requires the pinned Go toolchain'
test "$(go env GOVERSION)" = go1.26.7 ||
  fail 'full check requires Go 1.26.7'
test "$(GOWORK=off go env GOWORK)" = off ||
  fail 'full check requires GOWORK=off'

temporary=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-dependency-licenses.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM

module_template='{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{if .Replace}} REPLACED{{end}}{{end}}{{end}}'
if ! env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 GOWORK=off \
  go list -mod=readonly -buildvcs=false -deps -f "$module_template" \
    ./cmd/owntransit ./cmd/owntransit-launcher ./cmd/owntransitctl \
    ./cmd/owntransit-provision >"$temporary/darwin-modules"; then
  fail 'could not enumerate the macOS production dependency graph'
fi
if ! env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOWORK=off \
  go list -mod=readonly -buildvcs=false -deps -f "$module_template" \
    ./cmd/owntransit ./cmd/owntransit-connector ./cmd/owntransit-relay \
    ./cmd/owntransitctl ./cmd/owntransit-provision >"$temporary/linux-modules"; then
  fail 'could not enumerate the Linux production dependency graph'
fi

sed '/^$/d' "$temporary/darwin-modules" "$temporary/linux-modules" |
  LC_ALL=C sort -u >"$temporary/actual-modules"
printf '%s\n' "$expected_modules" | LC_ALL=C sort -u >"$temporary/expected-modules"

if grep -Fq ' REPLACED' "$temporary/actual-modules"; then
  fail 'a production dependency uses a module replacement'
fi
if ! cmp -s "$temporary/expected-modules" "$temporary/actual-modules"; then
  printf '%s\n' 'expected production modules:' >&2
  sed 's/^/  /' "$temporary/expected-modules" >&2
  printf '%s\n' 'observed production modules:' >&2
  sed 's/^/  /' "$temporary/actual-modules" >&2
  fail 'THIRD_PARTY_NOTICES.md inventory does not match the production graph'
fi

while IFS=' ' read -r module version; do
  coordinate="$module@$version"
  if ! env GOWORK=off GOFLAGS=-mod=readonly \
    go mod download -json "$coordinate" >"$temporary/module.json"; then
    fail "could not retrieve authenticated module evidence for $coordinate"
  fi
  module_dir=$(sed -n 's/^[[:space:]]*"Dir": "\([^"]*\)",$/\1/p' "$temporary/module.json")
  module_sum=$(sed -n 's/^[[:space:]]*"Sum": "\([^"]*\)",$/\1/p' "$temporary/module.json")
  module_mod_sum=$(sed -n 's/^[[:space:]]*"GoModSum": "\([^"]*\)",$/\1/p' "$temporary/module.json")
  test -n "$module_dir" && test -n "$module_sum" && test -n "$module_mod_sum" ||
    fail "module download returned incomplete evidence for $coordinate"
  test -d "$module_dir" || fail "module directory is absent for $coordinate"
  find "$module_dir" -maxdepth 1 -type f \
    \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' -o -iname 'PATENTS*' \) \
    -print -quit | grep -q . || fail "no top-level upstream license evidence for $coordinate"
done <"$temporary/actual-modules"

printf '%s\n' 'dependency license production-graph and upstream-evidence checks passed'
