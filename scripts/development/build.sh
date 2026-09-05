#!/bin/sh
set -eu
umask 077
GOMAXPROCS=2
export GOMAXPROCS
GOFLAGS=
GOWORK=off
GOENV=off
export GOFLAGS GOWORK GOENV
fail() { printf 'development-build: %s\n' "$*" >&2; exit 1; }
test "$#" -eq 2 || fail 'usage: build.sh ABSOLUTE_GO1267 ABSOLUTE_NEW_OUTPUT'
go_bin=$1
output=$2
case "$go_bin" in /*) ;; *) fail 'Go path must be absolute' ;; esac
case "$output" in /*) ;; *) fail 'output path must be absolute' ;; esac
test ! -e "$output" && test ! -L "$output" || fail 'output must not exist'
test "$("$go_bin" version | awk '{print $3}')" = go1.26.7 || fail 'pinned Go 1.26.7 is required'
project=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$project"
test -z "$(git status --porcelain)" || fail 'freeze a clean source commit before building'
commit=$(git rev-parse HEAD)
epoch=$(git log -1 --format=%ct)
tar_bin=
for candidate in gtar tar /opt/homebrew/bin/gtar; do
  if "$candidate" --version 2>/dev/null | grep -Fq 'GNU tar'; then tar_bin=$candidate; break; fi
done
test -n "$tar_bin" || fail 'GNU tar is required'
install -d -m 0700 "$output"
scratch=$(mktemp -d "$output/build.XXXXXXXX")
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
version=0.1.3
ldflags="-buildid= -X github.com/sentrybottale/owntransit/internal/buildinfo.Version=$version -X github.com/sentrybottale/owntransit/internal/buildinfo.Commit=$commit -X github.com/sentrybottale/owntransit/internal/buildinfo.Dirty=false"

for platform in linux-amd64 linux-arm64 darwin-arm64; do
  target_os=${platform%-*}
  arch=${platform#*-}
  top=owntransit-preview-$version-$platform
  bundle=$scratch/$top
  install -d -m 0700 "$bundle"
  printf 'schema=owntransit.development-capsule.v1\nversion=%s\nos=%s\narch=%s\n' "$version" "$target_os" "$arch" > "$bundle/CAPSULE"
  install -m 0644 LICENSE "$bundle/LICENSE"
  install -m 0644 THIRD_PARTY_NOTICES.md "$bundle/NOTICE"
  CGO_ENABLED=0 GOOS=$target_os GOARCH=$arch GOTOOLCHAIN=local "$go_bin" build -mod=readonly -trimpath -buildvcs=false -ldflags "$ldflags" -o "$bundle/owntransit" ./cmd/owntransit
  if test "$target_os" = linux; then
    install -m 0755 scripts/development/install-linux.sh "$bundle/install-linux.sh"
    for role in connector relay; do
      CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOTOOLCHAIN=local "$go_bin" build -mod=readonly -trimpath -buildvcs=false -ldflags "$ldflags" -o "$bundle/owntransit-$role" "./cmd/owntransit-$role"
    done
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch GOTOOLCHAIN=local "$go_bin" build -mod=readonly -trimpath -buildvcs=false -tags=owntransit_relay_container -ldflags "$ldflags" -o "$scratch/relay-container-$arch" ./cmd/owntransit-relay
    OWNTRANSIT_GNU_TAR="$tar_bin" sh scripts/development/make-relay-oci.sh "$scratch/relay-container-$arch" "$bundle/owntransit-relay.oci.tar" "$arch" "$commit" "$epoch" LICENSE THIRD_PARTY_NOTICES.md
  fi
  chmod 0644 "$bundle/CAPSULE"
  (cd "$bundle"; for member in CAPSULE LICENSE NOTICE install-linux.sh owntransit owntransit-connector owntransit-relay owntransit-relay.oci.tar; do
    if test -f "$member"; then printf '%s  %s\n' "$(sha "$member")" "$member"; fi
  done) > "$bundle/SHA256SUMS"
  chmod 0644 "$bundle/SHA256SUMS"
  "$tar_bin" --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner -cf "$scratch/$top.tar" -C "$scratch" "$top"
  gzip -n -c "$scratch/$top.tar" > "$output/$top.tar.gz"
  chmod 0644 "$output/$top.tar.gz"
done
install -m 0644 install-preview-linux.sh "$output/install-preview-linux.sh"
printf 'OwnTransit 0.1.3 DEVELOPMENT PREVIEW\nsource_commit=%s\nsource_date_epoch=%s\n\nNot stable or production-qualified. Published releases are immutable. Explicit relay setup can replace an identified old relay and update the selected website route, with rollback on failure.\nDistribution signatures authenticate these exact development bytes, not a platform qualification claim.\n' "$commit" "$epoch" > "$output/DEVELOPMENT.txt"
chmod 0644 "$output/DEVELOPMENT.txt"
(cd "$output"; for member in DEVELOPMENT.txt install-preview-linux.sh owntransit-preview-0.1.3-darwin-arm64.tar.gz owntransit-preview-0.1.3-linux-amd64.tar.gz owntransit-preview-0.1.3-linux-arm64.tar.gz; do printf '%s  %s\n' "$(sha "$member")" "$member"; done) > "$output/DEVELOPMENT-SHA256SUMS"
chmod 0644 "$output/DEVELOPMENT-SHA256SUMS"
printf 'Built exact development capsules in %s\nBuild intermediates retained in %s\n' "$output" "$scratch"
