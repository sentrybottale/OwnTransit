#!/bin/sh
set -eu

fail() {
  printf 'build-artifacts: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: build-artifacts.sh \
  --version TOKEN \
  --release-id 52_CHAR_BASE32_ID \
  --sequence POSITIVE_INTEGER \
  --source-commit 40_OR_64_HEX \
  --source-date-epoch SECONDS \
  --output ABSOLUTE_NEW_DIRECTORY \
  [--engine container|docker]

Builds the exact nine-artifact OwnTransit v1 matrix twice, compares the
unsigned outputs, and atomically creates a deterministic checksum staging tree.
This command does not sign, publish, or install anything.
EOF
}

version=
release_id=
sequence=
source_commit=
source_date_epoch=
output=
engine=

while test "$#" -gt 0; do
  case "$1" in
    --version|--release-id|--sequence|--source-commit|--source-date-epoch|--output|--engine)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --version) version=$value ;;
        --release-id) release_id=$value ;;
        --sequence) sequence=$value ;;
        --source-commit) source_commit=$value ;;
        --source-date-epoch) source_date_epoch=$value ;;
        --output) output=$value ;;
        --engine) engine=$value ;;
      esac
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument $1"
      ;;
  esac
done

test -n "$version" || fail "--version is required"
test -n "$release_id" || fail "--release-id is required"
case "$sequence" in *[!0-9]*|'') fail "--sequence must be a positive decimal integer" ;; esac
test "$sequence" -gt 0 || fail "--sequence must be positive"
test -n "$source_commit" || fail "--source-commit is required"
test -n "$source_date_epoch" || fail "--source-date-epoch is required"
test -n "$output" || fail "--output is required"

case "$version" in
  *[!A-Za-z0-9._+-]*|'') fail "version contains an unsafe character" ;;
esac
case "$version" in
  [A-Za-z0-9]*) ;;
  *) fail "version must begin with an alphanumeric character" ;;
esac
test "${#version}" -le 128 || fail "version is too long"

case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

case "$source_commit" in
  *[!0-9a-f]*|'') fail "source commit must be lowercase hexadecimal" ;;
esac
case "${#source_commit}" in
  40|64) ;;
  *) fail "source commit must contain 40 or 64 hexadecimal characters" ;;
esac

case "$source_date_epoch" in
  *[!0-9]*|'') fail "source date epoch must be a positive decimal integer" ;;
esac
test "${#source_date_epoch}" -le 10 || fail "source date epoch is out of the supported range"
test "$source_date_epoch" -gt 0 || fail "source date epoch must be positive"

case "$output" in
  /*) ;;
  *) fail "output path must be absolute" ;;
esac
test ! -e "$output" && test ! -L "$output" || fail "output path already exists"
output_parent_input=$(dirname "$output")
output_parent=$(CDPATH= cd -P -- "$output_parent_input" && pwd) || fail "cannot resolve output parent"
output_base=$(basename "$output")
case "$output_base" in
  *[!A-Za-z0-9._+-]*|'') fail "output basename contains an unsafe character" ;;
esac
resolved_output="$output_parent/$output_base"
test "$output_parent" != / || resolved_output="/$output_base"
test "$resolved_output" = "$output" || fail "output path must be canonical and contain no symlinked parent"

project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$project_root"

test -d .git || fail "a Git checkout is required for a release build"
actual_commit=$(git rev-parse --verify HEAD) || fail "cannot resolve source revision"
test "$actual_commit" = "$source_commit" || fail "--source-commit does not equal Git HEAD"
test -z "$(git status --porcelain=v1 --untracked-files=all)" || fail "release builds require a completely clean source tree"

if test -z "$engine"; then
  if command -v container >/dev/null 2>&1; then
    engine=container
  elif command -v docker >/dev/null 2>&1 && docker buildx version >/dev/null 2>&1; then
    engine=docker
  else
    fail "Apple Container or Docker Buildx is required"
  fi
fi
case "$engine" in
  container)
    command -v container >/dev/null 2>&1 || fail "container command is unavailable"
    ;;
  docker)
    command -v docker >/dev/null 2>&1 || fail "docker command is unavailable"
    docker buildx version >/dev/null 2>&1 || fail "Docker Buildx is unavailable"
    ;;
  *)
    fail "--engine must be container or docker"
    ;;
esac

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

builder_digest='sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514'
builder_image="docker.io/library/golang:1.26.7-bookworm@$builder_digest"
# Signed evidence uses the canonical tag-free name. The executed image keeps
# the human-readable tag, but both references are pinned to this one digest.
builder_identity="docker.io/library/golang@$builder_digest"
run_release_tool() {
  if test "$engine" = container; then
    container run --rm \
      --mount "type=bind,source=$project_root,target=/src,readonly" \
      --mount "type=bind,source=$stage_root,target=/bundle" \
      --workdir /src \
      "$builder_image" \
      go run -mod=readonly ./scripts/release/releasectl "$@"
  else
    docker run --rm \
      --mount "type=bind,source=$project_root,target=/src,readonly" \
      --mount "type=bind,source=$stage_root,target=/bundle" \
      --workdir /src \
      "$builder_image" \
      go run -mod=readonly ./scripts/release/releasectl "$@"
  fi
}

build_relay_oci() {
  relay_binary=$1
  relay_output=$2
  case "$relay_binary" in
    "$build_root"/*) ;;
    *) fail "relay binary escaped the build workspace" ;;
  esac
  case "$relay_output" in
    "$build_root"/*) ;;
    *) fail "relay OCI output escaped the build workspace" ;;
  esac
  container_binary="/build/${relay_binary#"$build_root/"}"
  container_output="/build/${relay_output#"$build_root/"}"
  host_uid=$(id -u)
  host_gid=$(id -g)
  if test "$engine" = container; then
    container run --rm \
      --network none \
      --uid "$host_uid" \
      --gid "$host_gid" \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp \
      --mount "type=bind,source=$project_root,target=/src,readonly" \
      --mount "type=bind,source=$build_root,target=/build" \
      --workdir /src \
      "$builder_image" \
      /bin/sh /src/scripts/release/make-relay-oci.sh \
      "$container_binary" "$container_output" "$release_id" "$version" "$source_commit" "$source_date_epoch" \
      /src/LICENSE /src/THIRD_PARTY_NOTICES.md
  else
    docker run --rm \
      --network none \
      --user "$host_uid:$host_gid" \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp:rw,nosuid,nodev,noexec \
      --mount "type=bind,source=$project_root,target=/src,readonly" \
      --mount "type=bind,source=$build_root,target=/build" \
      --workdir /src \
      "$builder_image" \
      /bin/sh /src/scripts/release/make-relay-oci.sh \
      "$container_binary" "$container_output" "$release_id" "$version" "$source_commit" "$source_date_epoch" \
      /src/LICENSE /src/THIRD_PARTY_NOTICES.md
  fi
}

temporary_parent=$(CDPATH= cd -P -- "${TMPDIR:-/tmp}" && pwd) || fail "cannot resolve temporary directory"
build_root=$(mktemp -d "$temporary_parent/owntransit-release-build.XXXXXX") || fail "cannot create build workspace"
stage_root=$(mktemp -d "$output_parent/.${output_base}.XXXXXX") || {
  rm -rf -- "$build_root"
  fail "cannot create staging directory"
}
cleanup() {
  rm -rf -- "$build_root" "$stage_root"
}
trap cleanup EXIT HUP INT TERM

manifest_before="$build_root/source-before.txt"
manifest_after="$build_root/source-after.txt"
"$project_root/scripts/source-manifest.sh" > "$manifest_before"

build_export() {
  target_os=$1
  target_arch=$2
  destination=$3
  mkdir -p "$destination"
  if test "$engine" = container; then
    # Apple Container's BuildKit context synchronization has shipped versions
    # that mishandle deny-by-default .dockerignore negations. Keep the public
    # source read-only and build the exact release commands directly in the
    # same digest-pinned toolchain instead of broadening the build context.
    destination_parent=$(CDPATH= cd -P -- "$(dirname "$destination")" && pwd) ||
      fail "cannot resolve Apple Container build destination parent"
    destination_name=$(basename "$destination")
    test "$destination_parent" = "$build_root" ||
      fail "Apple Container build destination escaped its private workspace"
    host_uid=$(id -u)
    host_gid=$(id -g)
    container run --rm \
      --progress none \
      --network default \
      --uid "$host_uid" \
      --gid "$host_gid" \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp \
      --mount "type=bind,source=$project_root,target=/src,readonly" \
      --mount "type=bind,source=$destination_parent,target=/build" \
      --workdir /src \
      --env "TARGETOS=$target_os" \
      --env "TARGETARCH=$target_arch" \
      --env "OWNTRANSIT_VERSION=$version" \
      --env "OWNTRANSIT_RELEASE_ID=$release_id" \
      --env "OWNTRANSIT_SOURCE_COMMIT=$source_commit" \
      --env "SOURCE_DATE_EPOCH=$source_date_epoch" \
      --env "OUTPUT_DIRECTORY=/build/$destination_name" \
      "$builder_image" \
      /bin/sh -c '
        set -eu
        export CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH"
        export GOTOOLCHAIN=local GOWORK=off
        export HOME=/tmp/home GOMODCACHE=/tmp/go-mod GOCACHE=/tmp/go-cache
        mkdir -p "$HOME" "$GOMODCACHE" "$GOCACHE"
        go mod download
        go mod verify
        build_ldflags="-buildid= -s -w -X github.com/sentrybottale/owntransit/internal/buildinfo.Version=${OWNTRANSIT_VERSION} -X github.com/sentrybottale/owntransit/internal/buildinfo.Release=${OWNTRANSIT_RELEASE_ID} -X github.com/sentrybottale/owntransit/internal/buildinfo.Commit=${OWNTRANSIT_SOURCE_COMMIT} -X github.com/sentrybottale/owntransit/internal/buildinfo.Dirty=false"
        build_one() {
          output_name=$1
          package_path=$2
          go build -mod=readonly -trimpath -buildvcs=false -ldflags="$build_ldflags" -o "$OUTPUT_DIRECTORY/$output_name" "$package_path"
        }
        case "$TARGETOS/$TARGETARCH" in
          darwin/arm64)
            build_one owntransit ./cmd/owntransit
            build_one owntransit-launcher ./cmd/owntransit-launcher
            build_one owntransitctl ./cmd/owntransitctl
            build_one owntransit-provision ./cmd/owntransit-provision
            ;;
          linux/amd64)
            build_one owntransit ./cmd/owntransit
            build_one owntransit-connector ./cmd/owntransit-connector
            build_one owntransit-relay ./cmd/owntransit-relay
            build_one owntransitctl ./cmd/owntransitctl
            build_one owntransit-provision ./cmd/owntransit-provision
            ;;
          *)
            printf "unsupported release build target: %s/%s\n" "$TARGETOS" "$TARGETARCH" >&2
            exit 1
            ;;
        esac
        touch -d "@${SOURCE_DATE_EPOCH}" "$OUTPUT_DIRECTORY"/*
      '
  else
    docker buildx build \
      --progress plain \
      --file Containerfile \
      --target release-files \
      --build-arg "TARGETOS=$target_os" \
      --build-arg "TARGETARCH=$target_arch" \
      --build-arg "OWNTRANSIT_VERSION=$version" \
      --build-arg "OWNTRANSIT_RELEASE_ID=$release_id" \
      --build-arg "OWNTRANSIT_SOURCE_COMMIT=$source_commit" \
      --build-arg OWNTRANSIT_SOURCE_DIRTY=false \
      --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
      --output "type=local,dest=$destination" \
      .
  fi
}

exported_file() {
  export_root=$1
  export_name=$2
  matches=$(find "$export_root" -type f -name "$export_name" -print)
  test -n "$matches" || fail "builder did not export $export_name"
  case "$matches" in
    *'
'*) fail "builder exported $export_name more than once" ;;
  esac
  printf '%s\n' "$matches"
}

first_darwin="$build_root/first-darwin"
second_darwin="$build_root/second-darwin"
first_linux="$build_root/first-linux"
second_linux="$build_root/second-linux"
build_export darwin arm64 "$first_darwin"
build_export darwin arm64 "$second_darwin"
build_export linux amd64 "$first_linux"
build_export linux amd64 "$second_linux"

for name in owntransit owntransit-launcher owntransitctl owntransit-provision; do
  first=$(exported_file "$first_darwin" "$name")
  second=$(exported_file "$second_darwin" "$name")
  cmp -s "$first" "$second" || fail "darwin/arm64 $name is not reproducible"
done
for name in owntransit owntransit-connector owntransit-relay owntransitctl owntransit-provision; do
  first=$(exported_file "$first_linux" "$name")
  second=$(exported_file "$second_linux" "$name")
  cmp -s "$first" "$second" || fail "linux/amd64 $name is not reproducible"
done

command -v file >/dev/null 2>&1 || fail "file is required for static platform checks"
darwin_client_description=$(file -b "$(exported_file "$first_darwin" owntransit)")
printf '%s\n' "$darwin_client_description" | grep -Fq 'Mach-O 64-bit' || fail "darwin client is not a Mach-O 64-bit executable"
printf '%s\n' "$darwin_client_description" | grep -Eq '(^|[[:space:],])arm64([[:space:],]|$)' || fail "darwin client is not arm64"
darwin_launcher_description=$(file -b "$(exported_file "$first_darwin" owntransit-launcher)")
printf '%s\n' "$darwin_launcher_description" | grep -Fq 'Mach-O 64-bit' || fail "darwin client launcher is not a Mach-O 64-bit executable"
printf '%s\n' "$darwin_launcher_description" | grep -Eq '(^|[[:space:],])arm64([[:space:],]|$)' || fail "darwin client launcher is not arm64"
file -b "$(exported_file "$first_linux" owntransit)" | grep -Fq 'ELF 64-bit LSB' || fail "linux client is not an ELF executable"
file -b "$(exported_file "$first_linux" owntransit)" | grep -Fq 'x86-64' || fail "linux client is not amd64"
command -v strings >/dev/null 2>&1 || fail "strings is required for the connector target check"
strings "$(exported_file "$first_linux" owntransit-connector)" | grep -Fq 'tcp4 127.0.0.1:22' || fail "connector does not identify the production SSH target"
if strings "$(exported_file "$first_linux" owntransit-connector)" | grep -Fq '127.0.0.1:2222'; then
  fail "connector contains the POC SSH target"
fi

first_oci_root="$build_root/first-relay-oci"
second_oci_root="$build_root/second-relay-oci"
mkdir -p "$first_oci_root" "$second_oci_root"
first_oci="$first_oci_root/relay.oci.tar"
second_oci="$second_oci_root/relay.oci.tar"
build_relay_oci \
  "$(exported_file "$first_linux" owntransit-relay)" \
  "$first_oci"
build_relay_oci \
  "$(exported_file "$second_linux" owntransit-relay)" \
  "$second_oci"
cmp -s "$first_oci" "$second_oci" || fail "linux/amd64 relay OCI archive is not reproducible"

artifacts="$stage_root/artifacts"
mkdir -p "$artifacts"
install -m 0755 "$(exported_file "$first_darwin" owntransit)" "$artifacts/owntransit-darwin-arm64"
install -m 0755 "$(exported_file "$first_darwin" owntransit-launcher)" "$artifacts/owntransit-launcher-darwin-arm64"
install -m 0755 "$(exported_file "$first_linux" owntransit)" "$artifacts/owntransit-linux-amd64"
install -m 0755 "$(exported_file "$first_linux" owntransit-connector)" "$artifacts/owntransit-connector-linux-amd64"
install -m 0644 "$first_oci" "$artifacts/owntransit-relay-linux-amd64.oci.tar"
install -m 0755 "$(exported_file "$first_darwin" owntransitctl)" "$artifacts/owntransitctl-darwin-arm64"
install -m 0755 "$(exported_file "$first_linux" owntransitctl)" "$artifacts/owntransitctl-linux-amd64"
install -m 0755 "$(exported_file "$first_darwin" owntransit-provision)" "$artifacts/owntransit-provision-darwin-arm64"
install -m 0755 "$(exported_file "$first_linux" owntransit-provision)" "$artifacts/owntransit-provision-linux-amd64"
test "$(find "$artifacts" -type f -print | wc -l | tr -d '[:space:]')" -eq 9 || fail "staging does not contain the exact nine-artifact matrix"

"$project_root/scripts/source-manifest.sh" > "$manifest_after"
cmp -s "$manifest_before" "$manifest_after" || fail "source changed during the release build"
source_manifest_digest=$(sha256_file "$manifest_after")
install -m 0644 "$manifest_after" "$stage_root/SOURCE-MANIFEST.txt"
install -m 0644 "$project_root/LICENSE" "$stage_root/LICENSE"

mkdir -p "$stage_root/packaging/scripts" "$stage_root/packaging/systemd" "$stage_root/packaging/launchd"
for script in install-linux.sh uninstall-linux.sh install-macos.sh uninstall-macos.sh; do
  install -m 0755 "$project_root/scripts/release/$script" "$stage_root/packaging/scripts/$script"
done
for unit in owntransit-connector.service owntransit-relay.service; do
  install -m 0644 "$project_root/deploy/systemd/$unit" "$stage_root/packaging/systemd/$unit"
done
install -m 0644 "$project_root/deploy/systemd/README.md" "$stage_root/packaging/systemd/README.md"
install -m 0644 "$project_root/deploy/launchd/README.md" "$stage_root/packaging/launchd/README.md"

printf '%s\n' \
  "version=$version" \
  "release_id=$release_id" \
  "release_sequence=$sequence" \
  "source_commit=$source_commit" \
  "source_date_epoch=$source_date_epoch" \
  "source_manifest_sha256=$source_manifest_digest" \
  > "$stage_root/BUILD-INPUTS"
chmod 0644 "$stage_root/BUILD-INPUTS"

release_metadata="--bundle /bundle --version $version --release-id $release_id --sequence $sequence --created-unix $source_date_epoch --repository https://github.com/sentrybottale/owntransit --source-commit $source_commit --source-manifest-sha256 $source_manifest_digest --go-version go1.26.7 --builder-image $builder_identity"
# shellcheck disable=SC2086
run_release_tool evidence $release_metadata
# shellcheck disable=SC2086
run_release_tool manifest $release_metadata

(
  cd "$stage_root"
  find . -type f ! -name SHA256SUMS -print | LC_ALL=C sort |
    while IFS= read -r path; do
      clean_path=${path#./}
      digest=$(sha256_file "$clean_path")
      printf '%s  %s\n' "$digest" "$clean_path"
    done > SHA256SUMS
  chmod 0644 SHA256SUMS
)

chmod 0755 "$stage_root" "$stage_root/artifacts" "$stage_root/packaging" "$stage_root/packaging/scripts" "$stage_root/packaging/systemd" "$stage_root/packaging/launchd"
mv -- "$stage_root" "$output"
stage_root="$output_parent/.completed-owntransit-stage"
trap - EXIT HUP INT TERM
rm -rf -- "$build_root"

printf 'created unsigned deterministic staging tree: %s\n' "$output"
printf 'SHA256SUMS digest: %s\n' "$(sha256_file "$output/SHA256SUMS")"
printf '%s\n' 'The staging tree includes canonical SBOM, license, provenance, and unsigned manifest evidence. Offline release/policy signing and publication remain separate; Developer ID package output is disabled.'
