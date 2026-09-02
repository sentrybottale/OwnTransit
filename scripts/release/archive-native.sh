#!/bin/sh
set -eu

umask 077
LC_ALL=C
export LC_ALL

fail() {
  printf 'archive-native: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: archive-native.sh \
  --bundle ABSOLUTE_EXISTING_STAGING_DIRECTORY \
  --output ABSOLUTE_NEW_TAR_GZ

Validates the exact unsigned native staging tree produced by
build-artifacts.sh and packages it twice as a deterministic .tar.gz. The
archive is a qualification handoff only: it does not sign, authenticate,
publish, install, or include release-policy, signature, key, or trust files.
EOF
}

bundle=
output=
while test "$#" -gt 0; do
  case "$1" in
    --bundle|--output)
      test "$#" -ge 2 || fail "$1 requires a value"
      option=$1
      value=$2
      shift 2
      case "$option" in
        --bundle) bundle=$value ;;
        --output) output=$value ;;
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

test -n "$bundle" || fail "--bundle is required"
test -n "$output" || fail "--output is required"

case "$bundle" in /*) ;; *) fail "bundle path must be absolute" ;; esac
test -d "$bundle" && test ! -L "$bundle" || fail "bundle must be an existing non-symlink directory"
bundle_parent=$(CDPATH= cd -P -- "$(dirname "$bundle")" && pwd) || fail "cannot resolve bundle parent"
bundle_base=$(basename "$bundle")
resolved_bundle="$bundle_parent/$bundle_base"
test "$bundle_parent" != / || resolved_bundle="/$bundle_base"
test "$resolved_bundle" = "$bundle" || fail "bundle path must be canonical and contain no symlinked parent"

case "$output" in /*) ;; *) fail "output path must be absolute" ;; esac
case "$output" in *.tar.gz) ;; *) fail "output must end in .tar.gz" ;; esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"
output_parent=$(CDPATH= cd -P -- "$(dirname "$output")" && pwd) || fail "cannot resolve output parent"
output_base=$(basename "$output")
case "$output_base" in *[!A-Za-z0-9._+-]*|'') fail "output basename contains an unsafe character" ;; esac
resolved_output="$output_parent/$output_base"
test "$output_parent" != / || resolved_output="/$output_base"
test "$resolved_output" = "$output" || fail "output path must be canonical and contain no symlinked parent"
if test "$output_parent" = "$bundle"; then
  fail "output must remain outside the native staging tree"
fi
case "$output_parent/" in "$bundle/"*) fail "output must remain outside the native staging tree" ;; esac

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

darwin_mode() {
  darwin_mode_raw=$(stat -f %p -- "$1") || return 1
  case "$darwin_mode_raw" in ''|*[!0-7]*) return 1 ;; esac
  printf '%o\n' "$((0$darwin_mode_raw & 07777))"
}

file_metadata() {
  if test "$(uname -s)" = Darwin; then
    file_kind=$(stat -f %HT -- "$1") || return 1
    file_links=$(stat -f %l -- "$1") || return 1
    file_permissions=$(darwin_mode "$1") || return 1
    printf '%s|%s|%s\n' "$file_kind" "$file_links" "$file_permissions"
  else
    stat -c '%F|%h|%a' -- "$1"
  fi
}

directory_mode() {
  if test "$(uname -s)" = Darwin; then
    darwin_mode "$1"
  else
    stat -c '%a' -- "$1"
  fi
}

write_expected_files() {
  cat <<'EOF'
BUILD-INPUTS
LICENSE
RELEASE-MANIFEST.json
SOURCE-MANIFEST.txt
artifacts/owntransit-connector-linux-amd64
artifacts/owntransit-darwin-arm64
artifacts/owntransit-launcher-darwin-arm64
artifacts/owntransit-linux-amd64
artifacts/owntransit-provision-darwin-arm64
artifacts/owntransit-provision-linux-amd64
artifacts/owntransit-relay-linux-amd64.oci.tar
artifacts/owntransitctl-darwin-arm64
artifacts/owntransitctl-linux-amd64
evidence/PROVENANCE.json
evidence/THIRD_PARTY_LICENSES.txt
evidence/owntransit-connector-linux-amd64.spdx.json
evidence/owntransit-darwin-arm64.spdx.json
evidence/owntransit-launcher-darwin-arm64.spdx.json
evidence/owntransit-linux-amd64.spdx.json
evidence/owntransit-provision-darwin-arm64.spdx.json
evidence/owntransit-provision-linux-amd64.spdx.json
evidence/owntransit-relay-linux-amd64.oci.tar.spdx.json
evidence/owntransitctl-darwin-arm64.spdx.json
evidence/owntransitctl-linux-amd64.spdx.json
packaging/launchd/README.md
packaging/scripts/install.sh
packaging/scripts/install-linux.sh
packaging/scripts/install-macos.sh
packaging/scripts/uninstall-linux.sh
packaging/scripts/uninstall-macos.sh
packaging/systemd/README.md
packaging/systemd/owntransit-connector.service
packaging/systemd/owntransit-relay-exchange-template.service
packaging/systemd/owntransit-relay.service
EOF
}

write_expected_directories() {
  cat <<'EOF'
.
./artifacts
./evidence
./packaging
./packaging/launchd
./packaging/scripts
./packaging/systemd
EOF
}

expected_mode() {
  case "$1" in
    artifacts/owntransit-relay-linux-amd64.oci.tar) printf '%s\n' 644 ;;
    artifacts/*|packaging/scripts/*) printf '%s\n' 755 ;;
    *) printf '%s\n' 644 ;;
  esac
}

temporary=$(mktemp -d "$output_parent/.${output_base}.archive.XXXXXX") || fail "cannot create archive workspace"
temporary=$(CDPATH= cd -P -- "$temporary" && pwd) || fail "cannot resolve archive workspace"
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

expected_files="$temporary/expected-files"
expected_all_files="$temporary/expected-all-files"
expected_directories="$temporary/expected-directories"
write_expected_files | LC_ALL=C sort > "$expected_files"
{
  cat "$expected_files"
  printf '%s\n' SHA256SUMS
} | LC_ALL=C sort > "$expected_all_files"
write_expected_directories | LC_ALL=C sort > "$expected_directories"

version=
release_id=
release_sequence=
source_commit=
source_date_epoch=
source_manifest_sha256=

parse_build_inputs() {
  build_inputs="$bundle/BUILD-INPUTS"
  test -f "$build_inputs" && test ! -L "$build_inputs" || fail "BUILD-INPUTS is absent or not a regular file"
  {
    IFS= read -r version_line || fail "BUILD-INPUTS is incomplete"
    IFS= read -r release_id_line || fail "BUILD-INPUTS is incomplete"
    IFS= read -r release_sequence_line || fail "BUILD-INPUTS is incomplete"
    IFS= read -r source_commit_line || fail "BUILD-INPUTS is incomplete"
    IFS= read -r source_date_epoch_line || fail "BUILD-INPUTS is incomplete"
    IFS= read -r source_manifest_line || fail "BUILD-INPUTS is incomplete"
    if IFS= read -r extra_line; then
      fail "BUILD-INPUTS contains an unexpected extra line"
    fi
  } < "$build_inputs"

  case "$version_line" in version=*) version=${version_line#version=} ;; *) fail "BUILD-INPUTS version field is invalid" ;; esac
  case "$release_id_line" in release_id=*) release_id=${release_id_line#release_id=} ;; *) fail "BUILD-INPUTS release ID field is invalid" ;; esac
  case "$release_sequence_line" in release_sequence=*) release_sequence=${release_sequence_line#release_sequence=} ;; *) fail "BUILD-INPUTS release sequence field is invalid" ;; esac
  case "$source_commit_line" in source_commit=*) source_commit=${source_commit_line#source_commit=} ;; *) fail "BUILD-INPUTS source commit field is invalid" ;; esac
  case "$source_date_epoch_line" in source_date_epoch=*) source_date_epoch=${source_date_epoch_line#source_date_epoch=} ;; *) fail "BUILD-INPUTS source date field is invalid" ;; esac
  case "$source_manifest_line" in source_manifest_sha256=*) source_manifest_sha256=${source_manifest_line#source_manifest_sha256=} ;; *) fail "BUILD-INPUTS source manifest field is invalid" ;; esac

  case "$version" in *[!A-Za-z0-9._+-]*|'') fail "BUILD-INPUTS version contains an unsafe character" ;; esac
  case "$version" in [A-Za-z0-9]*) ;; *) fail "BUILD-INPUTS version must begin with an alphanumeric character" ;; esac
  test "${#version}" -le 64 || fail "BUILD-INPUTS version is too long for the canonical archive root"

  case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
  test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
  case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
  test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

  case "$release_sequence" in *[!0-9]*|'') fail "release sequence must be a positive decimal integer" ;; esac
  test "$release_sequence" -gt 0 || fail "release sequence must be positive"
  case "$source_commit" in *[!0-9a-f]*|'') fail "source commit must be lowercase hexadecimal" ;; esac
  case "${#source_commit}" in 40|64) ;; *) fail "source commit must contain 40 or 64 hexadecimal characters" ;; esac
  case "$source_date_epoch" in *[!0-9]*|'') fail "SOURCE_DATE_EPOCH must be a positive decimal integer" ;; esac
  test "${#source_date_epoch}" -le 10 || fail "SOURCE_DATE_EPOCH is out of the supported range"
  test "$source_date_epoch" -gt 0 || fail "SOURCE_DATE_EPOCH must be positive"
  case "$source_manifest_sha256" in *[!0-9a-f]*|'') fail "source manifest digest must be lowercase hexadecimal" ;; esac
  test "${#source_manifest_sha256}" -eq 64 || fail "source manifest digest must contain 64 hexadecimal characters"
}

validate_bundle() {
  parse_build_inputs

  special_entries=$(find "$bundle" -mindepth 1 ! -type f ! -type d -print)
  test -z "$special_entries" || {
    printf '%s\n' "$special_entries" >&2
    fail "bundle tree contains a symlink or non-regular entry"
  }
  linked_files=$(find "$bundle" -type f -links +1 -print)
  test -z "$linked_files" || {
    printf '%s\n' "$linked_files" >&2
    fail "bundle file has multiple hard links"
  }

  actual_files="$temporary/actual-files"
  actual_directories="$temporary/actual-directories"
  (
    cd "$bundle"
    find . -type f -print | sed 's|^\./||' | LC_ALL=C sort
  ) > "$actual_files"
  cmp -s "$expected_all_files" "$actual_files" || {
    diff -u "$expected_all_files" "$actual_files" >&2 || true
    fail "bundle file inventory is not the exact unsigned native staging tree"
  }
  (
    cd "$bundle"
    find . -type d -print | LC_ALL=C sort
  ) > "$actual_directories"
  cmp -s "$expected_directories" "$actual_directories" || {
    diff -u "$expected_directories" "$actual_directories" >&2 || true
    fail "bundle directory inventory is not the exact unsigned native staging tree"
  }

  while IFS= read -r relative; do
    metadata=$(file_metadata "$bundle/$relative") || fail "cannot inspect bundle member $relative"
    kind=${metadata%%|*}
    remainder=${metadata#*|}
    links=${remainder%%|*}
    mode=${remainder#*|}
    case "$kind" in "Regular File"|"regular file") ;; *) fail "bundle member is not a regular file: $relative" ;; esac
    test "$links" -eq 1 || fail "bundle member has multiple hard links: $relative"
    required_mode=$(expected_mode "$relative")
    test "$mode" = "$required_mode" || fail "bundle member mode is not $required_mode: $relative"
  done < "$expected_all_files"
  while IFS= read -r relative; do
    if test "$relative" = .; then
      directory="$bundle"
    else
      directory="$bundle/${relative#./}"
    fi
    mode=$(directory_mode "$directory") || fail "cannot inspect bundle directory $relative"
    test "$mode" = 755 || fail "bundle directory mode is not 755: $relative"
  done < "$expected_directories"

  checksum_paths="$temporary/checksum-paths"
  : > "$checksum_paths"
  previous=
  while IFS= read -r checksum_line; do
    digest=${checksum_line%%  *}
    relative=${checksum_line#"$digest  "}
    test "$checksum_line" = "$digest  $relative" || fail "SHA256SUMS contains a non-canonical line"
    test "${#digest}" -eq 64 || fail "SHA256SUMS contains a digest with the wrong length"
    case "$digest" in *[!0-9a-f]*|'') fail "SHA256SUMS contains a non-canonical digest" ;; esac
    test -n "$relative" || fail "SHA256SUMS contains an empty path"
    if test -n "$previous" && test "$relative" \< "$previous"; then
      fail "SHA256SUMS paths are not sorted"
    fi
    test "$relative" != "$previous" || fail "SHA256SUMS contains a duplicate path"
    previous=$relative
    printf '%s\n' "$relative" >> "$checksum_paths"
  done < "$bundle/SHA256SUMS"
  cmp -s "$expected_files" "$checksum_paths" || {
    diff -u "$expected_files" "$checksum_paths" >&2 || true
    fail "SHA256SUMS does not describe the exact native staging file set"
  }

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$bundle" && sha256sum -c SHA256SUMS >/dev/null 2>&1) || fail "SHA256SUMS verification failed"
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$bundle" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1) || fail "SHA256SUMS verification failed"
  else
    fail "sha256sum or shasum with check support is required"
  fi

  actual_source_manifest_sha256=$(sha256_file "$bundle/SOURCE-MANIFEST.txt")
  test "$actual_source_manifest_sha256" = "$source_manifest_sha256" ||
    fail "BUILD-INPUTS source manifest digest does not match SOURCE-MANIFEST.txt"
}

validate_bundle
checksum_record_before=$(sha256_file "$bundle/SHA256SUMS")

archive_root_name="owntransit-$version-native"
test "${#archive_root_name}" -le 100 || fail "canonical archive root exceeds the ustar component limit"
test "$output_base" = "$archive_root_name.tar.gz" ||
  fail "output basename must be exactly $archive_root_name.tar.gz"
snapshot_parent="$temporary/snapshot"
snapshot="$snapshot_parent/$archive_root_name"
mkdir -p "$snapshot"
chmod 0755 "$snapshot_parent" "$snapshot"
while IFS= read -r relative; do
  case "$relative" in */*) directory=${relative%/*}; mkdir -p "$snapshot/$directory" ;; esac
done < "$expected_all_files"
find "$snapshot" -type d -exec chmod 0755 {} \;
while IFS= read -r relative; do
  mode=$(expected_mode "$relative")
  install -m "$mode" "$bundle/$relative" "$snapshot/$relative"
  cmp -s "$bundle/$relative" "$snapshot/$relative" || fail "snapshot copy changed bundle member $relative"
done < "$expected_all_files"

live_bundle=$bundle
bundle=$snapshot
validate_bundle
bundle=$live_bundle

gnu_tar=
for candidate in gtar tar; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version 2>/dev/null | grep -Fq 'GNU tar'; then
    gnu_tar=$(command -v "$candidate")
    break
  fi
done

builder_digest='sha256:e8c859f5632dcfde7b32d2012b4351728f6437930887c2f6a91ea242459e5514'
builder_image="docker.io/library/golang:1.26.7-bookworm@$builder_digest"

archive_once() {
  archive_output=$1
  archive_number=$2
  if test -n "$gnu_tar"; then
    command -v gzip >/dev/null 2>&1 || fail "gzip is required with local GNU tar"
    uncompressed="$temporary/archive-$archive_number.tar"
    "$gnu_tar" \
      --sort=name \
      --format=ustar \
      --mtime="@$source_date_epoch" \
      --owner=0 \
      --group=0 \
      --numeric-owner \
      -cf "$uncompressed" \
      -C "$snapshot_parent" \
      "$archive_root_name"
    gzip -n -9 < "$uncompressed" > "$archive_output"
    rm -f -- "$uncompressed"
  elif command -v container >/dev/null 2>&1; then
    container_output="$temporary/container-output-$archive_number"
    mkdir "$container_output"
    chmod 0755 "$container_output"
    case "$snapshot_parent" in *,*) fail "Apple Container fallback cannot mount an input parent containing a comma" ;; esac
    case "$container_output" in *,*) fail "Apple Container fallback cannot mount an output parent containing a comma" ;; esac
    host_uid=$(id -u)
    host_gid=$(id -g)
    container run --rm \
      --network none \
      --uid "$host_uid" \
      --gid "$host_gid" \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp \
      --mount "type=bind,source=$snapshot_parent,target=/input,readonly" \
      --mount "type=bind,source=$container_output,target=/output" \
      "$builder_image" \
      /bin/sh -c '
        set -eu
        root_name=$1
        epoch=$2
        output_name=$3
        temporary=/output/archive-container-$$.tar
        trap '\''rm -f -- "$temporary"'\'' EXIT HUP INT TERM
        tar --version | grep -Fq "GNU tar"
        tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
          -cf "$temporary" -C /input "$root_name"
        gzip -n -9 < "$temporary" > "/output/$output_name"
      ' owntransit-archive "$archive_root_name" "$source_date_epoch" "$(basename "$archive_output")"
    mv -- "$container_output/$(basename "$archive_output")" "$archive_output"
  elif command -v docker >/dev/null 2>&1; then
    docker_output="$temporary/docker-output-$archive_number"
    mkdir "$docker_output"
    chmod 0755 "$docker_output"
    case "$snapshot_parent" in *,*) fail "Docker fallback cannot mount an input parent containing a comma" ;; esac
    case "$docker_output" in *,*) fail "Docker fallback cannot mount an output parent containing a comma" ;; esac
    host_uid=$(id -u)
    host_gid=$(id -g)
    docker run --rm \
      --pull=never \
      --network none \
      --user "$host_uid:$host_gid" \
      --cap-drop ALL \
      --read-only \
      --tmpfs /tmp:rw,nosuid,nodev,noexec \
      --mount "type=bind,source=$snapshot_parent,target=/input,readonly" \
      --mount "type=bind,source=$docker_output,target=/output" \
      "$builder_image" \
      /bin/sh -c '
        set -eu
        root_name=$1
        epoch=$2
        output_name=$3
        temporary=/output/archive-container-$$.tar
        trap '\''rm -f -- "$temporary"'\'' EXIT HUP INT TERM
        tar --version | grep -Fq "GNU tar"
        tar --sort=name --format=ustar --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
          -cf "$temporary" -C /input "$root_name"
        gzip -n -9 < "$temporary" > "/output/$output_name"
      ' owntransit-archive "$archive_root_name" "$source_date_epoch" "$(basename "$archive_output")"
    mv -- "$docker_output/$(basename "$archive_output")" "$archive_output"
  else
    fail "GNU tar, Apple Container, or Docker is required for deterministic native archiving"
  fi
  test -s "$archive_output" || fail "archive pass $archive_number produced no output"
  chmod 0644 "$archive_output"
}

first="$temporary/first.tar.gz"
second="$temporary/second.tar.gz"
archive_once "$first" first
archive_once "$second" second
cmp -s "$first" "$second" || fail "two native archive passes are not byte-identical"

validate_bundle
checksum_record_after=$(sha256_file "$bundle/SHA256SUMS")
test "$checksum_record_before" = "$checksum_record_after" || fail "bundle checksum record changed during archiving"
cmp -s "$bundle/SHA256SUMS" "$snapshot/SHA256SUMS" || fail "bundle checksum bytes changed during archiving"

archive_sha256=$(sha256_file "$first")
ln "$first" "$output" || fail "cannot atomically publish new archive output"
trap - EXIT HUP INT TERM
rm -rf -- "$temporary"

printf 'created deterministic qualification archive: %s\n' "$output"
printf 'archive_sha256=%s\n' "$archive_sha256"
printf '%s\n' 'This unsigned native archive carries no signature, policy, key, or trust authority; authenticate the external release evidence before qualification use.'
