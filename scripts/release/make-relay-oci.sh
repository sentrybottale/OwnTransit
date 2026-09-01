#!/bin/sh
set -eu

fail() {
  printf 'make-relay-oci: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage: make-relay-oci.sh BINARY OUTPUT RELEASE_ID VERSION COMMIT SOURCE_DATE_EPOCH PROJECT_LICENSE THIRD_PARTY_NOTICES

Build one deterministic, uncompressed OCI archive around an already-built
linux/amd64 owntransit-relay executable and its required license material.
OUTPUT must not exist.
EOF
}

test "$#" -eq 8 || {
  usage >&2
  exit 2
}

binary=$1
output=$2
release_id=$3
version=$4
commit=$5
source_date_epoch=$6
project_license=$7
third_party_notices=$8

case "$release_id" in *[!a-z2-7]*|'') fail "release ID must be lowercase unpadded RFC 4648 base32" ;; esac
test "${#release_id}" -eq 52 || fail "release ID must contain 52 base32 characters"
case "$release_id" in *[aq]) ;; *) fail "release ID has non-canonical unused trailing bits" ;; esac
test "$release_id" != aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa || fail "release ID must be nonzero"

case "$version" in
  *[!A-Za-z0-9._+-]*|'') fail "version contains an unsafe character" ;;
esac
case "$version" in
  [A-Za-z0-9]*) ;;
  *) fail "version must begin with an alphanumeric character" ;;
esac
test "${#version}" -le 128 || fail "version is too long"

case "$commit" in
  *[!0-9a-f]*|'') fail "commit must be lowercase hexadecimal" ;;
esac
case "${#commit}" in
  40|64) ;;
  *) fail "commit must contain 40 or 64 hexadecimal characters" ;;
esac

case "$source_date_epoch" in
  *[!0-9]*|'') fail "SOURCE_DATE_EPOCH must be a positive decimal integer" ;;
esac
test "${#source_date_epoch}" -le 10 || fail "SOURCE_DATE_EPOCH is out of the supported range"
test "$source_date_epoch" -gt 0 || fail "SOURCE_DATE_EPOCH must be positive"

test -f "$binary" && test ! -L "$binary" || fail "relay binary must be a regular non-symlink file"
test -x "$binary" || fail "relay binary is not executable"
for license_input in "$project_license" "$third_party_notices"; do
  test -f "$license_input" && test ! -L "$license_input" ||
    fail "license input must be a regular non-symlink file"
  license_size=$(wc -c <"$license_input" | tr -d '[:space:]')
  test "$license_size" -gt 0 && test "$license_size" -le 1048576 ||
    fail "license input is empty or exceeds 1 MiB"
done
case "$output" in
  /*) ;;
  *) fail "output path must be absolute" ;;
esac
test ! -e "$output" && test ! -L "$output" || fail "output already exists"

output_parent_input=$(dirname "$output")
output_parent=$(CDPATH= cd -P -- "$output_parent_input" && pwd) || fail "cannot resolve output parent"
output_base=$(basename "$output")
case "$output_base" in
  *[!A-Za-z0-9._+-]*|'') fail "output basename contains an unsafe character" ;;
esac
resolved_output="$output_parent/$output_base"
test "$output_parent" != / || resolved_output="/$output_base"
test "$resolved_output" = "$output" || fail "output path must be canonical and contain no symlinked parent"

gnu_tar=${OWNTRANSIT_GNU_TAR:-}
if test -n "$gnu_tar"; then
  "$gnu_tar" --version 2>/dev/null | grep -Fq 'GNU tar' || fail "OWNTRANSIT_GNU_TAR is not GNU tar"
else
  for candidate in gtar tar; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version 2>/dev/null | grep -Fq 'GNU tar'; then
      gnu_tar=$candidate
      break
    fi
  done
fi
test -n "$gnu_tar" || fail "GNU tar is required for reproducible OCI ownership and timestamps"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "sha256sum or shasum is required"
  fi
}

file_size() {
  wc -c < "$1" | tr -d '[:space:]'
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-relay-oci.XXXXXX") || fail "cannot create temporary directory"
output_temporary=$(mktemp "$output_parent/.${output_base}.XXXXXX") || {
  rm -rf -- "$temporary"
  fail "cannot create temporary output"
}
cleanup() {
  rm -rf -- "$temporary"
  rm -f -- "$output_temporary"
}
trap cleanup EXIT HUP INT TERM

rootfs="$temporary/rootfs"
layout="$temporary/layout"
mkdir -p "$rootfs" "$layout/blobs/sha256"
chmod 0755 "$rootfs" "$layout" "$layout/blobs" "$layout/blobs/sha256"
install -m 0755 "$binary" "$rootfs/owntransit-relay"
install -d -m 0755 "$rootfs/licenses"
install -m 0644 "$project_license" "$rootfs/licenses/Apache-2.0.txt"
install -m 0644 "$third_party_notices" "$rootfs/licenses/THIRD_PARTY_NOTICES.md"

layer="$temporary/layer.tar"
"$gnu_tar" \
  --sort=name \
  --format=ustar \
  --mtime="@$source_date_epoch" \
  --owner=65532 \
  --group=65532 \
  --numeric-owner \
  -cf "$layer" \
  -C "$rootfs" \
  licenses owntransit-relay

license_roundtrip="$temporary/license-roundtrip"
notice_roundtrip="$temporary/notice-roundtrip"
"$gnu_tar" -xOf "$layer" licenses/Apache-2.0.txt >"$license_roundtrip"
"$gnu_tar" -xOf "$layer" licenses/THIRD_PARTY_NOTICES.md >"$notice_roundtrip"
cmp -s "$project_license" "$license_roundtrip" || fail "OCI layer changed the project license"
cmp -s "$third_party_notices" "$notice_roundtrip" || fail "OCI layer changed the third-party notices"
layer_digest=$(sha256_file "$layer")
layer_size=$(file_size "$layer")
install -m 0644 "$layer" "$layout/blobs/sha256/$layer_digest"

config="$temporary/config.json"
printf '%s\n' \
  "{\"architecture\":\"amd64\",\"config\":{\"Cmd\":[\"run\",\"--runtime-root=/runtime\",\"--anchor-view-root=/anchor\",\"--reader-gid=65532\"],\"Entrypoint\":[\"/owntransit-relay\"],\"Labels\":{\"org.opencontainers.image.licenses\":\"Apache-2.0\",\"org.opencontainers.image.revision\":\"$commit\",\"org.opencontainers.image.title\":\"OwnTransit Relay\",\"org.opencontainers.image.version\":\"$version\",\"org.opencontainers.image.vendor\":\"OwnTransit\",\"org.opencontainers.image.release.id\":\"$release_id\"},\"User\":\"65532:65532\",\"WorkingDir\":\"/\"},\"os\":\"linux\",\"rootfs\":{\"diff_ids\":[\"sha256:$layer_digest\"],\"type\":\"layers\"}}" \
  > "$config"
config_digest=$(sha256_file "$config")
config_size=$(file_size "$config")
install -m 0644 "$config" "$layout/blobs/sha256/$config_digest"

manifest="$temporary/manifest.json"
printf '%s\n' \
  "{\"schemaVersion\":2,\"config\":{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"sha256:$config_digest\",\"size\":$config_size},\"layers\":[{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar\",\"digest\":\"sha256:$layer_digest\",\"size\":$layer_size}]}" \
  > "$manifest"
manifest_digest=$(sha256_file "$manifest")
manifest_size=$(file_size "$manifest")
install -m 0644 "$manifest" "$layout/blobs/sha256/$manifest_digest"

printf '%s\n' \
  "{\"schemaVersion\":2,\"manifests\":[{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"sha256:$manifest_digest\",\"size\":$manifest_size,\"platform\":{\"architecture\":\"amd64\",\"os\":\"linux\"},\"annotations\":{\"org.opencontainers.image.ref.name\":\"owntransit-relay:$release_id\"}}]}" \
  > "$layout/index.json"
printf '%s\n' '{"imageLayoutVersion":"1.0.0"}' > "$layout/oci-layout"
chmod 0644 "$layout/index.json" "$layout/oci-layout" "$layout/blobs/sha256/"*

"$gnu_tar" \
  --sort=name \
  --format=ustar \
  --mtime="@$source_date_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -cf "$output_temporary" \
  -C "$layout" \
  blobs index.json oci-layout
chmod 0644 "$output_temporary"
mv -- "$output_temporary" "$output"
output_temporary="$output_parent/.completed-owntransit-output"
trap - EXIT HUP INT TERM
rm -rf -- "$temporary"

printf 'created %s\n' "$output"
