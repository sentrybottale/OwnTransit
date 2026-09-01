#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist="$project_root/dist"
mkdir -p "$dist"
manifest_before=$(mktemp "$dist/.owntransit-source-before.XXXXXX")
manifest_after=$(mktemp "$dist/.owntransit-source-after.XXXXXX")
binary_tmp=$(mktemp "$dist/.owntransit-relay-linux-amd64.XXXXXX")
trap 'rm -f "$binary_tmp" "$manifest_before" "$manifest_after"' EXIT HUP INT TERM

cd "$project_root"
"$project_root/scripts/source-manifest.sh" > "$manifest_before"
container build --progress plain --platform linux/amd64 --file Containerfile \
  --target relay --tag owntransit-relay:poc-amd64 .
container image save --platform linux/amd64 \
  --output "$dist/owntransit-relay-amd64.oci.tar" owntransit-relay:poc-amd64

# Apple Container exports an OCI image layout that Docker on the VPS cannot
# load directly. Extract the one-file scratch layer as the reviewed deployment
# artifact; deploy/vps/Containerfile.relay wraps this exact static binary.
oci_tar="$dist/owntransit-relay-amd64.oci.tar"
outer_digest=$(tar -xOf "$oci_tar" index.json | jq -er '.manifests[0].digest | sub("^sha256:"; "")')
manifest_digest=$(tar -xOf "$oci_tar" "blobs/sha256/$outer_digest" \
  | jq -er '.manifests[] | select(.platform.os == "linux" and .platform.architecture == "amd64") | .digest | sub("^sha256:"; "")')
layer_digest=$(tar -xOf "$oci_tar" "blobs/sha256/$manifest_digest" \
  | jq -er 'if (.layers | length) == 1 then .layers[0].digest | sub("^sha256:"; "") else error("relay image must have exactly one layer") end')

tar -xOf "$oci_tar" "blobs/sha256/$layer_digest" \
  | tar -xzOf - owntransit-relay > "$binary_tmp"
"$project_root/scripts/source-manifest.sh" > "$manifest_after"
cmp -s "$manifest_before" "$manifest_after" || {
  echo "Source changed during the relay build; refusing to publish the artifact." >&2
  exit 1
}
chmod 0755 "$binary_tmp"
mv "$binary_tmp" "$dist/owntransit-relay-linux-amd64"
install -m 0644 "$manifest_after" "$dist/owntransit-relay-linux-amd64.source-manifest.txt"

(cd "$dist" && shasum -a 256 owntransit-relay-amd64.oci.tar > owntransit-relay-amd64.oci.tar.sha256)
(cd "$dist" && shasum -a 256 owntransit-relay-linux-amd64 > owntransit-relay-linux-amd64.sha256)
(cd "$dist" && shasum -a 256 owntransit-relay-linux-amd64.source-manifest.txt > owntransit-relay-linux-amd64.source-manifest.txt.sha256)

echo "Created the relay OCI archive, static binary, checksums, and source manifest"
