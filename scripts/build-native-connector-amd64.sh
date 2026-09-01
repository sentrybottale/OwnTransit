#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
dist="$project_root/dist"
mkdir -p "$dist"
export_root=$(mktemp -d "$dist/.owntransit-native-connector.XXXXXX")
manifest_before=$(mktemp "$dist/.owntransit-source-before.XXXXXX")
manifest_after=$(mktemp "$dist/.owntransit-source-after.XXXXXX")
artifact_tmp=$(mktemp "$dist/.owntransit-connector-linux-amd64-native.XXXXXX")
trap 'rm -rf "$export_root"; rm -f "$manifest_before" "$manifest_after" "$artifact_tmp"' EXIT HUP INT TERM

cd "$project_root"
"$project_root/scripts/source-manifest.sh" > "$manifest_before"
container build --progress plain --file Containerfile \
  --target test --tag owntransit-test:production .
container build --progress plain --platform linux/amd64 --file Containerfile \
  --target connector --output "type=local,dest=$export_root" .
"$project_root/scripts/source-manifest.sh" > "$manifest_after"
cmp -s "$manifest_before" "$manifest_after" || {
  echo "Source changed during the connector build; refusing to publish the artifact." >&2
  exit 1
}

test -x "$export_root/out.tar/linux_amd64/owntransit-connector"
install -m 0755 "$export_root/out.tar/linux_amd64/owntransit-connector" \
  "$artifact_tmp"
mv "$artifact_tmp" "$dist/owntransit-connector-linux-amd64-native"
install -m 0644 "$manifest_after" "$dist/owntransit-connector-linux-amd64-native.source-manifest.txt"
(cd "$dist" && shasum -a 256 owntransit-connector-linux-amd64-native > owntransit-connector-linux-amd64-native.sha256)
(cd "$dist" && shasum -a 256 owntransit-connector-linux-amd64-native.source-manifest.txt > owntransit-connector-linux-amd64-native.source-manifest.txt.sha256)

echo "Created the native connector, checksum, and source manifest; target is fixed to 127.0.0.1:22"
