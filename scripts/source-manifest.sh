#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

# Hash the complete reviewed build/deployment input set, including Git-untracked
# source files. The output is deterministic by path and contains no ignored
# runtime credentials.
find \
  .dockerignore \
  Containerfile \
  LICENSE \
  THIRD_PARTY_NOTICES.md \
  go.mod \
  go.sum \
  cmd \
  internal \
  deploy \
  scripts/release \
  scripts/build-native-connector-amd64.sh \
  scripts/build-relay-amd64.sh \
  scripts/source-manifest.sh \
  -type f -print |
  LC_ALL=C sort |
  while IFS= read -r path; do
    shasum -a 256 "$path"
  done
