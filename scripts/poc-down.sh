#!/bin/sh
set -eu

for name in owntransit-connector owntransit-relay; do
  if container list --all --format json | grep -q "\"id\"[[:space:]]*:[[:space:]]*\"$name\""; then
    container delete --force "$name"
  fi
done

echo "OwnTransit POC containers are absent; credentials and SSH host identity were preserved."
