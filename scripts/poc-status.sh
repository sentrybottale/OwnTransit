#!/bin/sh
set -eu

failed=0
for name in owntransit-relay owntransit-connector; do
  if ! container list --format json | grep -q "\"id\"[[:space:]]*:[[:space:]]*\"$name\""; then
    echo "$name is not running." >&2
    failed=1
  fi
done

container list
for name in owntransit-relay owntransit-connector; do
  echo "[$name]"
  container logs -n 20 "$name" 2>&1 || true
done

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "Processes are running. Use scripts/poc-ssh.sh for an end-to-end health proof."
