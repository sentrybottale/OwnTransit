#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
client_secrets="$project_root/poc/secrets/client"
host_uid=$(id -u)
host_gid=$(id -g)
relay_ip=$(container inspect owntransit-relay | sed -n 's/.*"ipv4Address" : "\([^/]*\)\/.*".*/\1/p' | tr -d '\\' | head -n 1)
test -n "$relay_ip"

exec container run --rm --interactive --progress none --network owntransit-poc \
  --uid "$host_uid" --gid "$host_gid" --cpus 1 --memory 256M \
  --ulimit nofile=32:32 --cap-drop ALL --read-only \
  --mount "type=bind,source=$client_secrets,target=/run/owntransit,readonly" \
  owntransit-client:local -config /run/owntransit/config.json \
  -relay-url "ws://$relay_ip:9087/connects"
