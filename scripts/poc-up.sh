#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
secrets_root="$project_root/poc/secrets"
ssh_root="$project_root/poc/runtime/ssh"
network_name=owntransit-poc

if [ ! -f "$secrets_root/relay/config.json" ] || [ ! -f "$secrets_root/connector/config.json" ]; then
  echo "Run scripts/poc-init.sh first." >&2
  exit 1
fi
container image inspect owntransit-relay:local >/dev/null
container image inspect owntransit-connector-poc:local >/dev/null

for name in owntransit-connector owntransit-relay; do
  if container list --all --format json | grep -q "\"id\"[[:space:]]*:[[:space:]]*\"$name\""; then
    echo "$name already exists. Run scripts/poc-down.sh before replacing the POC." >&2
    exit 1
  fi
done

if ! container network list --quiet | grep -Fxq "$network_name"; then
  container network create --internal --subnet 192.168.128.0/24 "$network_name"
else
  network_config=$(container network inspect "$network_name")
  if ! printf '%s\n' "$network_config" | grep -q '"mode"[[:space:]]*:[[:space:]]*"hostOnly"' \
    || ! printf '%s\n' "$network_config" | grep -q '"ipv4Subnet"[[:space:]]*:[[:space:]]*"192.168.128.0\\/24"'; then
    echo "Existing $network_name network is not the expected host-only 192.168.128.0/24 network." >&2
    exit 1
  fi
fi

host_uid=$(id -u)
host_gid=$(id -g)
container run --detach --name owntransit-relay --network "$network_name" \
  --uid "$host_uid" --gid "$host_gid" --cpus 1 --memory 256M \
  --ulimit nofile=128:128 --cap-drop ALL --read-only \
  --mount "type=bind,source=$secrets_root/relay,target=/run/owntransit,readonly" \
  owntransit-relay:local -config /run/owntransit/config.json

relay_ip=$(container inspect owntransit-relay | sed -n 's/.*"ipv4Address" : "\([^/]*\)\/.*".*/\1/p' | tr -d '\\' | head -n 1)
if [ -z "$relay_ip" ]; then
  echo "Could not resolve the private relay address; refusing to start connector." >&2
  exit 1
fi

container run --detach --name owntransit-connector --network "$network_name" \
  --cpus 1 --memory 256M --ulimit nofile=128:128 --init \
  --tmpfs /run/owntransit \
  --env "OWNTRANSIT_RELAY_URL=ws://$relay_ip:9087/connects" \
  --mount "type=bind,source=$secrets_root/connector,target=/secrets,readonly" \
  --mount "type=bind,source=$ssh_root,target=/run/owntransit-ssh,readonly" \
  owntransit-connector-poc:local

echo "OwnTransit local POC is starting. Use scripts/poc-status.sh, then scripts/poc-ssh.sh."
