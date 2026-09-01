#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ssh_root="$project_root/poc/runtime/ssh"
proxy_command="$project_root/scripts/poc-proxy.sh"

exec ssh \
  -i "$ssh_root/id_ed25519" \
  -o IdentitiesOnly=yes \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  -o "UserKnownHostsFile=$ssh_root/known_hosts" \
  -o HostKeyAlias=owntransit-poc \
  -o "ProxyCommand=$proxy_command" \
  owntransit-poc@owntransit-poc "$@"
