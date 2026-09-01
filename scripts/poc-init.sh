#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
poc_root="$project_root/poc"
secrets_root="$poc_root/secrets"
ssh_root="$poc_root/runtime/ssh"

if [ -e "$secrets_root" ]; then
  echo "Refusing to overwrite $secrets_root" >&2
  exit 1
fi

mkdir -p "$poc_root" "$ssh_root"
chmod 700 "$poc_root" "$ssh_root"
mkdir -m 0700 "$secrets_root"

host_uid=$(id -u)
host_gid=$(id -g)
if ! container run --rm --progress none --network none --read-only \
  --uid "$host_uid" --gid "$host_gid" --cpus 1 --memory 256M \
  --ulimit nofile=32:32 --cap-drop ALL \
  --mount "type=bind,source=$secrets_root,target=/work" \
  owntransit-certgen-poc:local \
  -out /work \
  -relay-listen 0.0.0.0:9087 \
  -relay-url ws://127.0.0.1:9087/connects; then
  echo "Credential generation failed; inspect and securely remove the incomplete $secrets_root before retrying." >&2
  exit 1
fi

if [ ! -f "$ssh_root/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C owntransit-poc-client -f "$ssh_root/id_ed25519"
fi
cp "$ssh_root/id_ed25519.pub" "$ssh_root/authorized_keys"
chmod 600 "$ssh_root/id_ed25519" "$ssh_root/authorized_keys"
chmod 644 "$ssh_root/id_ed25519.pub"

if [ ! -f "$ssh_root/ssh_host_ed25519_key" ]; then
  ssh-keygen -q -t ed25519 -N '' -C owntransit-poc-host -f "$ssh_root/ssh_host_ed25519_key"
fi
chmod 600 "$ssh_root/ssh_host_ed25519_key"
chmod 644 "$ssh_root/ssh_host_ed25519_key.pub"

awk '{ print "owntransit-poc " $1 " " $2 }' \
  "$ssh_root/ssh_host_ed25519_key.pub" > "$ssh_root/known_hosts"
chmod 600 "$ssh_root/known_hosts"

echo "Local POC credentials initialized. Offline issuer keys remain under poc/secrets/offline-issuers and are never mounted into an endpoint."
