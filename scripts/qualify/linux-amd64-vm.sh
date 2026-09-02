#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

script_dir=$(CDPATH='' cd -P -- "$(dirname "$0")" && pwd) || {
  printf '%s\n' 'linux-amd64-vm: cannot resolve qualification script directory' >&2
  exit 1
}
exec "$script_dir/linux-vm-core.sh" --qualification-architecture amd64 "$@"
