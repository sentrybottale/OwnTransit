#!/bin/sh
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

test "$(uname -s)" = Linux || {
  printf '%s\n' 'linux-vm: qualification requires Linux' >&2
  exit 1
}
case "$(uname -m)" in
  x86_64|amd64) architecture=amd64 ;;
  aarch64|arm64) architecture=arm64 ;;
  *)
    printf 'linux-vm: unsupported Linux architecture: %s\n' "$(uname -m)" >&2
    exit 1
    ;;
esac

script_dir=$(CDPATH='' cd -P -- "$(dirname "$0")" && pwd) || {
  printf '%s\n' 'linux-vm: cannot resolve qualification script directory' >&2
  exit 1
}
exec "$script_dir/linux-$architecture-vm.sh" "$@"
