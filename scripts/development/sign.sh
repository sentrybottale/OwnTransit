#!/bin/sh
# Development signatures have no production release-policy authority.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY WAYLAND_DISPLAY
umask 077
fail() { printf 'development-sign: %s\n' "$*" >&2; exit 1; }
test "$#" -eq 3 || fail 'usage: sign.sh PRIVATE_KEY PUBLIC_KEY ABSOLUTE_DEVELOPMENT_SHA256SUMS'
key=$1
public=$2
subject=$3
for path in "$key" "$public" "$subject"; do
  case "$path" in /*) ;; *) fail 'all paths must be absolute' ;; esac
  case "$path" in *[!A-Za-z0-9/_.+-]*) fail 'paths must use the portable custody alphabet' ;; esac
  test -f "$path" && test ! -L "$path" || fail 'regular non-symlink files are required'
  canonical=$(CDPATH= cd -P -- "$(dirname "$path")" && pwd)/$(basename "$path")
  test "$canonical" = "$path" || fail 'symlinked path ancestor rejected'
done
case "$key" in "$(dirname "$subject")"/*) fail 'private key must stay outside artifact staging' ;; esac
test "$(basename "$subject")" = DEVELOPMENT-SHA256SUMS || fail 'development inventory name required'
test ! -e "$subject.sig" && test ! -L "$subject.sig" || fail 'refusing to overwrite an existing signature'
test "$(wc -c < "$subject" | tr -d '[:space:]')" -le 8192 || fail 'inventory exceeds bound'
uid=$(id -u)
path=$key
is_key=yes
while :; do
  test ! -L "$path" || fail 'symlinked key custody rejected'
  case "$(uname -s)" in
    Darwin)
      owner=$(stat -f %u "$path")
      mode_raw=$(stat -f %p "$path")
      mode=$((0$mode_raw & 07777))
      links=$(stat -f %l "$path")
      # macOS home directories commonly deny deletion to everyone. This ACE
      # grants no access and is safe to retain. Every grant or other ACE fails.
      ls -lde "$path" | sed '1d' | awk '
        NF && $0 !~ /^[[:space:]]*[0-9]+: group:everyone deny delete$/ {exit 1}
      ' || fail 'key custody contains an unsupported ACL'
      ;;
    Linux)
      owner=$(stat -c %u "$path")
      mode_raw=$(stat -c %a "$path")
      mode=$((0$mode_raw))
      links=$(stat -c %h "$path")
      ;;
    *) fail 'unsupported signer host' ;;
  esac
  if test "$is_key" = yes; then
    test "$owner" = "$uid" && test "$mode" -eq 384 && test "$links" = 1 || fail 'private key must be caller-owned, single-link mode 0600'
    is_key=no
  else
    test -d "$path" || fail 'custody ancestor is not a directory'
    test "$owner" = 0 || test "$owner" = "$uid" || fail 'custody ancestor belongs to another user'
    test $((mode & 022)) -eq 0 || fail 'custody ancestor is group/world writable'
  fi
  test "$path" = / && break
  path=$(dirname "$path")
done
derived=$(ssh-keygen -y -f "$key" </dev/null) || fail 'cannot load the named private key noninteractively'
derived=$(printf '%s\n' "$derived" | awk 'NR==1 && NF>=2 {print $1 " " $2} END {if(NR!=1) exit 1}') || fail 'invalid derived public key'
expected=$(awk '{print $1 " " $2}' "$public")
test "$derived" = "$expected" || fail 'private key does not match the intended public key'
case "$expected" in 'ssh-ed25519 '*) ;; *) fail 'Ed25519 distribution key required' ;; esac
allowed=$(mktemp "$(dirname "$subject")/.development-allowed.XXXXXXXX")
trap 'rm -f -- "$allowed"' EXIT HUP INT TERM
printf 'owntransit-development %s\n' "$expected" > "$allowed"
ssh-keygen -Y sign -f "$key" -n owntransit-development-v1 "$subject" </dev/null
ssh-keygen -Y verify -f "$allowed" -I owntransit-development -n owntransit-development-v1 -s "$subject.sig" < "$subject"
printf '%s\n' 'Development inventory signed and verified. No production manifest, policy, qualification record or counter was created.'
