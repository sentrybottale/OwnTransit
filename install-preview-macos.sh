#!/bin/sh
# Receiver-owned distribution; installs only an unprivileged local Mac client.
main() {
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV TAR_OPTIONS GZIP SSH_AUTH_SOCK SSH_ASKPASS DISPLAY
umask 077
version=0.6.0
base=https://github.com/sentrybottale/OwnTransit/releases/download/v0.6.0
fail() { printf 'owntransit-install: %s\n' "$*" >&2; exit 1; }
quote() { printf "'"; printf '%s' "$1" | sed "s/'/'\"'\"'/g"; printf "'"; }
test "$(uname -s):$(uname -m)" = Darwin:arm64 || fail 'Apple-silicon macOS is required'
uid=$(id -u)
test "$uid" != 0 || fail 'run as your Mac user, without sudo'
action=${1:-client}
test "$#" -le 1 || fail 'usage: sh install-preview-macos.sh [client|--uninstall]'
case "$action" in client|--uninstall) ;; *) fail 'macOS supports the client only' ;; esac
user_home=${HOME:?HOME is required}
case "$user_home" in /*) ;; *) fail 'HOME must be absolute' ;; esac
test "$(cd -P -- "$user_home" && pwd)" = "$user_home" || fail 'HOME must be canonical'
protected() {
  test -d "$1" && test ! -L "$1" || fail 'unsafe installation directory'
  owner=$(stat -f %u "$1"); raw=$(stat -f %p "$1")
  test "$owner" = 0 || test "$owner" = "$uid" || fail 'installation ancestor belongs to another user'
  test $((0$raw & 022)) -eq 0 || fail 'installation ancestor is writable by another user'
  ls -lde "$1" | sed '1d' | awk 'NF && $0 !~ /^[[:space:]]*[0-9]+: group:everyone deny delete$/ {exit 1}' || fail 'installation ancestor has an unsupported ACL'
}
path=$user_home
while :; do protected "$path"; test "$path" = / && break; path=$(dirname "$path"); done
ensure() {
  if test ! -e "$1" && test ! -L "$1"; then mkdir -m 0700 "$1"; fi
  protected "$1"
  test "$(stat -f %u "$1")" = "$uid" || fail 'installation directory must belong to this user'
}
software="$user_home/Library/Application Support/OwnTransitSoftware"
bindir="$user_home/.local/bin"
target="$software/$version"
alias_path="$bindir/owntransit-preview"
normal_alias="$bindir/owntransit"
owned_alias() {
  test -L "$1" && test "$(stat -f %u "$1")" = "$uid" && test "$(readlink "$1")" = "$target/owntransit"
}
check_release() {
  checked=${1:-$target}
  protected "$checked"
  test "$(stat -f %u "$checked")" = "$uid" || fail 'release belongs to another user'
  test "$(find "$checked" -mindepth 1 -maxdepth 1 | wc -l | tr -d '[:space:]')" = 6 || fail 'unexpected files in release directory'
  for member in CAPSULE LICENSE NOTICE SHA256SUMS owntransit install-macos.sh; do
    file="$checked/$member"
    test -f "$file" && test ! -L "$file" && test "$(stat -f %l "$file")" = 1 && test "$(stat -f %u "$file")" = "$uid" || fail 'unsafe installed release member'
    case "$member" in owntransit|install-macos.sh) mode=100755 ;; *) mode=100644 ;; esac
    test "$(stat -f %p "$file")" = "$mode" || fail 'installed release permissions differ'
  done
}
if test "$action" = --uninstall; then
  test -e "$target" || { printf '%s\n' 'OwnTransit 0.6.0 client is not installed here.'; exit 0; }
  for path in "$user_home/Library" "$user_home/Library/Application Support" "$software" "$target" "$user_home/.local" "$bindir"; do protected "$path"; done
  owned_alias "$alias_path" || fail 'preview command is not the managed client; nothing removed'
  check_release
  # Never purge pairing state or remove an unrelated command/directory.
  if owned_alias "$normal_alias"; then rm -- "$normal_alias"; fi
  rm -- "$alias_path"
  for member in CAPSULE LICENSE NOTICE SHA256SUMS owntransit install-macos.sh; do rm -- "$target/$member"; done
  rmdir "$target"
  printf '%s\n' 'OwnTransit client software removed. Pairing and SSH settings retained.'
  printf '%s\n' 'Reinstalling restores the commands without new pairing codes.'
  exit 0
fi
for path in "$user_home/Library" "$user_home/Library/Application Support" "$software" "$user_home/.local" "$bindir"; do ensure "$path"; done
stage=$(mktemp -d "$software/download.XXXXXXXX")
cleanup() {
  status=$?; trap - EXIT HUP INT TERM
  case "$stage" in "$software"/download.*) ;; *) exit 1 ;; esac
  suffix=${stage##*/download.}; case "$suffix" in ''|*[!A-Za-z0-9]*) exit 1 ;; esac
  if test -d "$stage" && test ! -L "$stage" && test "$(stat -f %u "$stage")" = "$uid"; then rm -rf -- "$stage"; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
fetch() {
  name=$1; maximum=$2
  env -i PATH="$PATH" LC_ALL=C curl --disable --fail --show-error --silent --location \
    --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 900 \
    --max-filesize "$maximum" --output "$stage/$name" "$base/$name" || fail "download failed: $name"
  test "$(wc -c < "$stage/$name" | tr -d '[:space:]')" -le "$maximum" || fail 'download exceeds bound'
}
printf 'Installing signed OwnTransit %s client for macOS arm64...\n' "$version"
fetch distribution-public.key 4096
test "$(shasum -a 256 "$stage/distribution-public.key" | awk '{print $1}')" = 55d97d90f4b81628aa534ba28960b63685ea5d1d4eeef489ffb28de632dc0a9e || fail 'distribution signer does not match pinned authority'
awk 'NF>=2 && $1=="ssh-ed25519" {print "owntransit-development " $1 " " $2; n++} END {if(n!=1) exit 1}' "$stage/distribution-public.key" > "$stage/allowed_signers"
fetch DEVELOPMENT-SHA256SUMS 8192
fetch DEVELOPMENT-SHA256SUMS.sig 8192
ssh-keygen -Y verify -f "$stage/allowed_signers" -I owntransit-development -n owntransit-development-v1 \
  -s "$stage/DEVELOPMENT-SHA256SUMS.sig" < "$stage/DEVELOPMENT-SHA256SUMS" >/dev/null 2>&1 || fail 'release signature rejected'
test "$(wc -l < "$stage/DEVELOPMENT-SHA256SUMS" | tr -d '[:space:]')" = 6 || fail 'unexpected release inventory'
awk 'BEGIN {ok=1;p=""} {if(NF!=2 || length($1)!=64 || $1!~/^[0-9a-f]+$/ || $0!=$1 "  " $2 || seen[$2]++ || (p!="" && p>=$2))ok=0; if($2!="DEVELOPMENT.txt" && $2!="install-preview-linux.sh" && $2!="install-preview-macos.sh" && $2!="owntransit-preview-0.6.0-darwin-arm64.tar.gz" && $2!="owntransit-preview-0.6.0-linux-amd64.tar.gz" && $2!="owntransit-preview-0.6.0-linux-arm64.tar.gz")ok=0;p=$2} END {exit ok?0:1}' "$stage/DEVELOPMENT-SHA256SUMS" || fail 'malformed release inventory'
top=owntransit-preview-$version-darwin-arm64
archive=$top.tar.gz
expected=$(awk -v name="$archive" '$2==name {print $1}' "$stage/DEVELOPMENT-SHA256SUMS")
fetch "$archive" 67108864
test "$(shasum -a 256 "$stage/$archive" | awk '{print $1}')" = "$expected" || fail 'archive digest mismatch'
tar -tzf "$stage/$archive" | sort > "$stage/members"
printf '%s\n' "$top/" "$top/CAPSULE" "$top/LICENSE" "$top/NOTICE" "$top/SHA256SUMS" "$top/owntransit" "$top/install-macos.sh" | sort > "$stage/expected"
cmp -s "$stage/members" "$stage/expected" || fail 'archive members are not exact'
tar -tvzf "$stage/$archive" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {exit 1}' || fail 'archive contains links or special files'
tar -xzf "$stage/$archive" -C "$stage"
chmod 0700 "$stage/$top"
chmod 0755 "$stage/$top/owntransit" "$stage/$top/install-macos.sh"
chmod 0644 "$stage/$top/CAPSULE" "$stage/$top/LICENSE" "$stage/$top/NOTICE" "$stage/$top/SHA256SUMS"
expected_capsule=$(printf 'schema=owntransit.development-capsule.v1\nversion=%s\nos=darwin\narch=arm64' "$version")
test "$(cat "$stage/$top/CAPSULE")" = "$expected_capsule" || fail 'wrong platform or release'
test "$(wc -c < "$stage/$top/SHA256SUMS" | tr -d '[:space:]')" -le 8192 || fail 'capsule inventory exceeds bound'
test "$(wc -l < "$stage/$top/SHA256SUMS" | tr -d '[:space:]')" = 5 || fail 'unexpected capsule inventory count'
awk 'BEGIN{ok=1;p=""} {if(NF!=2 || length($1)!=64 || $1!~/^[0-9a-f]+$/ || $0!=$1 "  " $2 || seen[$2]++ || (p!="" && p>=$2))ok=0;if($2!="CAPSULE" && $2!="LICENSE" && $2!="NOTICE" && $2!="install-macos.sh" && $2!="owntransit")ok=0;p=$2} END{exit ok?0:1}' "$stage/$top/SHA256SUMS" || fail 'malformed capsule inventory'
(cd "$stage/$top" && shasum -a 256 -c SHA256SUMS >/dev/null) || fail 'capsule checksum mismatch'
previous_target=
if test -e "$alias_path" || test -L "$alias_path"; then
  if ! owned_alias "$alias_path"; then
    test -L "$alias_path" && test "$(stat -f %u "$alias_path")" = "$uid" || fail 'refusing to replace an unmanaged client command'
    previous_target=$(readlink "$alias_path")
    case "$previous_target" in
      "$software/0.2.0/owntransit") previous_version=0.2.0 ;;
      "$software/0.3.0/owntransit") previous_version=0.3.0 ;;
      "$software/0.4.0/owntransit") previous_version=0.4.0 ;;
      "$software/0.5.0/owntransit") previous_version=0.5.0 ;;
      *) fail 'refusing to replace an unknown client release' ;;
    esac
    check_release "$software/$previous_version"
    previous_capsule=$(printf 'schema=owntransit.development-capsule.v1\nversion=%s\nos=darwin\narch=arm64' "$previous_version")
    test "$(cat "$software/$previous_version/CAPSULE")" = "$previous_capsule" || fail 'previous release identity differs'
  fi
fi
if test -e "$target" || test -L "$target"; then
  check_release
  for member in CAPSULE LICENSE NOTICE SHA256SUMS owntransit install-macos.sh; do
    test -f "$target/$member" && test ! -L "$target/$member" && test "$(stat -f %l "$target/$member")" = 1 || fail 'unsafe existing release member'
    cmp -s "$target/$member" "$stage/$top/$member" || fail 'existing release differs; refusing overwrite'
  done
else mv -- "$stage/$top" "$target"; fi
if test -n "$previous_target"; then
  test "$(readlink "$alias_path")" = "$previous_target" || fail 'client command changed during upgrade'
  alias_stage=$alias_path.$$.new
  test ! -e "$alias_stage" && test ! -L "$alias_stage" || fail 'client command staging name exists'
  ln -s "$target/owntransit" "$alias_stage"
  mv -- "$alias_stage" "$alias_path"
elif test ! -L "$alias_path"; then ln -s "$target/owntransit" "$alias_path"; fi
if test -n "$previous_target" && test -L "$normal_alias" && test "$(stat -f %u "$normal_alias")" = "$uid" && test "$(readlink "$normal_alias")" = "$previous_target"; then
  alias_stage=$normal_alias.$$.new
  test ! -e "$alias_stage" && test ! -L "$alias_stage" || fail 'normal command staging name exists'
  ln -s "$target/owntransit" "$alias_stage"
  mv -- "$alias_stage" "$normal_alias"
fi
if test ! -e "$normal_alias" && test ! -L "$normal_alias"; then ln -s "$target/owntransit" "$normal_alias"; fi
command_path=$alias_path
if owned_alias "$normal_alias"; then command_path=$normal_alias; fi
printf '%s\n' 'Installed. Existing pairing and SSH settings are unchanged.'
printf '%s\n' 'THIS MACHINE: your Mac client (the computer you connect from), not the public VPS.'
printf 'NEXT — on THIS Mac, without sudo: '; quote "$command_path"; printf ' pair setup\n'
printf '%s\n' 'Then answer its prompts: your relay URL and the private receiver code (otpair2.).'
printf 'Another tunnel: '; quote "$command_path"; printf ' pair setup --tunnel office\n'
printf 'Uninstall (retains pairing): sh '; quote "$target/install-macos.sh"; printf ' --uninstall\n'
}
main "$@"
