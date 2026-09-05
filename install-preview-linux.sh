#!/bin/sh
# Explicit signed DEVELOPMENT lane. This does not install the stable release.
main() {
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
unset CDPATH ENV BASH_ENV TAR_OPTIONS GZIP SSH_AUTH_SOCK SSH_ASKPASS DISPLAY
umask 077
version=0.1.2
base=https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.2
stage=
fail() { printf 'owntransit-development: %s\n' "$*" >&2; exit 1; }
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test -n "$stage"; then
    case "$stage" in /var/lib/owntransit-preview-download.*) ;; *) exit 1 ;; esac
    suffix=${stage#/var/lib/owntransit-preview-download.}
    case "$suffix" in ''|*[!A-Za-z0-9]*) exit 1 ;; esac
    if test -d "$stage" && test ! -L "$stage" && test "$(stat -c %u "$stage")" = 0; then
      rm -rf -- "$stage" || status=1
    else status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
test "$#" -ge 1 && test "$#" -le 2 || fail 'usage: sudo sh install-preview-linux.sh client|connector|relay [PUBLIC_RELAY_URL]'
role=$1
setup_url=${2-}
test "$#" -eq 1 || test "$role" = relay || fail 'a public URL can be passed only for relay setup'
case "$role" in client|connector|relay) ;; *) fail 'role must be client, connector or relay' ;; esac
test "$(id -u)" = 0 || fail 'run through sudo'
test "$(uname -s)" = Linux || fail 'Linux is required'
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'Linux amd64 or arm64 is required' ;; esac
for command_name in awk cat chmod curl dirname env grep id install mktemp mv rm sha256sum sort ssh-keygen stat tar tr uname wc; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command missing: $command_name"
done
system_ca_found=no
for ca_path in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
  if test -s "$ca_path"; then system_ca_found=yes; break; fi
done
test "$system_ca_found" = yes || fail 'install the distribution ca-certificates package first'
for path in / /var /var/lib; do
  test -d "$path" && test ! -L "$path" && test "$(stat -c %u "$path")" = 0 || fail 'unsafe download staging ancestor'
  mode=$(stat -c %a "$path")
  case "$mode" in [0-7][0-7][0-7]) ;; *) fail 'unsafe staging mode' ;; esac
  test $((0$mode & 022)) -eq 0 || fail 'writable staging ancestor'
done
stage=$(mktemp -d /var/lib/owntransit-preview-download.XXXXXXXX)
test "$(stat -c %a "$stage")" = 700 && test "$(stat -c %u "$stage")" = 0 || fail 'staging is not private'

fetch() {
  name=$1
  maximum=$2
  test ! -e "$stage/$name" && test ! -L "$stage/$name" || fail 'duplicate asset'
  (
    ulimit -f 262144
    env -i PATH="$PATH" LC_ALL=C curl --disable --fail --show-error --silent --location \
      --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 900 \
      --max-filesize "$maximum" --output "$stage/$name.part" "$base/$name"
  ) || fail "download failed: $name"
  test -f "$stage/$name.part" && test ! -L "$stage/$name.part" && test "$(stat -c %h "$stage/$name.part")" = 1 || fail 'unsafe downloaded file'
  test "$(wc -c < "$stage/$name.part" | tr -d '[:space:]')" -le "$maximum" || fail 'download exceeds size bound'
  mv -- "$stage/$name.part" "$stage/$name"
}

printf 'Installing signed OwnTransit %s DEVELOPMENT preview (%s, Linux %s).\n' "$version" "$role" "$arch"
printf '%s\n' 'This is a development build. Endpoint credentials are preserved. Explicit relay setup may replace an identified old relay, with rollback on failure.'
fetch distribution-public.key 4096
test "$(sha256sum "$stage/distribution-public.key" | awk '{print $1}')" = 55d97d90f4b81628aa534ba28960b63685ea5d1d4eeef489ffb28de632dc0a9e || fail 'distribution key does not match the pinned authority'
awk 'NF >= 2 && $1 == "ssh-ed25519" {print "owntransit-development " $1 " " $2; count++} END {if(count!=1) exit 1}' "$stage/distribution-public.key" > "$stage/allowed_signers"
fetch DEVELOPMENT-SHA256SUMS 8192
fetch DEVELOPMENT-SHA256SUMS.sig 8192
ssh-keygen -Y verify -f "$stage/allowed_signers" -I owntransit-development \
  -n owntransit-development-v1 -s "$stage/DEVELOPMENT-SHA256SUMS.sig" \
  < "$stage/DEVELOPMENT-SHA256SUMS" >/dev/null 2>&1 || fail 'development inventory signature rejected'

test "$(wc -l < "$stage/DEVELOPMENT-SHA256SUMS" | tr -d '[:space:]')" = 5 || fail 'unexpected signed inventory count'
awk '
  BEGIN { ok=1; previous="" }
  {
    if (NF!=2 || length($1)!=64 || $1 !~ /^[0-9a-f]+$/ || $0!=$1 "  " $2 || seen[$2]++ || (previous!="" && previous >= $2)) ok=0
    if ($2!="DEVELOPMENT.txt" && $2!="install-preview-linux.sh" && $2!="owntransit-preview-0.1.2-darwin-arm64.tar.gz" && $2!="owntransit-preview-0.1.2-linux-amd64.tar.gz" && $2!="owntransit-preview-0.1.2-linux-arm64.tar.gz") ok=0
    previous=$2
  }
  END { exit ok ? 0 : 1 }
' "$stage/DEVELOPMENT-SHA256SUMS" || fail 'malformed signed development inventory'

top=owntransit-preview-$version-linux-$arch
archive=$top.tar.gz
expected=$(awk -v name="$archive" '$2==name {print $1}' "$stage/DEVELOPMENT-SHA256SUMS")
test "${#expected}" = 64 || fail 'selected platform missing from signed inventory'
fetch "$archive" 134217728
test "$(sha256sum "$stage/$archive" | awk '{print $1}')" = "$expected" || fail 'signed archive digest mismatch'

# Authentication precedes inspection and extraction. A flat exact inventory
# also rejects accidental traversal, extra members and links in a signed build.
tar -tzf "$stage/$archive" > "$stage/members"
printf '%s\n' "$top/" "$top/CAPSULE" "$top/LICENSE" "$top/NOTICE" "$top/SHA256SUMS" \
  "$top/install-linux.sh" "$top/owntransit" "$top/owntransit-connector" \
  "$top/owntransit-relay" "$top/owntransit-relay.oci.tar" | sort > "$stage/expected-members"
sort "$stage/members" > "$stage/sorted-members"
test "$(cat "$stage/sorted-members")" = "$(cat "$stage/expected-members")" || fail 'archive inventory is not exact'
tar -tvzf "$stage/$archive" | awk 'substr($0,1,1)!="-" && substr($0,1,1)!="d" {exit 1}' || fail 'archive contains a link or special member'
tar --extract --gzip --no-same-owner --no-same-permissions --file "$stage/$archive" --directory "$stage" || fail 'authenticated archive extraction failed'
chmod 0700 "$stage/$top"
chmod 0755 "$stage/$top/install-linux.sh" "$stage/$top/owntransit" "$stage/$top/owntransit-connector" "$stage/$top/owntransit-relay"
chmod 0644 "$stage/$top/CAPSULE" "$stage/$top/LICENSE" "$stage/$top/NOTICE" "$stage/$top/SHA256SUMS" "$stage/$top/owntransit-relay.oci.tar"
env -i PATH="$PATH" LC_ALL=C "$stage/$top/install-linux.sh" --bundle "$stage/$top" --role "$role"
if test "$role" = relay; then
  if test -n "$setup_url"; then
    env -i PATH="$PATH" LC_ALL=C /usr/local/bin/owntransit-relay-preview setup --url "$setup_url"
  elif ( : </dev/tty ) 2>/dev/null; then
    env -i PATH="$PATH" LC_ALL=C /usr/local/bin/owntransit-relay-preview setup </dev/tty
  fi
fi
}
main "$@"
