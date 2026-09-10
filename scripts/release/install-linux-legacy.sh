#!/bin/sh
main() {
caller_path=${PATH-}
set -eu

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
LC_ALL=C
export LC_ALL
IFS=$(printf ' \t\n.')
IFS=${IFS%.}
unset CDPATH ENV BASH_ENV GZIP TAR_OPTIONS POSIXLY_CORRECT
umask 077

program=owntransit-install-linux
release_version=0.1.0
release_base=https://github.com/sentrybottale/OwnTransit/releases/download/v0.1.0
stage=

fail() {
  printf '%s: %s\n' "$program" "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
usage:
  sudo ./install-linux.sh connector
  sudo ./install-linux.sh client [EXISTING_LOCAL_USER]
  sudo ./install-linux.sh relay
  sudo ./install-linux.sh provisioner

Installs one local OwnTransit 0.1.0 role on Linux amd64 or arm64. A fresh
connector or relay remains disabled and stopped; an existing service role keeps
its service state. When client user is omitted, the script uses the non-root
account recorded by sudo.
EOF
}

safe_stage_path() {
  candidate=$1
  prefix=/var/lib/owntransit-install-v0.1.0.
  case "$candidate" in
    "$prefix"*) ;;
    *) return 1 ;;
  esac
  suffix=${candidate#"$prefix"}
  case "$suffix" in
    ''|*[!A-Za-z0-9]*) return 1 ;;
  esac
  test "$(dirname "$candidate")" = /var/lib
}

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if test -n "$stage"; then
    if safe_stage_path "$stage" && test -d "$stage" && test ! -L "$stage" &&
      test "$(stat -c %u "$stage" 2>/dev/null || printf x)" = 0; then
      rm -rf -- "$stage" || status=1
    else
      printf '%s: refusing to remove unexpected staging path: %s\n' "$program" "$stage" >&2
      status=1
    fi
  fi
  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if test "$#" -eq 1; then
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
  esac
fi
test "$#" -ge 1 || {
  usage >&2
  exit 2
}
role=$1
shift

client_user=
client_user_inferred=no
case "$role" in
  connector|relay|provisioner)
    test "$#" -eq 0 || {
      usage >&2
      exit 2
    }
    ;;
  client)
    test "$#" -le 1 || {
      usage >&2
      exit 2
    }
    if test "$#" -eq 1; then
      client_user=$1
    else
      client_user=${SUDO_USER-}
      client_user_inferred=yes
    fi
    case "$client_user" in
      ''|root|-*|*[!A-Za-z0-9_-]*)
        fail "client needs an explicit existing non-root local user"
        ;;
    esac
    test "${#client_user}" -le 32 || fail "client user name is too long"
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

test "$(id -u)" -eq 0 || fail "run this installer through sudo"
if test "$client_user_inferred" = yes; then
  sudo_uid=${SUDO_UID-}
  case "$sudo_uid" in
    ''|*[!0-9]*) fail "sudo did not provide a valid non-root caller identity; specify the client user" ;;
  esac
  test "${#sudo_uid}" -le 10 && test "$sudo_uid" -gt 0 ||
    fail "sudo did not provide a valid non-root caller identity; specify the client user"
  resolved_sudo_uid=$(id -u "$client_user" 2>/dev/null) ||
    fail "sudo caller user does not resolve locally; specify the client user"
  test "$resolved_sudo_uid" = "$sudo_uid" ||
    fail "sudo caller user and UID do not match; specify the client user"
  resolved_sudo_user=$(id -un "$sudo_uid" 2>/dev/null) ||
    fail "sudo caller UID does not resolve locally; specify the client user"
  test "$resolved_sudo_user" = "$client_user" ||
    fail "sudo caller UID is not canonical for the client user; specify the client user"
fi
test "$(uname -s)" = Linux || fail "Linux is required"
case "$(uname -m)" in
  x86_64|amd64) platform_arch=amd64 ;;
  aarch64|arm64) platform_arch=arm64 ;;
  *) fail "supported architectures are Linux amd64/x86_64 and arm64/aarch64" ;;
esac

for command_name in awk basename cat chmod chown cmp dirname env find flock getent grep groupadd id install ln ls mktemp mv readlink rm rmdir sed sha256sum stat tar tr uname usermod wc; do
  command -v "$command_name" >/dev/null 2>&1 ||
    fail "required host utility is unavailable; install it before retrying: $command_name"
done
if test "$role" = connector || test "$role" = relay; then
  test -d /run/systemd/system || fail "the $role requires Linux running systemd"
  command -v systemctl >/dev/null 2>&1 ||
    fail "the $role requires systemctl from the existing systemd installation"
  command -v useradd >/dev/null 2>&1 ||
    fail "the $role requires useradd from the existing account-management tools"
fi
if test "$role" = client; then
  client_uid=$(id -u "$client_user" 2>/dev/null) || fail "client user does not exist: $client_user"
  test "$client_uid" -gt 0 || fail "client user must be non-root"
fi
if test "$role" = provisioner; then
  test -f /proc/sys/fs/protected_hardlinks &&
    test "$(cat /proc/sys/fs/protected_hardlinks)" = 1 ||
    fail "the provisioner requires fs.protected_hardlinks=1"
fi
if test "$role" = connector || test "$role" = relay; then
  for pending_record in \
    "/var/lib/owntransit/package-supervisor/$role.intent" \
    "/var/lib/owntransit/package-supervisor/$role.restart"; do
    if test -e "$pending_record" || test -L "$pending_record"; then
      if test "$role" = connector; then
        fail "pending connector package recovery exists; do not delete its supervisor record; finish authenticated package recovery, then retry"
      fi
      fail "pending relay package recovery exists; do not delete its supervisor record; finish authenticated package recovery, then retry"
    fi
  done
fi

command -v curl >/dev/null 2>&1 || fail "curl is required; install it with the host package manager, then retry"
command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen is required; install the OpenSSH client tools manually, then retry"
test -s /etc/ssl/certs/ca-certificates.crt ||
  fail "the system CA certificate bundle is required; install ca-certificates manually, then retry"
install_podman=no
if test "$role" = relay; then
  standard_podman=
  if test -x /usr/bin/podman; then
    standard_podman=$(readlink -f -- /usr/bin/podman 2>/dev/null) ||
      fail "cannot resolve the required Podman path: /usr/bin/podman"
    case "$standard_podman" in /*) ;; *) fail "the required Podman path is not canonical" ;; esac
  fi
  validate_discovered_podman() {
    discovered_podman=$1
    canonical_podman=$(readlink -f -- "$discovered_podman" 2>/dev/null) ||
      fail "cannot resolve existing Podman path: $discovered_podman"
    if test -z "$standard_podman" || test "$canonical_podman" != "$standard_podman"; then
      fail "existing Podman uses an unsupported path: $discovered_podman; OwnTransit requires /usr/bin/podman"
    fi
  }
  caller_podman=$(PATH=$caller_path command -v podman 2>/dev/null || true)
  if test -n "$caller_podman"; then
    case "$caller_podman" in
      /*) ;;
      *) fail "existing Podman command is not an absolute path: $caller_podman" ;;
    esac
    test -x "$caller_podman" || fail "existing Podman command is not executable: $caller_podman"
    validate_discovered_podman "$caller_podman"
  fi
  for discovered_podman in \
    /bin/podman \
    /usr/local/bin/podman \
    /usr/local/sbin/podman \
    /snap/bin/podman; do
    test -x "$discovered_podman" || continue
    validate_discovered_podman "$discovered_podman"
  done
  if test -z "$standard_podman"; then
    install_podman=yes
  fi
fi
if test "$install_podman" = yes; then
  test -f /etc/debian_version && test -x /usr/bin/apt-get ||
    fail "automatic Podman installation requires Debian or Ubuntu with /usr/bin/apt-get; install Podman at /usr/bin/podman, then retry"
fi

require_protected_ancestor() {
  protected_directory=$1
  test -d "$protected_directory" && test ! -L "$protected_directory" ||
    fail "unsafe staging ancestor: $protected_directory"
  test "$(stat -c %u "$protected_directory")" = 0 ||
    fail "staging ancestor is not root-owned: $protected_directory"
  protected_mode=$(stat -c %a "$protected_directory")
  case "$protected_mode" in
    [0-7][0-7][0-7]) ;;
    *) fail "staging ancestor has non-canonical mode: $protected_directory" ;;
  esac
  test $((0$protected_mode & 022)) -eq 0 ||
    fail "staging ancestor is group/world writable: $protected_directory"
}

require_protected_ancestor /
require_protected_ancestor /var
require_protected_ancestor /var/lib

stage=$(mktemp -d /var/lib/owntransit-install-v0.1.0.XXXXXXXX) ||
  fail "cannot create protected staging directory"
safe_stage_path "$stage" || fail "mktemp returned an unsafe staging path"
test "$(stat -c %u "$stage")" = 0 && test "$(stat -c %a "$stage")" = 700 ||
  fail "staging directory is not private and root-owned"

assets=$stage/assets
trust=$stage/trust
install -d -o root -g root -m 0700 "$assets" "$trust"

printf 'Downloading OwnTransit %s for Linux %s...\n' "$release_version" "$platform_arch"

valid_digest() {
  digest=$1
  case "$digest" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  test "${#digest}" -eq 64
}

fetch_pinned() {
  destination_directory=$1
  name=$2
  expected_size=$3
  expected_sha256=$4

  case "$name" in
    ''|.*|*/*|*[!A-Za-z0-9._+-]*) fail "unsafe release asset name" ;;
  esac
  case "$expected_size" in
    ''|*[!0-9]*) fail "invalid pinned size for $name" ;;
  esac
  test "$expected_size" -gt 0 || fail "invalid pinned size for $name"
  valid_digest "$expected_sha256" || fail "invalid pinned digest for $name"

  destination=$destination_directory/$name
  partial=$destination_directory/.$name.part
  test ! -e "$destination" && test ! -L "$destination" &&
    test ! -e "$partial" && test ! -L "$partial" || fail "duplicate download target: $name"

  # curl before 8.4.0 does not enforce --max-filesize when the response size is
  # unknown. Keep a kernel file-size ceiling as the independent backstop.
  (
    ulimit -f 131072 || exit 1
    env -i PATH="$PATH" LC_ALL=C \
      curl --disable --fail --show-error --silent --location \
      --proto '=https' --proto-redir '=https' \
      --connect-timeout 20 --max-time 900 --max-filesize "$expected_size" \
      --output "$partial" "$release_base/$name"
  ) || fail "download failed: $name"

  test -f "$partial" && test ! -L "$partial" || fail "download is not a regular file: $name"
  test "$(stat -c %u "$partial")" = 0 && test "$(stat -c %h "$partial")" = 1 ||
    fail "download has unsafe ownership or links: $name"
  test "$(wc -c < "$partial" | tr -d '[:space:]')" = "$expected_size" ||
    fail "download size mismatch: $name"
  actual_sha256=$(sha256sum "$partial" | awk '{print $1}')
  test "$actual_sha256" = "$expected_sha256" || fail "download checksum mismatch: $name"
  chmod 0600 "$partial"
  mv -- "$partial" "$destination"
}

# The immutable v0.1.0 release inventory. Every byte is checked before use.
fetch_pinned "$assets" NATIVE-SHA256SUMS.sig 318 5989c3eadcf6ca9b8abb49ae62a121d63283a71113cc83211acdbaf630dcd077
fetch_pinned "$assets" RELEASE-CANDIDATE.json 352 a31bc6b6b7d6714d82a5de217acc2aa690870facd50c7335121c029da65cdd64
fetch_pinned "$assets" RELEASE-MANIFEST.json 9429 fa3a9a20983ca88f20becffa4bfd680d291a55e2cebde331e690e0ab92eeb55e
fetch_pinned "$assets" RELEASE-MANIFEST.sig 305 39d913ffb32f51bc20748b6885be88440cae681d3768ddc8b1813334dd354a41
fetch_pinned "$assets" RELEASE-POLICY.json 266 153bf3a320241ac497bf162afe0c8a8d04eb520adca9307dd77d394436835ebc
fetch_pinned "$assets" RELEASE-POLICY.sig 310 c46dcb9f43c663c6e7d45af4527cdc4cd4d655ad6ee7c72ab253a36df4333822
fetch_pinned "$assets" SHA256SUMS 797 906e634897637256cf504e96919e155e0a5d834d0485b43803efc38fc912930e
fetch_pinned "$assets" owntransit-0.1.0-native.tar.gz 35719170 d5f9ec458fc00c6a47a0eb7c46e2a0a5bade7e2ab95c5ad6e34c5fc256c1b2bc
fetch_pinned "$assets" owntransit-0.1.0-source.tar.gz 705230 9075c4fb95e4776c519197b47602e9a2a55bdb5203d8f637e5f5e1f036423b5c
fetch_pinned "$assets" owntransit.rb 5951 0f5745d7e1a3e6cf0501233c0109c1809ddc689a559b1c987e709e807a66c1d1

fetch_pinned "$trust" SHA256SUMS.sig 318 06114fed81b98dfa68d71dae30d215ed7e7035bc30fb215e45fc9269ea8796ad
fetch_pinned "$trust" TRUST-STATEMENT.txt 629 e5049fc6f3c6be061992d74f83b84506950a7abb1d3f0117f7b452ed47b31a4b
fetch_pinned "$trust" TRUST-STATEMENT.txt.sig 314 5e17c496fc1fedbc59a906d24da048c72fab5def198a0a89f5b2b8f266cd9c70
fetch_pinned "$trust" allowed_signers 199 f64f68ea2ccea65d933def37ab8b8f54ef903065d5bc9d80a786d8adc9c24b1e
fetch_pinned "$trust" distribution-public.key 108 55d97d90f4b81628aa534ba28960b63685ea5d1d4eeef489ffb28de632dc0a9e
fetch_pinned "$trust" policy-public.pem 113 c08d51d3ac460a07442a555cd8c1a83d170594c12bed22ad5bba8009e2e8bda0
fetch_pinned "$trust" release-public.pem 113 4c0a7e562a42e59d291b4a9780263c76ff3306135e79255fde40907523070878

test "$(find "$assets" -type f -print | wc -l | tr -d '[:space:]')" = 10 ||
  fail "downloaded asset inventory is not exact"
test "$(find "$trust" -type f -print | wc -l | tr -d '[:space:]')" = 7 ||
  fail "downloaded trust inventory is not exact"

native_archive=$assets/owntransit-0.1.0-native.tar.gz
test "$(sha256sum "$native_archive" | awk '{print $1}')" = d5f9ec458fc00c6a47a0eb7c46e2a0a5bade7e2ab95c5ad6e34c5fc256c1b2bc ||
  fail "native archive changed before extraction"

tar --extract --gzip --no-same-owner --file "$native_archive" --directory "$stage" ||
  fail "cannot extract authenticated native archive"
bundle=$stage/owntransit-0.1.0-native
entrypoint=$bundle/packaging/scripts/install.sh
test -d "$bundle" && test ! -L "$bundle" && test -x "$entrypoint" ||
  fail "authenticated native bundle has no installer"

if test "$install_podman" = yes; then
  printf '%s\n' 'Installing required package: podman'
  env -i PATH="$PATH" LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
    /usr/bin/apt-get -qq update || fail "apt-get update failed while preparing Podman"
  env -i PATH="$PATH" LC_ALL=C DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l \
    /usr/bin/apt-get -y -qq --no-remove --no-install-recommends install podman ||
    fail "apt-get could not install required package: podman"
fi
if test "$role" = relay; then
  command -v podman >/dev/null 2>&1 && test "$(command -v podman)" = /usr/bin/podman &&
    test -x /usr/bin/podman || fail "Podman remains unavailable at /usr/bin/podman"
fi

printf 'Installing OwnTransit %s %s for Linux %s...\n' "$release_version" "$role" "$platform_arch"
set -- --bundle "$bundle" --assets "$assets" --trust "$trust" --role "$role"
if test "$role" = client; then
  set -- "$@" --client-user "$client_user"
fi
if ! env -i PATH="$PATH" LC_ALL=C "$entrypoint" "$@" > "$stage/install.log" 2>&1; then
  cat "$stage/install.log" >&2
  fail "installation failed; see the details above"
fi
if test "$role" = client; then
  printf 'OwnTransit client installed for %s.\n' "$client_user"
  printf 'Next: start a new login session (or run: sudo -iu %s).\n' "$client_user"
  printf '%s\n' 'Then run owntransit setup with the actual .otinvite file supplied by your administrator. Installation does not create an invitation.'
elif test "$role" = connector; then
  printf '%s\n' 'Connector package installed. Existing service state was preserved. If this is a fresh connector, enroll it before enabling the service.'
elif test "$role" = relay; then
  printf '%s\n' 'Relay package installed. Existing service state was preserved; a fresh relay remains disabled and loopback-only.'
  printf '%s\n' 'Enrollment and public HTTPS integration are separate: https://github.com/sentrybottale/OwnTransit/blob/main/INSTALL.md'
else
  printf '%s\n' 'Provisioner installed as /usr/local/bin/owntransit-provision. No service or endpoint credential was created.'
  printf '%s\n' 'Generate and keep route-authority keys on the trusted administrator machine, never on the public relay.'
fi
}

main "$@"
