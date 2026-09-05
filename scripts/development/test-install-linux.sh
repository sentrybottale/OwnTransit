#!/bin/sh
set -eu

fail() { printf 'development-install-test: %s\n' "$*" >&2; exit 1; }
test "$(id -u)" -eq 0 || fail 'requires root'
test "$(uname -s)" = Linux || fail 'requires Linux'
test -f /.dockerenv || fail 'refuses to mutate a non-container host'
/usr/bin/systemctl --owntransit-development-test || fail 'requires the disposable fake systemctl support command'

case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'unsupported test architecture' ;; esac
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
bundle=/root/owntransit-preview-0.1.2-linux-$arch
install -d -o root -g root -m 0700 "$bundle"
printf 'schema=owntransit.development-capsule.v1\nversion=0.1.2\nos=linux\narch=%s\n' "$arch" > "$bundle/CAPSULE"
printf '%s\n' development-license > "$bundle/LICENSE"
printf '%s\n' development-notice > "$bundle/NOTICE"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit-connector"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit-relay"
printf '%s\n' development-oci > "$bundle/owntransit-relay.oci.tar"
install -o root -g root -m 0755 "$project_root/scripts/development/install-linux.sh" "$bundle/install-linux.sh"
chmod 0644 "$bundle/CAPSULE" "$bundle/LICENSE" "$bundle/NOTICE" "$bundle/owntransit-relay.oci.tar"
chmod 0755 "$bundle/owntransit" "$bundle/owntransit-connector" "$bundle/owntransit-relay"
chown root:root "$bundle"/*
(
  cd "$bundle"
  sha256sum CAPSULE LICENSE NOTICE install-linux.sh owntransit owntransit-connector owntransit-relay owntransit-relay.oci.tar > SHA256SUMS
)
chmod 0644 "$bundle/SHA256SUMS"
chown root:root "$bundle/SHA256SUMS"

corrupt=/root/owntransit-preview-corrupt-$arch
cp -a "$bundle" "$corrupt"
printf '%s\n' tampered >> "$corrupt/NOTICE"
if "$corrupt/install-linux.sh" --bundle "$corrupt" --role client >/tmp/corrupt.out 2>/tmp/corrupt.err; then
  fail 'tampered bundle installed'
fi
test ! -e /opt/owntransit-preview && test ! -e /usr/local/bin/owntransit-preview || fail 'tampered bundle mutated installation paths'

client_output=/tmp/owntransit-preview-client.out
"$bundle/install-linux.sh" --bundle "$bundle" --role client > "$client_output"
grep -Fqx 'Next: owntransit-preview pair setup' "$client_output"
test -x /opt/owntransit-preview/0.1.2/client/owntransit
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.1.2/client/owntransit
test ! -e /var/lib/owntransit-pair && test ! -e /var/lib/owntransit || fail 'client install created runtime or legacy state'

install -d -m 0755 /run/systemd/system
: > /tmp/owntransit-development-systemctl.calls
"$bundle/install-linux.sh" --bundle "$bundle" --role connector
test -x /opt/owntransit-preview/0.1.2/connector/owntransit-connector
test "$(readlink /usr/local/bin/owntransit-connector-preview)" = /opt/owntransit-preview/0.1.2/connector/owntransit-connector
test -f /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'ExecStart=/opt/owntransit-preview/0.1.2/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair' /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' /etc/systemd/system/owntransit-connector-pair.service
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-reinstall.out
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload || fail 'exact reinstall repeated systemd mutation'

printf '%s\n' unmanaged > /usr/local/bin/owntransit-relay-preview
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/unmanaged.out 2>/tmp/unmanaged.err; then
  fail 'unmanaged relay alias was overwritten'
fi
test "$(cat /usr/local/bin/owntransit-relay-preview)" = unmanaged
test ! -e /opt/owntransit-preview/0.1.2/relay || fail 'alias conflict partially installed relay role'
rm -- /usr/local/bin/owntransit-relay-preview
relay_output=/tmp/owntransit-preview-relay.out
"$bundle/install-linux.sh" --bundle "$bundle" --role relay > "$relay_output"
grep -Fqx 'Next: sudo owntransit-relay-preview setup' "$relay_output"
if grep -Fq 'podman run' "$relay_output"; then fail 'installer exposed manual container setup'; fi
test -x /opt/owntransit-preview/0.1.2/relay/owntransit-relay
test -f /opt/owntransit-preview/0.1.2/relay/owntransit-relay.oci.tar
test "$(readlink /usr/local/bin/owntransit-relay-preview)" = /opt/owntransit-preview/0.1.2/relay/owntransit-relay
"$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-reinstall.out

# Upgrading a known managed preview alias preserves the old executable.
install -d -m 0755 /opt/owntransit-preview/0.1.1/client
printf '%s\n' '#!/bin/sh' 'exit 0' > /opt/owntransit-preview/0.1.1/client/owntransit
chmod 0755 /opt/owntransit-preview/0.1.1/client/owntransit
ln -sfn /opt/owntransit-preview/0.1.1/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.1.2/client/owntransit
test -x /opt/owntransit-preview/0.1.1/client/owntransit

if grep -Eq '/etc/(ssh|nginx)|iptables|nft[[:space:]]|ufw|firewall-cmd|systemctl[[:space:]]+(enable|start)' "$bundle/install-linux.sh"; then
  fail 'installer contains forbidden host integration'
fi
printf '%s\n' 'development Linux installer tests passed'
