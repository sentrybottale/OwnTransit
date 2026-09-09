#!/bin/sh
set -eu

fail() { printf 'development-install-test: %s\n' "$*" >&2; exit 1; }
test "$(id -u)" -eq 0 || fail 'requires root'
test "$(uname -s)" = Linux || fail 'requires Linux'
test -f /.dockerenv || fail 'refuses to mutate a non-container host'
/usr/bin/systemctl --owntransit-development-test || fail 'requires the disposable fake systemctl support command'

case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'unsupported test architecture' ;; esac
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
bundle=/root/owntransit-preview-0.6.0-linux-$arch
install -d -o root -g root -m 0700 "$bundle"
printf 'schema=owntransit.development-capsule.v1\nversion=0.6.0\nos=linux\narch=%s\n' "$arch" > "$bundle/CAPSULE"
printf '%s\n' development-license > "$bundle/LICENSE"
printf '%s\n' development-notice > "$bundle/NOTICE"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit-connector"
printf '%s\n' '#!/bin/sh' \
  'case "$1" in uninstall-managed|uninstall-all-managed)' \
  'test "$(readlink /proc/self/fd/9)" = /var/lib/owntransit-relay-manager/package.lock || exit 93' \
  'flock -n 9 || exit 94' \
  'printf "%s\n" "$@" > /tmp/owntransit-relay-package-helper.args' \
  ';; esac' 'exit 0' > "$bundle/owntransit-relay"
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
grep -Fqx 'NEXT — on THIS client computer, as your ordinary user without sudo:' "$client_output"
grep -Fqx '  /usr/local/bin/owntransit pair setup' "$client_output"
grep -Fqx 'Then answer its prompts: your relay URL and the private receiver code (otpair2.).' "$client_output"
if grep -Eq 'otrelay1\.|otpair1\.' "$client_output"; then fail 'installer requested legacy two-code setup'; fi
test -x /opt/owntransit-preview/0.6.0/client/owntransit
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
test ! -e /var/lib/owntransit-pair && test ! -e /var/lib/owntransit || fail 'client install created runtime or legacy state'

install -d -m 0755 /run/systemd/system
: > /tmp/owntransit-development-systemctl.calls
"$bundle/install-linux.sh" --bundle "$bundle" --role connector > /tmp/owntransit-preview-connector.out
grep -Fqx 'NEXT — on THIS receiving SSH machine:' /tmp/owntransit-preview-connector.out
grep -Fqx '  sudo /usr/local/bin/owntransit-connector pair setup' /tmp/owntransit-preview-connector.out
test -x /opt/owntransit-preview/0.6.0/connector/owntransit-connector
test "$(readlink /usr/local/bin/owntransit-connector-preview)" = /opt/owntransit-preview/0.6.0/connector/owntransit-connector
test -f /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'ExecStart=/opt/owntransit-preview/0.6.0/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair' /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL' /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'AmbientCapabilities=CAP_SETUID' /etc/systemd/system/owntransit-connector-pair.service
grep -Fqx 'Type=notify' /etc/systemd/system/owntransit-connector-pair.service
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-reinstall.out
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload || fail 'exact reinstall repeated systemd mutation'

# Reproduce the exact old unit shape; the corrected package must upgrade it
# without accepting arbitrary local changes or removing confinement.
unit=/etc/systemd/system/owntransit-connector-pair.service
sed -e 's/0\.6\.0/0.1.2/g' -e 's/^Type=notify$/Type=simple/' \
  -e '/^NotifyAccess=main$/d' -e '/^TimeoutStartSec=30s$/d' \
  -e 's/^CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL$/CapabilityBoundingSet=CAP_SETUID CAP_SETGID/' \
  -e 's/^AmbientCapabilities=CAP_SETUID$/AmbientCapabilities=/' "$unit" > /tmp/old-preview-unit
install -m 0644 /tmp/old-preview-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-upgrade.out
grep -Fqx 'AmbientCapabilities=CAP_SETUID' "$unit"
grep -Fqx 'Type=notify' "$unit"
sed 's/0\.6\.0/0.1.3/g' "$unit" > /tmp/preview-013-unit
install -m 0644 /tmp/preview-013-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-013-upgrade.out
grep -Fqx 'ExecStart=/opt/owntransit-preview/0.6.0/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair' "$unit"
sed 's/0\.6\.0/0.1.6/g' "$unit" > /tmp/preview-016-unit
install -m 0644 /tmp/preview-016-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-016-upgrade.out
sed 's/0\.6\.0/0.1.7/g' "$unit" > /tmp/preview-017-unit
install -m 0644 /tmp/preview-017-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-017-upgrade.out
sed 's/0\.6\.0/0.2.0/g' "$unit" > /tmp/preview-020-unit
install -m 0644 /tmp/preview-020-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-020-upgrade.out
sed 's/0\.6\.0/0.3.0/g' "$unit" > /tmp/preview-030-unit
install -m 0644 /tmp/preview-030-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-030-upgrade.out
sed 's/0\.6\.0/0.4.0/g' "$unit" > /tmp/preview-040-unit
install -m 0644 /tmp/preview-040-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-040-upgrade.out
sed 's/0\.6\.0/0.5.0/g' "$unit" > /tmp/preview-050-unit
install -m 0644 /tmp/preview-050-unit "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/connector-050-upgrade.out
grep -Fqx 'ExecStart=/opt/owntransit-preview/0.6.0/connector/owntransit-connector pair serve --state /var/lib/owntransit-pair' "$unit"
printf '%s\n' 'Environment=UNMANAGED_CHANGE=yes' >> "$unit"
if "$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/edited-unit.out 2>/tmp/edited-unit.err; then
  fail 'locally edited unit was silently overwritten'
fi

printf '%s\n' unmanaged > /usr/local/bin/owntransit-relay-preview
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/unmanaged.out 2>/tmp/unmanaged.err; then
  fail 'unmanaged relay alias was overwritten'
fi
test "$(cat /usr/local/bin/owntransit-relay-preview)" = unmanaged
test ! -e /opt/owntransit-preview/0.6.0/relay || fail 'alias conflict partially installed relay role'
rm -- /usr/local/bin/owntransit-relay-preview
relay_output=/tmp/owntransit-preview-relay.out
"$bundle/install-linux.sh" --bundle "$bundle" --role relay > "$relay_output"
grep -Fqx 'NEXT — on THIS VPS:' "$relay_output"
grep -Fqx '  sudo /usr/local/bin/owntransit-relay setup' "$relay_output"
if grep -Fq -- '--instance default' "$relay_output"; then fail 'unqualified relay install silently selected default'; fi
if grep -Fq 'podman run' "$relay_output"; then fail 'installer exposed manual container setup'; fi
test -x /opt/owntransit-preview/0.6.0/relay/owntransit-relay
test -f /opt/owntransit-preview/0.6.0/relay/owntransit-relay.oci.tar
test "$(readlink /usr/local/bin/owntransit-relay-preview)" = /opt/owntransit-preview/0.6.0/relay/owntransit-relay
"$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-reinstall.out
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha >/tmp/relay-alpha-install.out
grep -Fqx '  sudo /usr/local/bin/owntransit-relay setup --instance alpha' /tmp/relay-alpha-install.out
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance '../default' >/tmp/relay-invalid-name.out 2>&1; then fail 'relay installer accepted traversal'; fi
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha --instance bravo >/tmp/relay-duplicate-name.out 2>&1; then fail 'relay installer accepted ambiguous scope'; fi
if "$bundle/install-linux.sh" --bundle "$bundle" --role client --instance alpha >/tmp/client-relay-name.out 2>&1; then fail 'client installer accepted relay instance'; fi
( flock -s 8; "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-package-race.out 2>&1 && exit 1; exit 0 ) 8<>/var/lib/owntransit-relay-manager/package.lock || fail 'relay package ignored a shared management lock'
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha --action uninstall >/tmp/relay-alpha-uninstall.out
test "$(cat /tmp/owntransit-relay-package-helper.args)" = "$(printf 'uninstall-managed\n--instance\nalpha\n--package-lock-fd\n9')" || fail 'scoped removal lost instance or package lock handoff'
test -x /usr/local/bin/owntransit-relay-preview && test -f /opt/owntransit-preview/0.6.0/relay/owntransit-relay.oci.tar || fail 'scoped removal removed shared software'

# Upgrading a known managed preview alias preserves the old executable.
install -d -m 0755 /opt/owntransit-preview/0.1.1/client
printf '%s\n' '#!/bin/sh' 'exit 0' > /opt/owntransit-preview/0.1.1/client/owntransit
chmod 0755 /opt/owntransit-preview/0.1.1/client/owntransit
ln -sfn /opt/owntransit-preview/0.1.1/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
test -x /opt/owntransit-preview/0.1.1/client/owntransit
install -d -m 0755 /opt/owntransit-preview/0.1.3/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.1.3/client/owntransit
ln -sfn /opt/owntransit-preview/0.1.3/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-013-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit

install -d -m 0755 /opt/owntransit-preview/0.1.6/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.1.6/client/owntransit
ln -sfn /opt/owntransit-preview/0.1.6/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-016-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
install -d -m 0755 /opt/owntransit-preview/0.1.7/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.1.7/client/owntransit
ln -sfn /opt/owntransit-preview/0.1.7/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-017-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
install -d -m 0755 /opt/owntransit-preview/0.3.0/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.3.0/client/owntransit
ln -sfn /opt/owntransit-preview/0.3.0/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-030-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
install -d -m 0755 /opt/owntransit-preview/0.4.0/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.4.0/client/owntransit
ln -sfn /opt/owntransit-preview/0.4.0/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-040-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
test -x /opt/owntransit-preview/0.4.0/client/owntransit
install -d -m 0755 /opt/owntransit-preview/0.5.0/client
install -m 0755 /opt/owntransit-preview/0.1.1/client/owntransit /opt/owntransit-preview/0.5.0/client/owntransit
ln -sfn /opt/owntransit-preview/0.5.0/client/owntransit /usr/local/bin/owntransit-preview
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-050-upgrade.out
test "$(readlink /usr/local/bin/owntransit-preview)" = /opt/owntransit-preview/0.6.0/client/owntransit
test -x /opt/owntransit-preview/0.5.0/client/owntransit

# A non-purging uninstall removes only verified local software and services.
install -d -m 0700 /var/lib/owntransit-pair
printf '%s\n' retained-state > /var/lib/owntransit-pair/uninstall-fixture
if "$bundle/install-linux.sh" --bundle "$bundle" --role connector --action uninstall >/tmp/edited-uninstall.out 2>&1; then
  fail 'modified connector unit was removed'
fi
install -m 0644 /opt/owntransit-preview/0.6.0/connector/service.template "$unit"
for tunnel in alpha bravo; do
  install -d -m 0700 "/var/lib/owntransit-tunnels/$tunnel"
  printf '%s\n' "retained-$tunnel" > "/var/lib/owntransit-tunnels/$tunnel/pairing-fixture"
  sed "s@/var/lib/owntransit-pair@/var/lib/owntransit-tunnels/$tunnel@g" "$unit" > "/etc/systemd/system/owntransit-connector-pair@$tunnel.service"
  chmod 0644 "/etc/systemd/system/owntransit-connector-pair@$tunnel.service"
done
"$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/named-reinstall.out
grep -Fq 'owntransit-connector-pair@alpha.service' /tmp/named-reinstall.out
printf '%s\n' '# modified instance' >> /etc/systemd/system/owntransit-connector-pair@alpha.service
if "$bundle/install-linux.sh" --bundle "$bundle" --role connector --action uninstall >/tmp/named-uninstall.out 2>&1; then fail 'modified named unit uninstalled'; fi
test -e "$unit" && test -e /etc/systemd/system/owntransit-connector-pair@bravo.service
sed 's@/var/lib/owntransit-pair@/var/lib/owntransit-tunnels/alpha@g' "$unit" > /etc/systemd/system/owntransit-connector-pair@alpha.service

# Package changes may not race a live setup holding the shared maintenance lock.
( flock -s 8; "$bundle/install-linux.sh" --bundle "$bundle" --role connector >/tmp/maintenance-race.out 2>&1 && exit 1; exit 0 ) 8<>/var/lib/owntransit-connector-manager/package.lock || fail 'installer ignored shared setup lock'
"$bundle/install-linux.sh" --bundle "$bundle" --role connector --action uninstall
test ! -e "$unit" && test ! -e /usr/local/bin/owntransit-connector-preview
test "$(cat /var/lib/owntransit-pair/uninstall-fixture)" = retained-state
for tunnel in alpha bravo; do
  test ! -e "/etc/systemd/system/owntransit-connector-pair@$tunnel.service"
  test "$(cat "/var/lib/owntransit-tunnels/$tunnel/pairing-fixture")" = "retained-$tunnel"
done
"$bundle/install-linux.sh" --bundle "$bundle" --role connector
test -e "$unit"
rm -- /usr/local/bin/owntransit
printf '%s\n' unmanaged-command > /usr/local/bin/owntransit
"$bundle/install-linux.sh" --bundle "$bundle" --role client
test "$(cat /usr/local/bin/owntransit)" = unmanaged-command
"$bundle/install-linux.sh" --bundle "$bundle" --role client --action uninstall
test "$(cat /usr/local/bin/owntransit)" = unmanaged-command
test ! -e /opt/owntransit-preview/0.6.0/client
"$bundle/install-linux.sh" --bundle "$bundle" --role client --action uninstall
"$bundle/install-linux.sh" --bundle "$bundle" --role client
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --action uninstall
test "$(cat /tmp/owntransit-relay-package-helper.args)" = "$(printf 'uninstall-all-managed\n--package-lock-fd\n9')" || fail 'whole-role removal did not cover all instances under the package lock'
test ! -e /usr/local/bin/owntransit-relay-preview

if grep -Eq '/etc/(ssh|nginx)|iptables|nft[[:space:]]|ufw|firewall-cmd|systemctl[[:space:]]+(enable|start)' "$bundle/install-linux.sh"; then
  fail 'installer contains forbidden host integration'
fi
printf '%s\n' 'development Linux installer tests passed'
