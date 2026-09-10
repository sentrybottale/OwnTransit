#!/bin/sh
set -eu

fail() { printf 'development-install-test: %s\n' "$*" >&2; exit 1; }
test "$(id -u)" -eq 0 || fail 'requires root'
test "$(uname -s)" = Linux || fail 'requires Linux'
test -f /.dockerenv || fail 'refuses to mutate a non-container host'
/usr/bin/systemctl --owntransit-development-test || fail 'requires the disposable fake systemctl support command'

case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail 'unsupported test architecture' ;; esac
project_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
bundle=/root/owntransit-0.7.0-linux-$arch
install -d -o root -g root -m 0700 "$bundle"
printf 'schema=owntransit.development-capsule.v1\nversion=0.7.0\nos=linux\narch=%s\n' "$arch" > "$bundle/CAPSULE"
printf '%s\n' development-license > "$bundle/LICENSE"
printf '%s\n' development-notice > "$bundle/NOTICE"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit-client"
printf '%s\n' '#!/bin/sh' 'exit 0' > "$bundle/owntransit-target"
printf '%s\n' '#!/bin/sh' \
  'case "$1" in uninstall-managed|uninstall-all-managed|migrate-package-hooks)' \
  'test "$(readlink /proc/self/fd/9)" = /var/lib/owntransit-relay-manager/package.lock || exit 93' \
  'flock -n 9 || exit 94' \
  'if test "$1" = migrate-package-hooks; then' \
  '  test ! -e /tmp/owntransit-relay-refuse-hooks || exit 96' \
  '  if test -e /tmp/owntransit-relay-require-old-helper; then test -L /usr/local/bin/owntransit-relay-preview || exit 95; fi' \
  '  printf "%s\n" "$@" > /tmp/owntransit-relay-hook-helper.args' \
  'else printf "%s\n" "$@" > /tmp/owntransit-relay-package-helper.args; fi' \
  ';; esac' 'exit 0' > "$bundle/owntransit-relay"
printf '%s\n' development-oci > "$bundle/owntransit-relay.oci.tar"
install -o root -g root -m 0755 "$project_root/scripts/development/install-linux.sh" "$bundle/install-linux.sh"
chmod 0644 "$bundle/CAPSULE" "$bundle/LICENSE" "$bundle/NOTICE" "$bundle/owntransit-relay.oci.tar"
chmod 0755 "$bundle/owntransit-client" "$bundle/owntransit-target" "$bundle/owntransit-relay"
chown root:root "$bundle"/*
(
  cd "$bundle"
  sha256sum CAPSULE LICENSE NOTICE install-linux.sh owntransit-client owntransit-relay owntransit-relay.oci.tar owntransit-target > SHA256SUMS
)
chmod 0644 "$bundle/SHA256SUMS"
chown root:root "$bundle/SHA256SUMS"

corrupt=/root/owntransit-corrupt-$arch
cp -a "$bundle" "$corrupt"
printf '%s\n' tampered >> "$corrupt/NOTICE"
if "$corrupt/install-linux.sh" --bundle "$corrupt" --role client >/tmp/corrupt.out 2>/tmp/corrupt.err; then
  fail 'tampered bundle installed'
fi
test ! -e /opt/owntransit && test ! -e /usr/local/bin/owntransit-client || fail 'tampered bundle mutated installation paths'

client_output=/tmp/owntransit-client.out
"$bundle/install-linux.sh" --bundle "$bundle" --role client > "$client_output"
grep -Fqx 'NEXT — on THIS Client computer, without sudo:' "$client_output"
grep -Fqx '  /usr/local/bin/owntransit-client setup' "$client_output"
grep -Fqx 'Choose New tunnel or Continue tunnel from the menu.' "$client_output"
if grep -Eq 'otrelay1\.|otpair1\.|otpair2\.|setup --tunnel|--replace' "$client_output"; then fail 'installer bypassed the menu handoff'; fi
test -x /opt/owntransit/0.7.0/client/owntransit-client
test "$(readlink /usr/local/bin/owntransit-client)" = /opt/owntransit/0.7.0/client/owntransit-client
test ! -e /var/lib/owntransit-pair && test ! -e /var/lib/owntransit || fail 'client install created runtime or legacy state'

install -d -m 0755 /run/systemd/system
: > /tmp/owntransit-development-systemctl.calls
"$bundle/install-linux.sh" --bundle "$bundle" --role target > /tmp/owntransit-target.out
grep -Fqx 'NEXT — on THIS Target machine:' /tmp/owntransit-target.out
grep -Fqx '  sudo /usr/local/bin/owntransit-target setup' /tmp/owntransit-target.out
test -x /opt/owntransit/0.7.0/target/owntransit-target
test "$(readlink /usr/local/bin/owntransit-target)" = /opt/owntransit/0.7.0/target/owntransit-target
test -f /etc/systemd/system/owntransit-target.service
grep -Fqx 'ExecStart=/opt/owntransit/0.7.0/target/owntransit-target serve --state /var/lib/owntransit-pair' /etc/systemd/system/owntransit-target.service
grep -Fqx 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_KILL' /etc/systemd/system/owntransit-target.service
grep -Fqx 'AmbientCapabilities=CAP_SETUID' /etc/systemd/system/owntransit-target.service
grep -Fqx 'Type=notify' /etc/systemd/system/owntransit-target.service
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload
"$bundle/install-linux.sh" --bundle "$bundle" --role target >/tmp/target-reinstall.out
test "$(cat /tmp/owntransit-development-systemctl.calls)" = daemon-reload || fail 'exact reinstall repeated systemd mutation'

# Latest managed target service can retire its old name without changing state.
unit=/etc/systemd/system/owntransit-target.service
legacy_unit=/etc/systemd/system/owntransit-connector-pair.service
sed -e 's/0\.7\.0/0.6.1/g' -e 's@/opt/owntransit/@/opt/owntransit-preview/@g' \
  -e 's@/target/owntransit-target serve@/connector/owntransit-connector pair serve@g' \
  -e 's@/target$@/connector@' -e 's/ Target$/ preview receiver pairing broker/' "$unit" > "$legacy_unit"
chmod 0644 "$legacy_unit"
rm -- "$unit"
"$bundle/install-linux.sh" --bundle "$bundle" --role target >/tmp/target-upgrade.out
test ! -e "$legacy_unit"
grep -Fqx 'ExecStart=/opt/owntransit/0.7.0/target/owntransit-target serve --state /var/lib/owntransit-pair' "$unit"
printf '%s\n' 'Environment=UNMANAGED_CHANGE=yes' >> "$unit"
if "$bundle/install-linux.sh" --bundle "$bundle" --role target >/tmp/edited-unit.out 2>/tmp/edited-unit.err; then
  fail 'locally edited unit was silently overwritten'
fi

printf '%s\n' unmanaged > /usr/local/bin/owntransit-relay
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/unmanaged.out 2>/tmp/unmanaged.err; then
  fail 'unmanaged relay alias was overwritten'
fi
test "$(cat /usr/local/bin/owntransit-relay)" = unmanaged
test ! -e /opt/owntransit/0.7.0/relay || fail 'alias conflict partially installed relay role'
rm -- /usr/local/bin/owntransit-relay
relay_output=/tmp/owntransit-relay.out
"$bundle/install-linux.sh" --bundle "$bundle" --role relay > "$relay_output"
grep -Fqx 'NEXT — on THIS VPS:' "$relay_output"
grep -Fqx '  sudo /usr/local/bin/owntransit-relay setup' "$relay_output"
if grep -Fq -- '--instance default' "$relay_output"; then fail 'unqualified relay install silently selected default'; fi
if grep -Fq 'podman run' "$relay_output"; then fail 'installer exposed manual container setup'; fi
test -x /opt/owntransit/0.7.0/relay/owntransit-relay
test -f /opt/owntransit/0.7.0/relay/owntransit-relay.oci.tar
test "$(readlink /usr/local/bin/owntransit-relay)" = /opt/owntransit/0.7.0/relay/owntransit-relay
test "$(cat /tmp/owntransit-relay-hook-helper.args)" = "$(printf 'migrate-package-hooks\n--package-lock-fd\n9')" || fail 'relay hook migration lost the protected package-lock handoff'
# No old alias is retired before the real ownership validator has completed.
install -d -m 0755 /opt/owntransit-preview/0.6.1/relay
install -m 0755 "$bundle/owntransit-relay" /opt/owntransit-preview/0.6.1/relay/owntransit-relay
ln -s /opt/owntransit-preview/0.6.1/relay/owntransit-relay /usr/local/bin/owntransit-relay-preview
touch /tmp/owntransit-relay-refuse-hooks /tmp/owntransit-relay-require-old-helper
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-refused-hooks.out 2>&1; then fail 'hook migration failure was ignored'; fi
test -L /usr/local/bin/owntransit-relay-preview || fail 'failed hook migration retired a needed alias'
rm -- /tmp/owntransit-relay-refuse-hooks
"$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-migrated-hooks.out
test ! -L /usr/local/bin/owntransit-relay-preview || fail 'successful hook migration retained the old public alias'
rm -- /tmp/owntransit-relay-require-old-helper
"$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-reinstall.out
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha >/tmp/relay-alpha-install.out
grep -Fqx '  sudo /usr/local/bin/owntransit-relay setup --instance alpha' /tmp/relay-alpha-install.out
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance '../default' >/tmp/relay-invalid-name.out 2>&1; then fail 'relay installer accepted traversal'; fi
if "$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha --instance bravo >/tmp/relay-duplicate-name.out 2>&1; then fail 'relay installer accepted ambiguous scope'; fi
if "$bundle/install-linux.sh" --bundle "$bundle" --role client --instance alpha >/tmp/client-relay-name.out 2>&1; then fail 'client installer accepted relay instance'; fi
( flock -s 8; "$bundle/install-linux.sh" --bundle "$bundle" --role relay >/tmp/relay-package-race.out 2>&1 && exit 1; exit 0 ) 8<>/var/lib/owntransit-relay-manager/package.lock || fail 'relay package ignored a shared management lock'
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --instance alpha --action uninstall >/tmp/relay-alpha-uninstall.out
test "$(cat /tmp/owntransit-relay-package-helper.args)" = "$(printf 'uninstall-managed\n--instance\nalpha\n--package-lock-fd\n9')" || fail 'scoped removal lost instance or package lock handoff'
test -x /usr/local/bin/owntransit-relay && test -f /opt/owntransit/0.7.0/relay/owntransit-relay.oci.tar || fail 'scoped removal removed shared software'

# Exact prior aliases are retired; previous software remains immutable.
install -d -m 0755 /opt/owntransit-preview/0.6.1/client
printf '%s\n' '#!/bin/sh' 'exit 0' > /opt/owntransit-preview/0.6.1/client/owntransit
chmod 0755 /opt/owntransit-preview/0.6.1/client/owntransit
ln -s /opt/owntransit-preview/0.6.1/client/owntransit /usr/local/bin/owntransit-preview
ln -s /opt/owntransit-preview/0.6.1/client/owntransit /usr/local/bin/owntransit
"$bundle/install-linux.sh" --bundle "$bundle" --role client >/tmp/client-upgrade.out
test ! -e /usr/local/bin/owntransit-preview && test ! -L /usr/local/bin/owntransit-preview
test ! -e /usr/local/bin/owntransit && test ! -L /usr/local/bin/owntransit
test -x /opt/owntransit-preview/0.6.1/client/owntransit
test "$(readlink /usr/local/bin/owntransit-client)" = /opt/owntransit/0.7.0/client/owntransit-client

# A non-purging uninstall removes only verified local software and services.
install -d -m 0700 /var/lib/owntransit-pair
printf '%s\n' retained-state > /var/lib/owntransit-pair/uninstall-fixture
if "$bundle/install-linux.sh" --bundle "$bundle" --role target --action uninstall >/tmp/edited-uninstall.out 2>&1; then
  fail 'modified target unit was removed'
fi
install -m 0644 /opt/owntransit/0.7.0/target/service.template "$unit"
for tunnel in alpha bravo; do
  install -d -m 0700 "/var/lib/owntransit-tunnels/$tunnel"
  printf '%s\n' "retained-$tunnel" > "/var/lib/owntransit-tunnels/$tunnel/pairing-fixture"
  sed "s@/var/lib/owntransit-pair@/var/lib/owntransit-tunnels/$tunnel@g" "$unit" > "/etc/systemd/system/owntransit-target@$tunnel.service"
  chmod 0644 "/etc/systemd/system/owntransit-target@$tunnel.service"
done
"$bundle/install-linux.sh" --bundle "$bundle" --role target >/tmp/named-reinstall.out
grep -Fqx '  sudo /usr/local/bin/owntransit-target setup' /tmp/named-reinstall.out
printf '%s\n' '# modified instance' >> /etc/systemd/system/owntransit-target@alpha.service
if "$bundle/install-linux.sh" --bundle "$bundle" --role target --action uninstall >/tmp/named-uninstall.out 2>&1; then fail 'modified named unit uninstalled'; fi
test -e "$unit" && test -e /etc/systemd/system/owntransit-target@bravo.service
sed 's@/var/lib/owntransit-pair@/var/lib/owntransit-tunnels/alpha@g' "$unit" > /etc/systemd/system/owntransit-target@alpha.service

# Package changes may not race a live setup holding the shared maintenance lock.
( flock -s 8; "$bundle/install-linux.sh" --bundle "$bundle" --role target >/tmp/maintenance-race.out 2>&1 && exit 1; exit 0 ) 8<>/var/lib/owntransit-connector-manager/package.lock || fail 'installer ignored shared setup lock'
"$bundle/install-linux.sh" --bundle "$bundle" --role target --action uninstall
test ! -e "$unit" && test ! -e /usr/local/bin/owntransit-target
test "$(cat /var/lib/owntransit-pair/uninstall-fixture)" = retained-state
for tunnel in alpha bravo; do
  test ! -e "/etc/systemd/system/owntransit-target@$tunnel.service"
  test "$(cat "/var/lib/owntransit-tunnels/$tunnel/pairing-fixture")" = "retained-$tunnel"
done
"$bundle/install-linux.sh" --bundle "$bundle" --role target
test -e "$unit"
printf '%s\n' unmanaged-command > /usr/local/bin/owntransit
"$bundle/install-linux.sh" --bundle "$bundle" --role client
test "$(cat /usr/local/bin/owntransit)" = unmanaged-command
"$bundle/install-linux.sh" --bundle "$bundle" --role client --action uninstall
test "$(cat /usr/local/bin/owntransit)" = unmanaged-command
test ! -e /opt/owntransit/0.7.0/client
"$bundle/install-linux.sh" --bundle "$bundle" --role client --action uninstall
"$bundle/install-linux.sh" --bundle "$bundle" --role client
"$bundle/install-linux.sh" --bundle "$bundle" --role relay --action uninstall
test "$(cat /tmp/owntransit-relay-package-helper.args)" = "$(printf 'uninstall-all-managed\n--package-lock-fd\n9')" || fail 'whole-role removal did not cover all instances under the package lock'
test ! -e /usr/local/bin/owntransit-relay

if grep -Eq '/etc/(ssh|nginx)|iptables|nft[[:space:]]|ufw|firewall-cmd' "$bundle/install-linux.sh"; then
  fail 'installer contains forbidden host integration'
fi
printf '%s\n' 'development Linux installer tests passed'
