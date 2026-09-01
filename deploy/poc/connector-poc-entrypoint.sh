#!/bin/sh
set -eu

install -d -m 0700 -o owntransit -g owntransit /run/owntransit
cp -a /secrets/. /run/owntransit/
chown -R owntransit:owntransit /run/owntransit
chmod 0600 /run/owntransit/config.json /run/owntransit/*-key.pem

/usr/sbin/sshd -t -f /etc/ssh/sshd_config_owntransit
/usr/sbin/sshd -f /etc/ssh/sshd_config_owntransit

if [ -n "${OWNTRANSIT_RELAY_URL:-}" ]; then
  set -- -relay-url "$OWNTRANSIT_RELAY_URL" "$@"
fi

exec setpriv --reuid=owntransit --regid=owntransit --init-groups \
  /usr/local/bin/owntransit-connector -config /run/owntransit/config.json "$@"
