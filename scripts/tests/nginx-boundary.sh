#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
location_file=$project_root/deploy/vps/nginx-location.conf
limits_file=$project_root/deploy/vps/nginx-http-limits.conf

fail() {
  echo "nginx-boundary-test: $*" >&2
  exit 1
}

test -f "$location_file" && test -f "$limits_file" || fail "nginx boundary snippets are missing"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/owntransit-nginx-boundary.XXXXXX")
cleanup() {
  rm -rf -- "$scratch"
}
trap cleanup EXIT HUP INT TERM

carrier=$scratch/carrier
exchange=$scratch/exchange
sed -n '/^location = \/connects {$/,/^}$/p' "$location_file" >"$carrier"
sed -n '/^location = \/connects\/enrollment {$/,/^}$/p' "$location_file" >"$exchange"

test "$(grep -c '^location ' "$location_file")" -eq 2 || fail "only the two exact OwnTransit locations are allowed in this snippet"
test "$(grep -c '^location = /connects {$' "$carrier")" -eq 1 || fail "exact carrier location is missing"
test "$(grep -c '^location = /connects/enrollment {$' "$exchange")" -eq 1 || fail "exact enrollment location is missing"

require_line() {
  file=$1
  line=$2
  grep -Fqx "$line" "$file" || fail "missing reviewed directive: $line"
}

for line in \
  'limit_conn_zone $realip_remote_addr zone=owntransit_conn_per_peer:1m;' \
  'limit_conn_zone $server_name zone=owntransit_conn_global:1m;' \
  'limit_req_zone $realip_remote_addr zone=owntransit_upgrade_per_peer:1m rate=1r/s;' \
  'limit_req_zone $server_name zone=owntransit_upgrade_global:1m rate=4r/s;' \
  'limit_conn_zone $realip_remote_addr zone=owntransit_enrollment_conn_per_peer:1m;' \
  'limit_conn_zone $server_name zone=owntransit_enrollment_conn_global:1m;' \
  'limit_req_zone $realip_remote_addr zone=owntransit_enrollment_upgrade_per_peer:1m rate=2r/s;' \
  'limit_req_zone $server_name zone=owntransit_enrollment_upgrade_global:1m rate=8r/s;'
do
  require_line "$limits_file" "$line"
done

test "$(grep -c 'zone=owntransit_.*_per_peer:' "$limits_file")" -eq 4 ||
  fail "exactly four original-peer quota zones are required"
if grep -Eq '^limit_(conn|req)_zone[[:space:]]+\$(binary_remote_addr|remote_addr|http_[[:alnum:]_]+)([^[:alnum:]_]|$)' "$limits_file"; then
  fail "a request-rewritten or request-header value became a quota key"
fi
if grep -Eq '^limit_(conn|req)_zone .*zone=owntransit_.*_per_ip:' "$limits_file" ||
  grep -Eq '^  limit_(conn|req) .*owntransit_.*_per_ip' "$location_file"
then
  fail "legacy shared-memory zone names cannot be reused with a new key"
fi

for line in \
  '  access_log off;' \
  '  limit_conn owntransit_conn_per_peer 8;' \
  '  limit_conn owntransit_conn_global 96;' \
  '  limit_req zone=owntransit_upgrade_per_peer burst=4 nodelay;' \
  '  limit_req zone=owntransit_upgrade_global burst=8 nodelay;' \
  '  proxy_pass http://127.0.0.1:9087/connects;' \
  '  proxy_send_timeout 1d;' \
  '  proxy_read_timeout 1d;'
do
  require_line "$carrier" "$line"
done

for line in \
  '  access_log off;' \
  '  limit_conn owntransit_enrollment_conn_per_peer 4;' \
  '  limit_conn owntransit_enrollment_conn_global 16;' \
  '  limit_req zone=owntransit_enrollment_upgrade_per_peer burst=4 nodelay;' \
  '  limit_req zone=owntransit_enrollment_upgrade_global burst=16 nodelay;' \
  '  limit_conn_status 429;' \
  '  limit_req_status 429;' \
  '  client_max_body_size 1k;' \
  '  proxy_pass http://127.0.0.1:9087/connects/enrollment;' \
  '  proxy_http_version 1.1;' \
  '  proxy_set_header Upgrade $http_upgrade;' \
  '  proxy_set_header Connection "upgrade";' \
  '  proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;' \
  '  proxy_set_header Origin $http_origin;' \
  '  proxy_set_header Sec-WebSocket-Extensions "";' \
  '  proxy_set_header Cookie "";' \
  '  proxy_set_header Authorization "";' \
  '  proxy_set_header Forwarded "";' \
  '  proxy_set_header X-Forwarded-For "";' \
  '  proxy_set_header X-Real-IP "";' \
  '  proxy_set_header X-Forwarded-Proto "";' \
  '  proxy_pass_request_body off;' \
  '  proxy_set_header Content-Length "";' \
  '  proxy_set_header Transfer-Encoding "";' \
  '  proxy_buffering off;' \
  '  proxy_request_buffering off;' \
  '  proxy_next_upstream off;' \
  '  proxy_connect_timeout 5s;' \
  '  proxy_send_timeout 15s;' \
  '  proxy_read_timeout 15s;'
do
  require_line "$exchange" "$line"
done

if grep -Fq 'owntransit_enrollment_' "$carrier"; then
  fail "carrier location consumes an enrollment quota zone"
fi
if grep -Eq 'owntransit_(conn|upgrade)_' "$exchange"; then
  fail "enrollment location consumes a carrier quota zone"
fi
if grep -Eq 'proxy_pass[[:space:]]+https?://[^;]*\$|access_log[[:space:]]+(on|[^o])' "$location_file"; then
  fail "nginx boundary gained a variable upstream or enabled access log"
fi

echo "nginx carrier and enrollment boundaries passed"
