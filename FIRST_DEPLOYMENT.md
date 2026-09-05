# First Linux deployment

These steps use the shipped OwnTransit
0.1.0 commands for exactly one public relay, one private connector, one route,
and one Linux client. They cover the actual invitation creation command and
the administrator's enrollment and activation work. Installation by itself
does not connect the machines.

This guide was added after the immutable v0.1.0 source commit. It describes and
links only commands shipped in that release, but the guide itself is not a file
authenticated by the v0.1.0 source archive or qualification record.

OwnTransit does not create or change SSH users, host keys, user keys,
`authorized_keys`, `sshd_config`, client SSH configuration, or host recovery.
The private server must already accept the intended OpenSSH connection on
`127.0.0.1:22`.

## Before starting

Install the authenticated 0.1.0 `relay`, `connector`, `client`, and
`provisioner` roles using [INSTALL.md](INSTALL.md). Run the provisioner on an
offline machine. The online courier described below must not have any CA or
deployment-signing private key.

Install `jq` before starting these steps. The relay and connector require an
operational systemd manager; guided client setup invokes `/usr/bin/sudo`. All
clocks must be correct. The invitation and the target requests have one-hour
validity windows, so create the requests and invitation only when every person
and machine is ready.

The relay prerequisite is operator-managed HTTPS, not an OwnTransit install
step:

- choose one lower-case public DNS name with working WebPKI HTTPS;
- integrate the reviewed
  [Nginx HTTP limits](deploy/vps/nginx-http-limits.conf) into the existing
  `http` context and the reviewed
  [Nginx locations](deploy/vps/nginx-location.conf) into the intended existing
  TLS server; and
- verify that those exact `/connects` and `/connects/enrollment` locations can
  reach only the relay package's loopback publication at `127.0.0.1:9087`.

This runbook never edits or reloads Nginx, changes operator firewall policy,
changes SSH, touches a website, or takes over a public port. Do that integration
through the host's existing change process before continuing. OwnTransit itself
publishes the relay only on host loopback; the existing HTTPS server remains the
public listener. Starting the Podman bridge can create Podman's ordinary
runtime networking and NAT state, so review that separately under the host's
container policy.

Keep another way to administer every machine throughout the deployment.

## Exact 0.1.0 release context

These values come from the authenticated public 0.1.0 release manifest:

```text
release_id       ov7g6h3cxxmpnbdm4twv2nkvneg2yk5ydrn4vtxjsj7m56yv2mgq
release_sequence 13
source_commit    445579f850589e1564ed41ecd9cc2d1f3c571439
```

| Linux artifact | amd64 / x86_64 SHA-256 | arm64 / aarch64 SHA-256 |
|---|---|---|
| client | `aed22980cd6855b800ab55d02fb115e81789907b670e64595fd245476133d201` | `82f2e96ca0dc3fc0995583319eddd7677a4d5cb8f8bc40144b7e2b2fdf5c3a7b` |
| connector | `58c9d0c14e73d94023a6e67982c994879f5374ea717a2d169bda741ab6e03a19` | `4b7944257521f06f6e48bc1f3670696ce30151ac08f67048c22a80875eee7ba2` |
| relay OCI | `b213b4017c9efd30a2575de31ca262224ed53bf8552cab773c7bf4c09f66e55c` | `ef0d55df3d6ad1b780373bde162d07db84352d369a676aa186f93acebfdccba5` |
| lifecycle | `8cd53cb708f4ff1b02810b642ebb1684c390288d429d839328787b6458d205f1` | `70b6ab31513ecd63225b05ff1de35a37bf27200a5d602fe208b69c68ef1b93e8` |
| provisioner | `de7629873d244eec528c5e6d7b470a969ffd8cf6080d5867c8461e81e55748e2` | `ee04be68465967c02567113e8c7c02f26ca967149a505e6ce36c72d69ae2576f` |

Only the client, connector, and relay digests are supplied to endpoint
bootstrap below. Package installation authenticates the lifecycle and
provisioner artifacts. Do not substitute a digest copied from an unauthenticated
download page.

### Exact transfer destinations

The transport used to move files is operator-specific. On every receiving
machine, create a fresh single-link file at the exact destination below with
the listed owner and mode; refuse an existing destination rather than
overwriting it. `/TRANSFER/...` in later commands means the operator-selected
read-only arrival location, not a literal directory.

| From | File | Exact receiving destination |
|---|---|---|
| offline provisioner | five public authority files | relay and connector: `/root/owntransit-route-public/` (`root`, public files `0644`, directory `0700`) |
| relay | `relay-request.otr` | offline: `$OFFLINE_ROOT/inputs/relay-request.otr` (offline user, `0600`) |
| connector | `connector-request.otr` | offline: `$OFFLINE_ROOT/inputs/connector-request.otr` (offline user, `0600`) |
| connector | `connector-bootstrap.json` | offline: `$OFFLINE_ROOT/inputs/connector-bootstrap.json` (offline user, `0600`) |
| client | `owntransit-client-runtime.json` | offline: `$OFFLINE_ROOT/inputs/client-runtime.json` (offline user, `0600`) |
| courier | `allocation-hash.json` | relay: `/root/owntransit-initial-route/allocation-hash.json` (`root`, `0600`) |
| offline provisioner | `invitation.otinvite` | client: `$HOME/office.otinvite` (intended client user, `0600`) |
| offline provisioner | `courier-registration.otreg` | courier: `$COURIER_ROOT/courier-registration.otreg` (courier user, `0600`) |
| courier | `encrypted-request.otreq` | offline: `$OFFLINE_ROOT/inputs/encrypted-request.otreq` (offline user, `0600`) |
| offline provisioner | `bound-response.otb` | courier: `$COURIER_ROOT/bound-response.otb` (courier user, `0600`) |
| offline provisioner | `relay-response.otb` | relay: `/root/owntransit-initial-route/relay-response.otb` (`root`, `0600`) |
| offline provisioner | `connector-response.otb` | connector: `/root/owntransit-initial-route/connector-response.otb` (`root`, `0600`) |

## 1. Offline provisioner: create one route authority

Run as the ordinary offline provisioner account, not on the relay:

```sh
set -eu
umask 077

PROVISION=/usr/local/bin/owntransit-provision
OFFLINE_ROOT=$HOME/owntransit-initial-route
AUTHORITY=$OFFLINE_ROOT/authority

install -d -m 0700 "$OFFLINE_ROOT"
install -d -m 0700 "$OFFLINE_ROOT/inputs"
"$PROVISION" init-authority --out "$AUTHORITY" \
  > "$OFFLINE_ROOT/authority-created.json"
cat "$OFFLINE_ROOT/authority-created.json"

ROUTE_ID=$(jq -er '
  select(.schema == "owntransit.provision.authority.v1")
  | .route_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$AUTHORITY/summary.json")
printf 'route_id=%s\n' "$ROUTE_ID"
```

This generates the route ID, three separate route-scoped CA keypairs, and a
separate deployment-signing keypair. Keep the complete `$AUTHORITY` directory
offline and backed up under the operator's key-custody procedure.

Copy only these public files, plus `summary.json`, into a protected temporary
directory on the relay and connector:

```text
outer-endpoint-ca-cert.pem
inner-connector-ca-cert.pem
inner-client-capability-ca-cert.pem
deployment-signing-public.pem
summary.json
```

Authenticate that transfer independently. Never copy any `*-key.pem` from the
authority directory to the relay, connector, client, or online courier.

On each of the relay and connector hosts, receive those five files from the
operator-selected transfer location with:

```sh
set -eu
AUTHORITY_TRANSFER=/TRANSFER/AUTHORITY-PUBLIC
PUBLIC_TRUST=/root/owntransit-route-public
sudo test ! -e "$PUBLIC_TRUST"
sudo install -d -o root -g root -m 0700 "$PUBLIC_TRUST"
for file_name in \
  outer-endpoint-ca-cert.pem \
  inner-connector-ca-cert.pem \
  inner-client-capability-ca-cert.pem \
  deployment-signing-public.pem \
  summary.json
do
  sudo test -f "$AUTHORITY_TRANSFER/$file_name"
  sudo test ! -L "$AUTHORITY_TRANSFER/$file_name"
  sudo test ! -e "$PUBLIC_TRUST/$file_name"
  sudo install -o root -g root -m 0644 \
    "$AUTHORITY_TRANSFER/$file_name" "$PUBLIC_TRUST/$file_name"
done
```

## 2. Public relay: bootstrap and create its request

The relay role must already be installed, with Podman available at
`/usr/bin/podman`. Place the five public authority files above in
`/root/owntransit-route-public`. First run `sudo -i`. In the resulting root
shell, paste:

```sh
set -eu
umask 077

RELEASE_ID=ov7g6h3cxxmpnbdm4twv2nkvneg2yk5ydrn4vtxjsj7m56yv2mgq
RELEASE_SEQUENCE=13
RELAY_CTL=/usr/libexec/owntransit/roles/relay/current/owntransitctl
PUBLIC_TRUST=/root/owntransit-route-public
WORK=/root/owntransit-initial-route
install -d -m 0700 "$WORK"

RELAY_VERSION=$("$RELAY_CTL" version)
RELAY_ARCH=$(printf '%s\n' "$RELAY_VERSION" | jq -er \
  --arg release "$RELEASE_ID" \
  'select(.schema == "owntransit.build.v1" and .version == "0.1.0" and .release_id == $release and .source_commit == "445579f850589e1564ed41ecd9cc2d1f3c571439" and .source_dirty == "false" and .role == "lifecycle" and .goos == "linux") | .goarch')
case "$RELAY_ARCH" in
  amd64) RELAY_SHA=b213b4017c9efd30a2575de31ca262224ed53bf8552cab773c7bf4c09f66e55c ;;
  arm64) RELAY_SHA=ef0d55df3d6ad1b780373bde162d07db84352d369a676aa186f93acebfdccba5 ;;
  *) printf 'unsupported relay architecture: %s\n' "$RELAY_ARCH" >&2; exit 1 ;;
esac
RELAY_INSTALLED_SUM=$(sha256sum \
  /usr/libexec/owntransit/roles/relay/current/owntransit-relay.oci.tar)
test "${RELAY_INSTALLED_SUM%% *}" = "$RELAY_SHA"
RELAY_GID=$(getent group owntransit-relay | awk -F: '$1 == "owntransit-relay" { print $3 }')
case "$RELAY_GID" in ''|*[!0-9]*|0) printf '%s\n' 'invalid relay GID' >&2; exit 1 ;; esac

"$RELAY_CTL" bootstrap \
  --state-root /var/lib/owntransit/relay/private \
  --rollback-anchor-root /var/lib/owntransit/relay/authority \
  --runtime-root /var/lib/owntransit/relay/runtime \
  --runtime-config-root /runtime \
  --anchor-view-root /var/lib/owntransit/relay/anchor-view \
  --reader-gid "$RELAY_GID" \
  --role relay \
  --release-id "$RELEASE_ID" \
  --release-sequence "$RELEASE_SEQUENCE" \
  --artifact-sha256 "$RELAY_SHA" \
  --os linux \
  --arch "$RELAY_ARCH" \
  --outer-ca "$PUBLIC_TRUST/outer-endpoint-ca-cert.pem" \
  --inner-connector-ca "$PUBLIC_TRUST/inner-connector-ca-cert.pem" \
  --inner-client-ca "$PUBLIC_TRUST/inner-client-capability-ca-cert.pem" \
  --deployment-signer "$PUBLIC_TRUST/deployment-signing-public.pem" \
  > "$WORK/relay-bootstrap.json"
cat "$WORK/relay-bootstrap.json"

RELAY_ID=$(jq -er '
  select(.schema == "owntransit.ctl.bootstrap.v1" and .role == "relay")
  | .installation_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$WORK/relay-bootstrap.json")
printf 'relay_installation_id=%s\n' "$RELAY_ID"

"$RELAY_CTL" enroll-init \
  --state-root /var/lib/owntransit/relay/private \
  --out "$WORK/relay-request.otr" \
  > "$WORK/relay-request-summary.json"
cat "$WORK/relay-request-summary.json"
jq -er 'select(.schema == "owntransit.ctl.request.v1") | .request_sha256' \
  "$WORK/relay-request-summary.json" >/dev/null
```

Copy `relay-request.otr` to the offline provisioner account as a new
single-link mode-`0600` file. It contains no endpoint private key.

## 3. Private connector: bootstrap and create its request

Place the same five authenticated public authority files in
`/root/owntransit-route-public`. First run `sudo -i` on the connector. In the
resulting root shell, paste:

```sh
set -eu
umask 077

RELEASE_ID=ov7g6h3cxxmpnbdm4twv2nkvneg2yk5ydrn4vtxjsj7m56yv2mgq
RELEASE_SEQUENCE=13
CONNECTOR_CTL=/usr/libexec/owntransit/roles/connector/current/owntransitctl
PUBLIC_TRUST=/root/owntransit-route-public
WORK=/root/owntransit-initial-route
install -d -m 0700 "$WORK"

ROUTE_ID=$(jq -er '
  select(.schema == "owntransit.provision.authority.v1")
  | .route_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$PUBLIC_TRUST/summary.json")
CONNECTOR_VERSION=$("$CONNECTOR_CTL" version)
CONNECTOR_ARCH=$(printf '%s\n' "$CONNECTOR_VERSION" | jq -er \
  --arg release "$RELEASE_ID" \
  'select(.schema == "owntransit.build.v1" and .version == "0.1.0" and .release_id == $release and .source_commit == "445579f850589e1564ed41ecd9cc2d1f3c571439" and .source_dirty == "false" and .role == "lifecycle" and .goos == "linux") | .goarch')
case "$CONNECTOR_ARCH" in
  amd64) CONNECTOR_SHA=58c9d0c14e73d94023a6e67982c994879f5374ea717a2d169bda741ab6e03a19 ;;
  arm64) CONNECTOR_SHA=4b7944257521f06f6e48bc1f3670696ce30151ac08f67048c22a80875eee7ba2 ;;
  *) printf 'unsupported connector architecture: %s\n' "$CONNECTOR_ARCH" >&2; exit 1 ;;
esac
CONNECTOR_INSTALLED_SUM=$(sha256sum \
  /usr/libexec/owntransit/roles/connector/current/owntransit-connector)
test "${CONNECTOR_INSTALLED_SUM%% *}" = "$CONNECTOR_SHA"
CONNECTOR_GID=$(getent group owntransit-connector | awk -F: '$1 == "owntransit-connector" { print $3 }')
case "$CONNECTOR_GID" in ''|*[!0-9]*|0) printf '%s\n' 'invalid connector GID' >&2; exit 1 ;; esac

"$CONNECTOR_CTL" bootstrap \
  --state-root /var/lib/owntransit/connector/private \
  --rollback-anchor-root /var/lib/owntransit/connector/authority \
  --runtime-root /var/lib/owntransit/connector/runtime \
  --runtime-config-root /var/lib/owntransit/connector/runtime \
  --anchor-view-root /var/lib/owntransit/connector/anchor-view \
  --reader-gid "$CONNECTOR_GID" \
  --role connector \
  --release-id "$RELEASE_ID" \
  --release-sequence "$RELEASE_SEQUENCE" \
  --artifact-sha256 "$CONNECTOR_SHA" \
  --os linux \
  --arch "$CONNECTOR_ARCH" \
  --outer-ca "$PUBLIC_TRUST/outer-endpoint-ca-cert.pem" \
  --inner-connector-ca "$PUBLIC_TRUST/inner-connector-ca-cert.pem" \
  --inner-client-ca "$PUBLIC_TRUST/inner-client-capability-ca-cert.pem" \
  --deployment-signer "$PUBLIC_TRUST/deployment-signing-public.pem" \
  --connector-target tcp4/127.0.0.1:22 \
  > "$WORK/connector-bootstrap.json"
cat "$WORK/connector-bootstrap.json"

CONNECTOR_ID=$(jq -er '
  select(.schema == "owntransit.ctl.bootstrap.v1" and .role == "connector")
  | .installation_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$WORK/connector-bootstrap.json")
printf 'connector_installation_id=%s\n' "$CONNECTOR_ID"

"$CONNECTOR_CTL" enroll-init \
  --state-root /var/lib/owntransit/connector/private \
  --route "$ROUTE_ID" \
  --out "$WORK/connector-request.otr" \
  > "$WORK/connector-request-summary.json"
cat "$WORK/connector-request-summary.json"
jq -er 'select(.schema == "owntransit.ctl.request.v1") | .request_sha256' \
  "$WORK/connector-request-summary.json" >/dev/null
```

Copy both `connector-request.otr` and `connector-bootstrap.json` to the offline
provisioner account as new single-link mode-`0600` files. The summary supplies
the connector ID; nobody needs to retype it.

## 4. Linux client: export its authenticated runtime facts

After installing the client and starting a new login session, run as the
intended client user:

```sh
set -eu
umask 077

RELEASE_ID=ov7g6h3cxxmpnbdm4twv2nkvneg2yk5ydrn4vtxjsj7m56yv2mgq
CLIENT_VERSION=$(owntransit version)
CLIENT_ARCH=$(printf '%s\n' "$CLIENT_VERSION" | jq -er \
  --arg release "$RELEASE_ID" \
  'select(.schema == "owntransit.build.v1" and .version == "0.1.0" and .release_id == $release and .source_commit == "445579f850589e1564ed41ecd9cc2d1f3c571439" and .source_dirty == "false" and .role == "client" and .goos == "linux") | .goarch')
case "$CLIENT_ARCH" in
  amd64) CLIENT_SHA=aed22980cd6855b800ab55d02fb115e81789907b670e64595fd245476133d201 ;;
  arm64) CLIENT_SHA=82f2e96ca0dc3fc0995583319eddd7677a4d5cb8f8bc40144b7e2b2fdf5c3a7b ;;
  *) printf 'unsupported client architecture: %s\n' "$CLIENT_ARCH" >&2; exit 1 ;;
esac
CLIENT_INSTALLED_SUM=$(sha256sum \
  /usr/libexec/owntransit/roles/client/current/owntransit)
test "${CLIENT_INSTALLED_SUM%% *}" = "$CLIENT_SHA"
jq -cn \
  --arg schema owntransit.operator.client-runtime-facts.v1 \
  --arg release_id "$RELEASE_ID" \
  --argjson release_sequence 13 \
  --arg os linux \
  --arg arch "$CLIENT_ARCH" \
  --arg artifact_sha256 "$CLIENT_SHA" \
  '{schema:$schema,release_id:$release_id,release_sequence:$release_sequence,os:$os,arch:$arch,artifact_sha256:$artifact_sha256}' \
  > "$HOME/owntransit-client-runtime.json"
chmod 0600 "$HOME/owntransit-client-runtime.json"
```

Send that public facts file to the offline provisioner through the operator's
authenticated transfer procedure. It contains no client key; the client keys
do not exist yet.

## 5. Online courier: create one allocation credential

The courier can be an unprivileged account on an online administrator machine,
including the relay host, because it is treated as untrusted. Install the
`client` software role for that existing account using INSTALL.md and start a
new login session. The commands below use its `/usr/local/bin/owntransit`
frontend; the courier does not run client enrollment. Never put the offline
authority directory on this machine.

```sh
set -eu
umask 077

COURIER_BIN=/usr/local/bin/owntransit
COURIER_ROOT=$HOME/owntransit-initial-route-courier
CREDENTIAL_STORE=$COURIER_ROOT/allocation-credential
install -d -m 0700 "$COURIER_ROOT"
test ! -e "$CREDENTIAL_STORE"

ALLOCATION_HASH=$("$COURIER_BIN" courier-credential-init \
  --store "$CREDENTIAL_STORE")
case "$ALLOCATION_HASH" in
  *[!0-9a-f]*|'') printf '%s\n' 'invalid allocation hash' >&2; exit 1 ;;
esac
test "${#ALLOCATION_HASH}" -eq 64
jq -cn --arg allocation_sha256 "$ALLOCATION_HASH" \
  '{schema:"owntransit.operator.allocation-hash.v1",allocation_sha256:$allocation_sha256}' \
  > "$COURIER_ROOT/allocation-hash.json"
chmod 0600 "$COURIER_ROOT/allocation-hash.json"
```

Keep the credential store online and private. Send only
`allocation-hash.json` to the relay operator.

## 6. Public relay: start temporary exchange-only mode

On the relay, derive the hash from the transferred JSON and start this exact
instance. Do not enable it:

```sh
set -eu
umask 077

ALLOCATION_TRANSFER=/TRANSFER/allocation-hash.json
ALLOCATION_RECORD=/root/owntransit-initial-route/allocation-hash.json
test -f "$ALLOCATION_TRANSFER"
test ! -L "$ALLOCATION_TRANSFER"
sudo test ! -e "$ALLOCATION_RECORD"
sudo test ! -L "$ALLOCATION_RECORD"
sudo install -o root -g root -m 0600 \
  "$ALLOCATION_TRANSFER" "$ALLOCATION_RECORD"
ALLOCATION_HASH=$(sudo jq -er '
  select(.schema == "owntransit.operator.allocation-hash.v1")
  | .allocation_sha256
  | select(type == "string" and test("^[0-9a-f]{64}$"))
' "$ALLOCATION_RECORD")
sudo systemctl start "owntransit-relay-exchange@${ALLOCATION_HASH}.service"
sudo systemctl is-active --quiet \
  "owntransit-relay-exchange@${ALLOCATION_HASH}.service"
```

This process has no endpoint runtime, CA key, deployment signer, target
selector, or persistent mailbox. Keep it running until step 11 proves the
client response was durably applied.

## 7. Offline provisioner: create the actual client invitation

Copy the connector bootstrap summary and client runtime facts into
`$OFFLINE_ROOT/inputs`. Copy the relay and connector requests into the paths
shown below. Keep all transferred files single-link, owned by the offline
account, and mode `0600`.

Set the two descriptions from pre-existing operator records. For byte-exact
portable JSON, use only letters, digits, spaces, periods, underscores, and
hyphens in these two values:

```sh
set -eu
umask 077

PROVISION=/usr/local/bin/owntransit-provision
OFFLINE_ROOT=$HOME/owntransit-initial-route
AUTHORITY=$OFFLINE_ROOT/authority
INPUTS=$OFFLINE_ROOT/inputs
INVITATION=$OFFLINE_ROOT/invitation
RECIPIENT_RECORD=$OFFLINE_ROOT/recipient.json
PUBLIC_DNS=relay.example.net  # replace with the real lower-case public name

RELEASE_ID=ov7g6h3cxxmpnbdm4twv2nkvneg2yk5ydrn4vtxjsj7m56yv2mgq
RELEASE_SEQUENCE=13
for transfer_name in \
  relay-request.otr \
  connector-request.otr \
  connector-bootstrap.json \
  owntransit-client-runtime.json
do
  case "$transfer_name" in
    owntransit-client-runtime.json) destination_name=client-runtime.json ;;
    *) destination_name=$transfer_name ;;
  esac
  test -f "/TRANSFER/$transfer_name"
  test ! -L "/TRANSFER/$transfer_name"
  test ! -e "$INPUTS/$destination_name"
  test ! -L "$INPUTS/$destination_name"
  install -m 0600 "/TRANSFER/$transfer_name" "$INPUTS/$destination_name"
done
ROUTE_ID=$(jq -er '.route_id | select(type == "string" and test("^[a-z2-7]{52}$"))' \
  "$AUTHORITY/summary.json")
CONNECTOR_ID=$(jq -er '
  select(.schema == "owntransit.ctl.bootstrap.v1" and .role == "connector")
  | .installation_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$INPUTS/connector-bootstrap.json")
CLIENT_ARCH=$(jq -er \
  --arg release "$RELEASE_ID" \
  'select(.schema == "owntransit.operator.client-runtime-facts.v1" and .release_id == $release and .release_sequence == 13 and .os == "linux") | .arch' \
  "$INPUTS/client-runtime.json")
case "$CLIENT_ARCH" in
  amd64) CLIENT_SHA=aed22980cd6855b800ab55d02fb115e81789907b670e64595fd245476133d201 ;;
  arm64) CLIENT_SHA=82f2e96ca0dc3fc0995583319eddd7677a4d5cb8f8bc40144b7e2b2fdf5c3a7b ;;
  *) printf 'unsupported client architecture: %s\n' "$CLIENT_ARCH" >&2; exit 1 ;;
esac
test "$(jq -er '.artifact_sha256' "$INPUTS/client-runtime.json")" = "$CLIENT_SHA"

INTENDED_RECIPIENT='replace with the pre-identified recipient'
IDENTITY_REFERENCE='replace with the pre-existing operator record reference'
jq -cn \
  --arg intended_recipient "$INTENDED_RECIPIENT" \
  --arg identity_contact_reference "$IDENTITY_REFERENCE" \
  '{schema:"owntransit.recipient-record.v1",intended_recipient:$intended_recipient,identity_contact_reference:$identity_contact_reference}' \
  > "$RECIPIENT_RECORD"
chmod 0600 "$RECIPIENT_RECORD"

"$PROVISION" issue-invitation \
  --authority "$AUTHORITY" \
  --role client \
  --connector-installation-id "$CONNECTOR_ID" \
  --release-id "$RELEASE_ID" \
  --release-sequence "$RELEASE_SEQUENCE" \
  --artifact-sha256 "$CLIENT_SHA" \
  --os linux \
  --arch "$CLIENT_ARCH" \
  --exchange-endpoint "wss://$PUBLIC_DNS/connects/enrollment" \
  --recipient-record "$RECIPIENT_RECORD" \
  --out "$INVITATION" \
  > "$OFFLINE_ROOT/invitation-created.json"
cat "$OFFLINE_ROOT/invitation-created.json"
```

This command really creates the invitation. Its output directory contains:

- `invitation.otinvite` — the **only** file sent to the recipient;
- `operator-receipt.otopr` — stays with the offline operator;
- `courier-registration.otreg` — goes only to the online courier;
- `summary.json`; and
- protected resume state used only by the provisioner.

The invitation is valid for one hour. Do not send the authority directory,
operator receipt, or courier registration to the recipient.

## 8. Online courier and client: register and upload the request

Install the transferred registration as a new mode-`0600` file owned by the
courier account, then run online:

```sh
set -eu
umask 077

COURIER_BIN=/usr/local/bin/owntransit
COURIER_ROOT=$HOME/owntransit-initial-route-courier
CREDENTIAL_STORE=$COURIER_ROOT/allocation-credential
REGISTRATION=$COURIER_ROOT/courier-registration.otreg
test -f /TRANSFER/courier-registration.otreg
test ! -L /TRANSFER/courier-registration.otreg
test ! -e "$REGISTRATION"
test ! -L "$REGISTRATION"
install -m 0600 /TRANSFER/courier-registration.otreg "$REGISTRATION"
"$COURIER_BIN" courier-register \
  --registration "$REGISTRATION" \
  --credential-store "$CREDENTIAL_STORE"
```

Install `invitation.otinvite` as a new mode-`0600` file owned by the intended
client user. On the client, run:

```sh
set -eu
umask 077

INVITATION=$HOME/office.otinvite
test -f /TRANSFER/invitation.otinvite
test ! -L /TRANSFER/invitation.otinvite
test ! -e "$INVITATION"
test ! -L "$INVITATION"
install -m 0600 /TRANSFER/invitation.otinvite "$INVITATION"
owntransit setup "$INVITATION"
```

The client now generates its installation ID, endpoint keys, CSRs, nonce,
one-response recipient, and exact signed request locally. Private key material
never leaves the client. The command uploads only the padded encrypted request
and displays three target words. The recipient reads those words to the
already-known administrator over the independently established contact
procedure, then presses Enter to save and wait if the reverse words are not yet
available.

After the client has uploaded, the online courier fetches into a new directory:

```sh
set -eu
umask 077

COURIER_BIN=/usr/local/bin/owntransit
COURIER_ROOT=$HOME/owntransit-initial-route-courier
REGISTRATION=$COURIER_ROOT/courier-registration.otreg
FETCH_ROOT=$COURIER_ROOT/fetched-request
test ! -e "$FETCH_ROOT"
"$COURIER_BIN" courier-fetch-request \
  --registration "$REGISTRATION" \
  --out "$FETCH_ROOT"
test -f "$FETCH_ROOT/encrypted-request.otreq"
```

Transfer `encrypted-request.otreq` to the offline provisioner as a new
single-link mode-`0600` file. It remains encrypted during transit.

## 9. Offline provisioner and humans: open and compare

```sh
set -eu
umask 077

PROVISION=/usr/local/bin/owntransit-provision
OFFLINE_ROOT=$HOME/owntransit-initial-route
INVITATION=$OFFLINE_ROOT/invitation
OPERATOR_SESSION=$OFFLINE_ROOT/operator-session
AUTHORITY=$OFFLINE_ROOT/authority
INPUTS=$OFFLINE_ROOT/inputs
ROUTE_ID=$(jq -er '.route_id | select(type == "string" and test("^[a-z2-7]{52}$"))' \
  "$AUTHORITY/summary.json")
CONNECTOR_ID=$(jq -er '
  select(.schema == "owntransit.ctl.bootstrap.v1" and .role == "connector")
  | .installation_id | select(type == "string" and test("^[a-z2-7]{52}$"))
' "$INPUTS/connector-bootstrap.json")

test -f /TRANSFER/encrypted-request.otreq
test ! -L /TRANSFER/encrypted-request.otreq
test ! -e "$INPUTS/encrypted-request.otreq"
test ! -L "$INPUTS/encrypted-request.otreq"
install -m 0600 /TRANSFER/encrypted-request.otreq \
  "$INPUTS/encrypted-request.otreq"

"$PROVISION" operator-open \
  --receipt "$INVITATION/operator-receipt.otopr" \
  --request "$OFFLINE_ROOT/inputs/encrypted-request.otreq" \
  --session-root "$OPERATOR_SESSION" \
  > "$OFFLINE_ROOT/operator-review.json"
cat "$OFFLINE_ROOT/operator-review.json"
jq -e --arg route "$ROUTE_ID" --arg connector "$CONNECTOR_ID" '
  .schema == "owntransit.provision.operator-session.v1"
  and .role == "client"
  and .route_id == $route
  and .connector_installation_id == $connector
  and .request.file == "signed-request.otr"
' "$OFFLINE_ROOT/operator-review.json" >/dev/null
```

Review the displayed intended recipient, pre-existing identity reference,
client installation ID, route ID, and connector ID. Authenticate the recipient
from pre-existing records. The recipient must independently authenticate the
administrator using the procedure established before this invitation. The
invitation, caller ID, contact details supplied during enrollment, and the
words are not proof of either person's identity.

Run this interactively and type the three words spoken by the recipient into
stdin. Press Enter, then send EOF with `Ctrl-D`; this command reads until EOF.
Do not put words on the command line, in a file, or in a transcript:

```sh
set -eu
umask 077

PROVISION=/usr/local/bin/owntransit-provision
OPERATOR_SESSION=$HOME/owntransit-initial-route/operator-session
"$PROVISION" operator-confirm-target --session-root "$OPERATOR_SESSION"
```

Only an exact match prints the three reverse-direction words. Read those words
to the recipient. On the client, the recipient runs `owntransit setup --resume`
if needed and types exactly those three words. Any mismatch cancels this
invitation; do not guess or retry it as though it matched.

## 10. Offline provisioner: approve and bind the response

`operator-open` created the exact client request at
`$OPERATOR_SESSION/signed-request.otr`. Use it with the two target requests:

```sh
set -eu
umask 077

PROVISION=/usr/local/bin/owntransit-provision
OFFLINE_ROOT=$HOME/owntransit-initial-route
AUTHORITY=$OFFLINE_ROOT/authority
INPUTS=$OFFLINE_ROOT/inputs
OPERATOR_SESSION=$OFFLINE_ROOT/operator-session
RESPONSES=$OFFLINE_ROOT/responses
BOUND=$OFFLINE_ROOT/bound-response
PUBLIC_DNS=relay.example.net  # the same real lower-case public name

RELAY_REQUEST=$INPUTS/relay-request.otr
CONNECTOR_REQUEST=$INPUTS/connector-request.otr
CLIENT_REQUEST=$OPERATOR_SESSION/signed-request.otr

"$PROVISION" approve-initial-route \
  --relay-request "$RELAY_REQUEST" \
  --connector-request "$CONNECTOR_REQUEST" \
  --client-request "$CLIENT_REQUEST" \
  --outer-ca-cert "$AUTHORITY/outer-endpoint-ca-cert.pem" \
  --outer-ca-key "$AUTHORITY/outer-endpoint-ca-key.pem" \
  --inner-connector-ca-cert "$AUTHORITY/inner-connector-ca-cert.pem" \
  --inner-connector-ca-key "$AUTHORITY/inner-connector-ca-key.pem" \
  --inner-client-ca-cert "$AUTHORITY/inner-client-capability-ca-cert.pem" \
  --inner-client-ca-key "$AUTHORITY/inner-client-capability-ca-key.pem" \
  --deployment-signing-key "$AUTHORITY/deployment-signing-key.pem" \
  --relay-url "wss://$PUBLIC_DNS/connects" \
  --relay-listen 0.0.0.0:9087 \
  --out "$RESPONSES" \
  > "$OFFLINE_ROOT/route-approved.json"
cat "$OFFLINE_ROOT/route-approved.json"

"$PROVISION" operator-bind-response \
  --session-root "$OPERATOR_SESSION" \
  --response "$RESPONSES/client-response.otb" \
  --relay-request "$RELAY_REQUEST" \
  --connector-request "$CONNECTOR_REQUEST" \
  --client-request "$CLIENT_REQUEST" \
  --deployment-signing-key "$AUTHORITY/deployment-signing-key.pem" \
  --out "$BOUND" \
  > "$OFFLINE_ROOT/client-response-bound.json"
cat "$OFFLINE_ROOT/client-response-bound.json"
```

The first command creates target-encrypted `relay-response.otb`,
`connector-response.otb`, and `client-response.otb`. The second command creates
`$BOUND/bound-response.otb`, cryptographically binding the invited client's
response to the confirmed transcript and the exact three-request set.

`0.0.0.0:9087` above is the relay's address inside its container. The signed
service publishes it only as `127.0.0.1:9087` on the host.

The optional `approve-initial-route --enrollment-allocation-sha256` flag is
deliberately omitted. Exchange-only mode is temporary; the enrolled full relay
does not need to retain an enrollment handler after this one-client cutover.

Transfer only `bound-response.otb` to the online courier. Transfer each raw
relay or connector response only to its intended target. All remain signed and
target-encrypted, but preserve them as exact single-link files.

## 11. Courier and client: upload and prove durable apply

On the online courier:

```sh
set -eu
umask 077

COURIER_BIN=/usr/local/bin/owntransit
COURIER_ROOT=$HOME/owntransit-initial-route-courier
REGISTRATION=$COURIER_ROOT/courier-registration.otreg
BOUND_RESPONSE=$COURIER_ROOT/bound-response.otb
test -f /TRANSFER/bound-response.otb
test ! -L /TRANSFER/bound-response.otb
test ! -e "$BOUND_RESPONSE"
test ! -L "$BOUND_RESPONSE"
install -m 0600 /TRANSFER/bound-response.otb "$BOUND_RESPONSE"
"$COURIER_BIN" courier-upload-response \
  --registration "$REGISTRATION" \
  --response "$BOUND_RESPONSE"
```

On the client, run:

```sh
set -eu
owntransit setup --resume
```

With the carrier still intentionally offline, the expected result after
response application is `SETUP SAVED — NOT READY`. That text is also used for
earlier resumable waits, so verify durable application explicitly before
stopping exchange-only mode:

```sh
set -eu
CLIENT_STATUS=$(sudo \
  /usr/libexec/owntransit/roles/client/current/owntransitctl status \
  --state-root /var/lib/owntransit/client/private)
printf '%s\n' "$CLIENT_STATUS" | jq -e '
  .schema == "owntransit.ctl.status.v1"
  and .role == "client"
  and .active == true
  and .active_release_sequence == 13
' >/dev/null
```

Do not continue until that command succeeds.

## 12. Relay and connector: cut over to the carrier

First stop the exact temporary instance on the relay:

```sh
set -eu
ALLOCATION_RECORD=/root/owntransit-initial-route/allocation-hash.json
ALLOCATION_HASH=$(sudo jq -er '
  select(.schema == "owntransit.operator.allocation-hash.v1")
  | .allocation_sha256
  | select(type == "string" and test("^[0-9a-f]{64}$"))
' "$ALLOCATION_RECORD")
sudo systemctl stop "owntransit-relay-exchange@${ALLOCATION_HASH}.service"
if sudo systemctl is-active --quiet \
  "owntransit-relay-exchange@${ALLOCATION_HASH}.service"; then
  printf '%s\n' 'exchange-only service is still active' >&2
  exit 1
fi
```

Install `relay-response.otb` as a root-owned mode-`0600` file on the relay,
then apply and verify it:

```sh
set -eu
umask 077

RELAY_RESPONSE=/root/owntransit-initial-route/relay-response.otb
test -f /TRANSFER/relay-response.otb
test ! -L /TRANSFER/relay-response.otb
sudo test ! -e "$RELAY_RESPONSE"
sudo test ! -L "$RELAY_RESPONSE"
sudo install -o root -g root -m 0600 \
  /TRANSFER/relay-response.otb "$RELAY_RESPONSE"
sudo /usr/libexec/owntransit/roles/relay/current/owntransitctl apply \
  --state-root /var/lib/owntransit/relay/private \
  --response "$RELAY_RESPONSE"
sudo /usr/libexec/owntransit/roles/relay/current/owntransitctl verify \
  --state-root /var/lib/owntransit/relay/private
sudo systemctl enable --now owntransit-relay.service
sudo systemctl is-active --quiet owntransit-relay.service
```

Install `connector-response.otb` as a root-owned mode-`0600` file on the
connector, then apply and verify it:

```sh
set -eu
umask 077

CONNECTOR_RESPONSE=/root/owntransit-initial-route/connector-response.otb
test -f /TRANSFER/connector-response.otb
test ! -L /TRANSFER/connector-response.otb
sudo test ! -e "$CONNECTOR_RESPONSE"
sudo test ! -L "$CONNECTOR_RESPONSE"
sudo install -o root -g root -m 0600 \
  /TRANSFER/connector-response.otb "$CONNECTOR_RESPONSE"
sudo /usr/libexec/owntransit/roles/connector/current/owntransitctl apply \
  --state-root /var/lib/owntransit/connector/private \
  --response "$CONNECTOR_RESPONSE"
sudo /usr/libexec/owntransit/roles/connector/current/owntransitctl verify \
  --state-root /var/lib/owntransit/connector/private
sudo systemctl enable --now owntransit-connector.service
sudo systemctl is-active --quiet owntransit-connector.service
```

The connector originates outbound OwnTransit connections; the relay accepts
them through the operator-managed HTTPS proxy. The connector opens no
OwnTransit listener and can deliver an authenticated stream only to its
build-fixed `tcp4 127.0.0.1:22` destination.

## 13. Client: prove the carrier, then test SSH separately

```sh
set -eu
owntransit setup --resume
```

Success is:

```text
OwnTransit carrier READY; SSH was not attempted.
```

`READY` proves the authenticated OwnTransit carrier and connector-local port-22
dial. It does not prove an SSH host key, user key, account, or authorization.

OwnTransit can print a safe stanza, but it never edits SSH configuration:

```sh
set -eu
SSH_USER=replace-with-the-existing-ssh-account
SSH_ALIAS=replace-with-the-operator-selected-alias
owntransit ssh-config --user "$SSH_USER" "$SSH_ALIAS"
```

Review and install that output through the operator's normal SSH process, keep
strict host-key checking, and then test the operator-owned SSH path:

```sh
set -eu
SSH_ALIAS=replace-with-the-operator-selected-alias
ssh "$SSH_ALIAS"
```

## What is automatic, and what is not

The commands above automatically generate unique installation IDs, endpoint
private keys, CSRs, nonces, one-response identities, route-scoped certificates,
mailbox IDs and capabilities, signed target-bound responses, durable runtime
generations, and the final carrier proof. Endpoint private keys never leave
their target. The relay and online courier receive no CA or deployment-signing
private key.

The administrator must still authenticate the release, protect the offline
authority, move the exact files to the correct machines, integrate existing
HTTPS safely, authenticate both humans, perform the cutover, and operate SSH
and host recovery. The shipped CLI has no administrator wizard, no recipient
record generator, no dedicated courier package, and no automatic Nginx, DNS,
firewall, SSH, or website integration. Relay and connector bootstrap/apply are
advanced root-only interfaces.

OwnTransit 0.1.0 supports only this initial single client. Adding another
client to the route is not implemented. Do not reuse an invitation, rotate the
route as a substitute, or weaken the human comparison.

The signed 0.1.0 qualification executed every ordinary native artifact and
qualified connector installation and reboot on the two Linux architectures,
but it explicitly recorded Linux client, provisioner, and relay package
lifecycle plus enrollment as `NOT-CLAIMED`. The source contains end-to-end
tests for the invitation, comparison, approval, cross-binding, apply, and READY
state machines; that is not the same as an independently qualified real
operator ceremony. Canary this flow with alternate access before depending on
it.
