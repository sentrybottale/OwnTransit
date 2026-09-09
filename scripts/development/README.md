# Signed receiver-owned capsules

0.5.0 adds a 56-character private receiver code and automatic delivery of public
setup material. The selected VPS still explicitly approves the receiver's public
ID; its approval command prints success. New clients enter their relay URL and
one private code. The versioned public-offer extension requires an updated relay
and receiver for new short-code setup. Existing paired state, endpoint wire
authentication, alarm state and relay origins remain unchanged. The same signer,
nine assets and bounded checks apply, with offer-substitution, mixed-version,
restart and terminal-paste tests. No signing key or ceremony is added.

0.4.0 adds named local relay instances and retains default deployment compatibility.
Relay instance creation/upgrade/removal is explicitly selected; endpoint pairings
never change relay origins automatically. The same existing signer, nine assets
and bounded source/installer checks apply, with multi-instance isolation coverage.

0.3.0 adds named client/receiver tunnel selection and independently managed
receiver instances. It uses the same bounded release checks and nine public
assets as 0.2.0. Existing default pairings remain intact; no wire migration or
new signing mechanism is required. See the 0.3.0 shipping-plan section.

For 0.2.0, follow the bounded receiver-owned release contract at the top of
`OWNTRANSIT_SHIPPING_PLAN.md`. Historical filenames, preview aliases and the
existing signing namespace are retained; no signature is reinterpreted as a
legacy 0.1.0 manifest/policy. The inventory now has six members, with nine public
assets after adding its signature, inventory and public key. The Mac archive
includes `install-macos.sh` for offline, non-purging removal.

A 0.2.0, 0.3.0, 0.4.0 or 0.5.0 release may be published without GitHub's prerelease flag after the
bounded checks and brief exact-build end-to-end check pass. Extended soak,
clean-host certification and independent assessment remain explicitly unclaimed.
No new signing keys or additional ceremony is introduced.

The earlier preview-lane rationale follows; its prerelease-only publication rule
applies to 0.1.x previews, not the explicitly scoped 0.2.0 release above.

This is the owner-authorized fast development lane. It is separate from the
stable/qualification release machinery in `scripts/release/` and creates no
production manifest, release policy, qualification record or rollback counter.
It must never claim that an unperformed platform or security assessment passed.

A development preview has an immutable signed source tag, exact versioned
platform capsules, project/dependency license notices, and one locally signed
outer checksum inventory. It uses the existing distribution key with the
separate SSHSIG namespace `owntransit-development-v1` and principal
`owntransit-development`. A development signature cannot be substituted into
the production release namespace. Signing keys never enter CI, capsules, relay
state or the repository. No key generation or rotation is part of this lane.

The initial curl bootstrap trusts GitHub to deliver its pinned verifier, just
like the existing Linux quick-install boundary. It then requires the exact
existing distribution public-key digest, validates the detached inventory
signature, and checks the selected archive digest before extraction or root
execution. The inner installer rechecks the platform and exact flat inventory.

Linux installation uses `/opt/owntransit-preview/0.5.0`, separately named
`*-preview` aliases, and one disabled connector service. It preserves every
legacy install, service, credential and SSH setting. `pair setup` on the
connector initializes its own identities and explicitly enables its installed
service; normal restart/network recovery does not require re-pairing. A local
security alarm is terminal and requires a deliberate rebuild with fresh keys.

Explicitly rerunning receiver `pair setup` creates fresh identities and a fresh
private code; it is not a service restart. A paired receiver asks before replacing
its client, and that consent is checked atomically against the current peer.
The old pairing is locked and drained before atomic state replacement. Setup
waits for the worker's advertisement acknowledgement and prints exact next steps.

Existing connector installation prints service restart commands instead
of a new-pairing command. Client setup recognizes a retained pairing/request and
prints its connection/resume step without changing identity. A managed relay
upgrade uses the same setup URL and a protected rollback journal; it does not
invoke the website route editor. Named endpoint tunnels and relay instances
select independent local state without changing the pairing wire profile.

## Build and publish

1. Finish the source changes, review them, and run source/security/publication
   checks, both race/vet profiles and the disposable installer/worker tests.
2. Freeze one clean source commit with the exact version heading. Run
   `sh scripts/development/build.sh ABSOLUTE_GO1267 ABSOLUTE_NEW_OUTPUT`.
   Build intermediates contain no credentials and remain under that output
   directory for inspection; they are not release assets.
3. Independently inspect the exact capsule inventories and OCI profile. Use
   `sh scripts/development/sign.sh PRIVATE_KEY PUBLIC_KEY DEVELOPMENT-SHA256SUMS`
   on the existing trusted signer host. All three paths must be absolute.
   The private key must be outside artifact staging. The signer accepts only
   non-writable key custody; macOS's default deny-delete ACL grants no access
   and is allowed without changing the host's ACL.
4. Verify signatures and archive digests independently. Execute the exact native
   client and Linux installer capsules in available bounded environments. No
   new-machine, host reboot or independent external review claim is made.
5. Create and verify one immutable signed version tag. Create a draft GitHub
   release (prerelease for the older 0.1.x lane; normal release is allowed for
   qualified 0.2.0 scope above). Upload only the six signed
   inventory members, the inventory, its detached signature, and the existing
   distribution public key. Download the entire draft and reverify it before
   publication. Publish with a prominent DEVELOPMENT PREVIEW warning.

The plain numeric version identifies these immutable bytes; GitHub's prerelease
flag and explicit development capsule/signature formats distinguish them from
the stable lane. A later corrected build gets a new version, never overwritten
assets or a moved tag. This owner-authorized lane does not satisfy or relax the
stable release gates.

Relay bootstrap can launch managed setup interactively or accept the public URL
as its second argument. The selected URL is visible and is not a secret. Managed
setup uses a non-root relay container and supports recognized Nginx, Apache and
Caddy sites, plus reuse of routing supplied by other proxies. It requires Linux
with systemd and an existing HTTPS site. Source-defined fixture tests exercise
cutover/rollback and actual provider configuration syntax without touching a VPS.

Provider references: [Nginx reverse proxy](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/),
[Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy),
[Apache WebSocket proxy](https://httpd.apache.org/docs/2.4/mod/mod_proxy_wstunnel.html).

## Installer tests

`test-install-linux.sh` refuses to run outside its explicitly instrumented
disposable Linux container. It covers both role isolation and fail-closed
tamper/unmanaged-path behavior. It never runs against an operator machine.
