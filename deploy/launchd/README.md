# OwnTransit and launchd

OwnTransit deliberately ships no macOS LaunchAgent or LaunchDaemon for the v1
client. The client is an on-demand OpenSSH `ProxyCommand`: launchd cannot supply
the SSH stdio stream, and daemonizing it would create a new listener or IPC
surface with no product purpose.

The macOS package installs root-owned launchers beneath
`/Library/OwnTransit/bin`. Privileged lifecycle execution must use the
authenticated root-owned copy there, never a user-writable Homebrew Cellar or
source-tree executable. The package never traverses a home directory, creates
user state, edits SSH configuration, or starts a background process.

The CGO-free Darwin runtime-view implementation now inspects the descriptor's
filesystem capability and extended-security attributes, rejects every extended
ACL, and fails closed with
`securefs.ErrReadOnlyACLVerificationUnavailable` when the filesystem or syscall
ABI cannot prove the result. The fixed zero-member setgid launcher and
GeneratedUID binding are also implemented. The 0.1.0 hard artifact smoke
authenticates and inspects the Darwin launcher and records its expected
fail-closed rejection when invoked outside its fixed installed path. It does
not claim candidate macOS client installation or launcher activation. The
clean-Apple-silicon lifecycle, ACL, setgid, task-port, restart and policy matrix
described in `packaging/macos/CLIENT_READER_BOUNDARY.md` is additional
assurance. A launchd job is not a workaround for the runtime security invariant.

If a future client mode genuinely requires a background job, its plist needs a
separate threat model, fixed absolute paths, no environment-selected program or
state, bounded logs, and clean-host launchd qualification. It is not smuggled
into the v1 ProxyCommand package.
