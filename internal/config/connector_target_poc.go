//go:build owntransit_poc_ssh

package config

// ConnectorSSHTarget is selected at build time. This explicit development-only
// profile is for the combined Apple Container POC, whose unprivileged sshd
// listens on port 2222.
const ConnectorSSHTarget = "127.0.0.1:2222"
