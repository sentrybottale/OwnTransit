//go:build !owntransit_poc_ssh

package config

// ConnectorSSHTarget is selected at build time. Every ordinary production
// build reaches only the host's IPv4 loopback OpenSSH listener on the standard
// port. The isolated combined development POC requires an explicit build tag.
const ConnectorSSHTarget = "127.0.0.1:22"
