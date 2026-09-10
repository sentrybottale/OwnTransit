// owntransit-target is the public target entrypoint.
package main

import (
	"fmt"
	"os"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/config"
	"github.com/sentrybottale/owntransit/internal/paircmd"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "version" {
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "owntransit-target version: unexpected argument")
			os.Exit(2)
		}
		if err := buildinfo.Write(os.Stdout, "target", "tcp4 "+config.ConnectorSSHTarget); err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(paircmd.Run(true, args, os.Stdin, os.Stdout, os.Stderr))
}
