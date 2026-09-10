// owntransit-client is the public client entrypoint.
package main

import (
	"fmt"
	"os"

	"github.com/sentrybottale/owntransit/internal/buildinfo"
	"github.com/sentrybottale/owntransit/internal/paircmd"
)

func main() {
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "version" {
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, "owntransit-client version: unexpected argument")
			os.Exit(2)
		}
		if err := buildinfo.Write(os.Stdout, "client", ""); err != nil {
			os.Exit(1)
		}
		return
	}
	os.Exit(paircmd.Run(false, args, os.Stdin, os.Stdout, os.Stderr))
}
