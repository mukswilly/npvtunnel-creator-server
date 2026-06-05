package main

import "fmt"

// Build metadata. Overridden at release time via -ldflags
// "-X main.version=... -X main.commit=... -X main.date=...".
// Defaults to "dev" for local / source builds.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// runVersionSubcommand prints the build version. Invoked via the
// `version` / `-v` / `--version` subcommands.
func runVersionSubcommand() int {
	if commit != "" || date != "" {
		fmt.Printf("creator-server %s (commit %s, built %s)\n", version, commit, date)
	} else {
		fmt.Printf("creator-server %s\n", version)
	}
	return 0
}
