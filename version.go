package main

import "fmt"

// Build metadata. version is overridden at release time via -ldflags; commit
// and date are stamped by the release tooling.
var (
	version = "dev"
	commit  = ""
	date    = ""
)

// runVersionSubcommand prints the build version and exits.
func runVersionSubcommand() int {
	if commit != "" || date != "" {
		fmt.Printf("creator-server %s (commit %s, built %s)\n", version, commit, date)
	} else {
		fmt.Printf("creator-server %s\n", version)
	}
	return 0
}
