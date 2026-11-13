// Package autostart keeps the entry that starts the daemon when a Windows
// user signs in: a value in that user's own Run key, which needs no
// administrator. Setup writes it, uninstall removes it, doctor reads it.
package autostart

import "strings"

// DaemonSubcommand is the subcommand that runs the daemon.
const DaemonSubcommand = "managed-observe-daemon"

// Command is the command line the sign-in entry runs: the daemon's program,
// quoted because its folder may hold spaces, and its subcommand.
func Command(daemon string) string {
	return `"` + daemon + `" ` + DaemonSubcommand
}

// Program is the program an entry starts: the quoted part Command writes, or
// the first word of an entry written some other way. "" for an empty entry.
func Program(entry string) string {
	if rest, quoted := strings.CutPrefix(entry, `"`); quoted {
		program, _, _ := strings.Cut(rest, `"`)
		return program
	}
	program, _, _ := strings.Cut(strings.TrimSpace(entry), " ")
	return program
}
