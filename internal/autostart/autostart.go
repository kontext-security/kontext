// Package autostart keeps the entry that starts the daemon when a Windows
// user signs in: a value in that user's own Run key, which needs no
// administrator. Setup writes it, uninstall removes it, doctor reads it.
package autostart

// Command is the command line the sign-in entry runs: the daemon's program,
// quoted because its folder may hold spaces, and its subcommand.
func Command(daemon string) string {
	return `"` + daemon + `" managed-observe-daemon`
}
