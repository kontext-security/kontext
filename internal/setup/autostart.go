package setup

// autostartCommand is the command line the sign-in entry runs: the daemon's
// program, quoted because its folder may hold spaces, and its subcommand.
func autostartCommand(daemon string) string {
	return `"` + daemon + `" managed-observe-daemon`
}
