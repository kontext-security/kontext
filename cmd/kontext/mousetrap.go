package main

import "github.com/spf13/cobra"

// startedByTheShell lets the daemon run when Windows Explorer starts it, which
// is how an entry in a user's Run key is started at sign-in. cobra otherwise
// takes a program whose parent is Explorer for a double-clicked command line
// tool: it prints "This is a command line tool" and exits. Seen on Windows 11:
// the daemon registered by setup never came up after a sign-in. Only the
// daemon turns the check off; a double-clicked `kontext` still gets the hint.
func startedByTheShell() {
	cobra.MousetrapHelpText = ""
}
