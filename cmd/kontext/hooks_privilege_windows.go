package main

import "golang.org/x/sys/windows"

// hooksPrivileged reports whether this process may write Claude Code's
// machine-wide managed settings under Program Files: an elevated token, as
// "Run as administrator" gives. A test seam.
var hooksPrivileged = func() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

const hooksPrivilegeHint = "system hook installation and removal require an elevated process; run it from a terminal opened with Run as administrator"
