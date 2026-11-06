//go:build !windows

package main

import "os"

// hooksPrivileged reports whether this process may write the machine-wide hook
// files: it runs as root. A test seam.
var hooksPrivileged = func() bool {
	return os.Geteuid() == 0
}

const hooksPrivilegeHint = "system hook installation and removal require root; use sudo with --scope system"
