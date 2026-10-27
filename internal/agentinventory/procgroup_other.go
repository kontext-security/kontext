//go:build !unix

package agentinventory

import "os/exec"

// ownProcessGroup keeps exec's default cancel (kill the process) where
// process groups are not available.
func ownProcessGroup(*exec.Cmd) {}
