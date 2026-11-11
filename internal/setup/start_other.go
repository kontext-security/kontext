//go:build !windows

package setup

import "errors"

// The Windows flow's session parts have no meaning elsewhere; a test replaces
// them through the seams in windows.go.
var errWindowsOnly = errors.New("only on Windows")

func startDetached(string, ...string) error { return errWindowsOnly }
