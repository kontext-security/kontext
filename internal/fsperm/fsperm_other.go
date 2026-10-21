//go:build !unix && !windows

package fsperm

import (
	"errors"
	"os"
)

// Requirement names what PrivateFile checks, for error messages.
const Requirement = "owner-only access"

var errUnsupported = errors.New("fsperm: private files are not supported on this platform")

// RestrictFile refuses: this platform has neither mode bits nor DACLs to keep a file private.
func RestrictFile(*os.File) error { return errUnsupported }

// PrivateFile reports every file as not private here.
func PrivateFile(string, os.FileInfo) (bool, error) { return false, errUnsupported }
