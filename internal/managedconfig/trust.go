package managedconfig

import (
	"errors"
	"os"
	"strings"
)

// ErrUntrustedSystemConfig reports a system config someone other than an
// administrator could have written, so it can't speak for the organization.
var ErrUntrustedSystemConfig = errors.New("system config is not admin-only")

// Test seam: reads the files only an installer should write.
var readSystemFile = readAdminOnly

// Test seam: finds what rules out a system file being an administrator's. The
// result's String can be slow, so only doctor asks for it.
var notAdminFile = systemFileNotAdmins

// systemFileIgnored reports a file at the system path that can't be an
// administrator's. Such a file must not take the machine from its users, so it
// doesn't count as there. What can't be determined doesn't ignore it.
func systemFileIgnored() bool {
	found, err := notAdminFile(systemPath)
	return err == nil && found != nil
}

// IgnoredSystemFile says why a file at the system path is being ignored, and ""
// if it isn't or there is none.
func IgnoredSystemFile() string {
	if strings.TrimSpace(os.Getenv(EnvPath)) != "" {
		return ""
	}
	found, err := notAdminFile(systemPath)
	if err != nil || found == nil {
		return ""
	}
	return found.String()
}
