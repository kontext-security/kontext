package managedconfig

import "errors"

// ErrUntrustedSystemConfig reports a system config someone other than an
// administrator could have written, so it can't speak for the organization.
var ErrUntrustedSystemConfig = errors.New("system config is not admin-only")

// Test seam: reads the files only an installer should write.
var readSystemFile = readAdminOnly
