package codexroute

import (
	"errors"
	"os"
)

// cloneFile clones nothing on Linux, so the binary is copied.
func cloneFile(*os.File, string) error { return errors.ErrUnsupported }
