//go:build !darwin && !linux

package codexroute

import "io"

// JobLog is where the proxy job logs; off macOS there is no job.
func JobLog(_ string, fallback io.Writer) io.Writer { return fallback }
