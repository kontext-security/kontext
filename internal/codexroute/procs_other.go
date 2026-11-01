//go:build !darwin

package codexroute

import "time"

// codexSince and processStarted are never needed off macOS, where nothing is
// routed.
func codexSince(time.Time) (int, error) { return 0, nil }

func processStarted(int) (time.Time, bool) { return time.Time{}, false }
