//go:build windows

package busyfile

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// What counts as busy, and for how long it is tried again, without a race:
// the two answers Windows gives for a file another handle has, wrapped as os
// wraps them, against one it gives for anything else.
func TestRetryTriesAgainOnlyWhileBusy(t *testing.T) {
	previous := wait
	wait = 250 * time.Millisecond
	t.Cleanup(func() { wait = previous })
	for name, test := range map[string]struct {
		err   error
		again bool
	}{
		"a rename over an open file":       {&os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.ERROR_ACCESS_DENIED}, true},
		"an open of a file being replaced": {&os.PathError{Op: "open", Path: "a", Err: errorSharingViolation}, true},
		"a file that is not there":         {&os.PathError{Op: "open", Path: "a", Err: syscall.ERROR_FILE_NOT_FOUND}, false},
	} {
		t.Run(name, func(t *testing.T) {
			tries := 0
			start := time.Now()
			err := retry(func() error { tries++; return test.err })
			took := time.Since(start)
			if err != test.err {
				t.Fatalf("retry = %v, want the error it was given", err)
			}
			if !test.again {
				if tries != 1 || took > 100*time.Millisecond {
					t.Fatalf("%d tries in %v, want one try and no wait", tries, took)
				}
				return
			}
			if tries < 10 || took < wait || took > wait+250*time.Millisecond {
				t.Fatalf("%d tries in %v, want many tries for about %v", tries, took, wait)
			}
		})
	}
}

func TestRetryStopsAtTheFirstSuccess(t *testing.T) {
	tries := 0
	err := retry(func() error {
		if tries++; tries < 3 {
			return &os.PathError{Op: "open", Path: "a", Err: errorSharingViolation}
		}
		return nil
	})
	if err != nil || tries != 3 {
		t.Fatalf("retry = %v after %d tries, want success on the third", err, tries)
	}
}
