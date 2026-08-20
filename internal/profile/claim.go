package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Claim markers stamp a directory that a setup run is mid-creating, named
// .claim-<pid>-<unique>. The pid makes liveness the owning process's rather
// than a timeout's: a crashed run's marker stops counting the moment its
// process is gone, so rename and removal need no grace period to clean up
// after it — and a live one pins the directory against both.
const claimMarkerPrefix = ".claim-"

// Claim atomically reserves name's directory, which must not exist: the bare
// Mkdir either creates it or fails with ErrExists because another process
// just did, leaving no window between check and write.
//
// The returned release acts only while the marker written here still exists —
// a directory removed and re-created by another process carries no marker of
// this claim's, and is never touched. release(failed=true) discards a
// still-empty claim; release(false) keeps the directory and drops only the
// marker.
func Claim(name string) (release func(failed bool), err error) {
	dir, err := Dir(name)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%w: %s", ErrExists, name)
		}
		return nil, err
	}
	marker, err := os.CreateTemp(dir, fmt.Sprintf("%s%d-", claimMarkerPrefix, os.Getpid()))
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	markerPath := marker.Name()
	if err := marker.Close(); err != nil {
		_ = os.Remove(markerPath)
		_ = os.Remove(dir)
		return nil, err
	}
	return func(failed bool) {
		if _, err := os.Lstat(markerPath); err != nil {
			// Not this claim's directory any more; leave it exactly as found.
			return
		}
		_ = os.Remove(markerPath)
		if failed {
			// Remove refuses a non-empty directory, so a run that got as far
			// as real content keeps it for inspection.
			_ = os.Remove(dir)
		}
	}, nil
}

// HasLiveClaim reports whether name's directory carries a claim whose owning
// process is still running. Dead processes' markers do not count and are
// removed on sight, so a crashed setup never leaves a directory that can no
// longer be renamed or removed.
func HasLiveClaim(name string) (bool, error) {
	dir, err := Dir(name)
	if err != nil {
		return false, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), claimMarkerPrefix) {
			continue
		}
		pidText, _, ok := strings.Cut(strings.TrimPrefix(entry.Name(), claimMarkerPrefix), "-")
		pid, convErr := strconv.Atoi(pidText)
		if !ok || convErr != nil || pid <= 0 {
			// Not a marker this code wrote; never let it block anything.
			continue
		}
		if pidAlive(pid) {
			return true, nil
		}
		_ = os.Remove(filepath.Join(dir, entry.Name()))
	}
	return false, nil
}

// errStillBeingCreated names the live-claim refusal rm and rename share.
func errStillBeingCreated(name string) error {
	return fmt.Errorf(
		"profile %q is still being created by another kontext process; wait for it to finish (a crashed run's claim clears as soon as its process exits)",
		name)
}
