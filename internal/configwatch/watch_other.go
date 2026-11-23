//go:build !darwin && !linux

package configwatch

import "errors"

// newBackend has no notification API here; the caller's poll does the work.
func newBackend() (backend, error) { return nil, errors.New("configwatch: unsupported platform") }
