//go:build !windows

package autostart

import "errors"

// ErrUnsupported is what every call returns off Windows.
var ErrUnsupported = errors.New("the sign-in entry exists only on Windows")

func Set(string) error { return ErrUnsupported }

func Remove() error { return ErrUnsupported }

func Entry() (string, error) { return "", ErrUnsupported }
