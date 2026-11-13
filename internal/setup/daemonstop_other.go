//go:build !windows

package setup

import "errors"

func stopProcess(int) error { return errors.New("only on Windows") }
