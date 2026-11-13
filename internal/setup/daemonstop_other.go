//go:build !windows

package setup

import "errors"

func stopProcess(int, string) (bool, error) { return false, errors.New("only on Windows") }
