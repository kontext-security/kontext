//go:build !windows

package setup

import "errors"

func stopProcess(int, string) (bool, error) { return false, errors.New("only on Windows") }

func stopProgramProcesses(string) (int, error) { return 0, errors.New("only on Windows") }
