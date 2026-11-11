//go:build !windows

package setup

func stopProcess(int) error { return errWindowsOnly }
