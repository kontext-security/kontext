//go:build windows

package setup

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// The user's own Run key: what it lists starts at that user's sign-in, and
// writing it needs no administrator.
const autostartKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// autostartValue names the entry. A variable so a test writes one of its own
// and never the entry of a real install.
var autostartValue = "Kontext"

// setAutostart makes daemon start with the daemon's subcommand at every
// sign-in of this user.
func setAutostart(daemon string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, autostartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(autostartValue, autostartCommand(daemon))
}

// removeAutostart takes the entry out again. No entry is not an error.
func removeAutostart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, autostartKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(autostartValue); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// autostartEntry reads the entry back, "" when there is none.
func autostartEntry() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, autostartKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(autostartValue)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return value, err
}

// startDetached starts program on its own: no console, not in this process's
// group, and not waited for, so it outlives the setup run that started it.
func startDetached(program string, args ...string) error {
	cmd := exec.Command(program, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
