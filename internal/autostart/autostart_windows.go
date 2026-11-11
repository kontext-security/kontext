//go:build windows

package autostart

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// The user's own Run key: what it lists starts at that user's sign-in.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// Value names the entry. A variable so a test writes one of its own and never
// the entry of a real install.
var Value = "Kontext"

// Set makes daemon start with the daemon's subcommand at every sign-in of
// this user.
func Set(daemon string) error {
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(Value, Command(daemon))
}

// Remove takes the entry out again. No entry is not an error.
func Remove() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(Value); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// Entry reads the entry back, "" when there is none.
func Entry() (string, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer key.Close()
	value, _, err := key.GetStringValue(Value)
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return value, err
}
