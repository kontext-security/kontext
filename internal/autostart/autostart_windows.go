//go:build windows

package autostart

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// The user's own Run key: what it lists starts at that user's sign-in.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// installValue names the entry of an install.
const installValue = "Kontext"

// Value names the entry. A variable so a test writes one of its own and never
// the entry of a real install.
var Value = installValue

// errUnderTest is what a test gets that would write an install's entry.
var errUnderTest = errors.New("a test must not touch the sign-in entry of a real install")

// installEntryOffLimits keeps tests off the entry of the machine they run
// on: a test's home does not cover the registry. A test that means to use
// the registry names an entry of its own in Value.
func installEntryOffLimits() bool { return underTest() && Value == installValue }

// Set makes daemon start with the daemon's subcommand at every sign-in of
// this user.
func Set(daemon string) error {
	if installEntryOffLimits() {
		return errUnderTest
	}
	key, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.SetStringValue(Value, Command(daemon))
}

// Remove takes the entry out again. No entry is not an error.
func Remove() error {
	if installEntryOffLimits() {
		return errUnderTest
	}
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
	// To a test, a machine has no install.
	if installEntryOffLimits() {
		return "", nil
	}
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
