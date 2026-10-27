package hookinstall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// WriteSystemFile installs a machine-wide hook file (Claude's drop-in, Cursor's
// hooks.json), asking for elevation only when needed. Setup injects its
// existing process seams; hooks uses the same writer. unchanged, when set, runs
// after the password prompt (see authorize).
func WriteSystemFile(path string, data []byte, euid int, run func(string, ...string) error, unchanged func() error) error {
	if euid == 0 {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		temp, err := os.CreateTemp(dir, ".kontext-hooks-*.tmp")
		if err != nil {
			return err
		}
		tempPath := temp.Name()
		defer os.Remove(tempPath)
		if err := temp.Chmod(0o644); err != nil {
			temp.Close()
			return err
		}
		if _, err := temp.Write(data); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Sync(); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Close(); err != nil {
			return err
		}
		if err := os.Rename(tempPath, path); err != nil {
			return err
		}
		return os.Chmod(path, 0o644)
	}

	if err := authorize(run, unchanged); err != nil {
		return err
	}
	temp, err := os.CreateTemp("", "kontext-hooks-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := run("sudo", "mkdir", "-p", filepath.Dir(path)); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	if err := run("sudo", "install", "-m", "0644", tempPath, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	return nil
}

// RemoveSystemFile removes a machine-wide hook file, asking for elevation only
// when needed.
func RemoveSystemFile(path string, euid int, run func(string, ...string) error, unchanged func() error) error {
	if euid == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := authorize(run, unchanged); err != nil {
		return err
	}
	return run("sudo", "rm", "-f", path)
}

// authorize asks for the administrator password before unchanged runs, so a
// change an administrator or MDM made while sudo waited is not overwritten.
// ponytail: the check and the sudo write are still two steps; a change in the
// milliseconds between them is not caught.
func authorize(run func(string, ...string) error, unchanged func() error) error {
	if unchanged == nil {
		return nil
	}
	if err := run("sudo", "-v"); err != nil {
		return fmt.Errorf("administrator authorization: %w", err)
	}
	return unchanged()
}
