package hookinstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteSystemFile installs a machine-wide hook file (Claude's drop-in, Cursor's
// hooks.json), asking for elevation only when needed. Setup injects its
// existing process seams; hooks uses the same writer.
func WriteSystemFile(path string, data []byte, euid int, run func(string, ...string) error) error {
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
