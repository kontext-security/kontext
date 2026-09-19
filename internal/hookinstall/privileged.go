package hookinstall

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteClaudeFile installs the system drop-in, asking for elevation only when
// needed. Setup injects its existing process seams; hooks uses the same writer.
func WriteClaudeFile(path string, data []byte, euid int, run func(string, ...string) error) error {
	if euid == 0 {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		temp, err := os.CreateTemp(dir, ".managed-settings-*.tmp")
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

	temp, err := os.CreateTemp("", "kontext-managed-settings-*.json")
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
		return fmt.Errorf("create Claude managed settings directory: %w", err)
	}
	if err := run("sudo", "install", "-m", "0644", tempPath, path); err != nil {
		return fmt.Errorf("install Claude managed settings: %w", err)
	}
	return nil
}
