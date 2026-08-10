// Package primemanaged installs the Kontext managed extension for Prime Agent
// (github.com/PrimeIntellect-ai/prime-agent). Prime Agent auto-discovers
// TypeScript extensions from ~/.prime/agent/extensions; the managed extension
// forwards lifecycle and tool events to `kontext hook --agent prime-agent`
// and enforces deny decisions at the synchronous tool_call boundary.
package primemanaged

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agenthooks"
)

//go:embed extension.ts
var extensionTemplate []byte

// managedMarker identifies extension files owned by kontext setup. Files
// without the marker are never overwritten or removed.
const managedMarker = "marker: kontext-managed-prime-agent-extension"

const binaryPlaceholder = "__KONTEXT_BINARY__"

// ExtensionFileName is the file kontext setup owns inside the Prime Agent
// extensions directory.
const ExtensionFileName = "kontext.ts"

// AgentConfigDir returns the Prime Agent user config directory. Its presence
// is how setup detects a Prime Agent installation.
func AgentConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".prime", "agent"), nil
}

// ExtensionsDir returns the Prime Agent global extensions directory.
func ExtensionsDir() (string, error) {
	configDir, err := AgentConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "extensions"), nil
}

// ExtensionPath returns the managed extension path without creating anything.
func ExtensionPath() (string, error) {
	dir, err := ExtensionsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ExtensionFileName), nil
}

// AgentInstalled reports whether a Prime Agent user config directory exists.
func AgentInstalled() (bool, error) {
	dir, err := AgentConfigDir()
	if err != nil {
		return false, err
	}
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// Render produces the managed extension contents for the given kontext binary.
func Render(kontextBinary string) ([]byte, error) {
	binary := strings.TrimSpace(kontextBinary)
	if binary == "" {
		return nil, errors.New("kontext binary path is empty")
	}
	if strings.ContainsAny(binary, "\\\"\n") {
		return nil, fmt.Errorf("kontext binary path %q contains unsupported characters", binary)
	}
	if !bytes.Contains(extensionTemplate, []byte(binaryPlaceholder)) {
		return nil, errors.New("extension template is missing the binary placeholder")
	}
	return bytes.ReplaceAll(extensionTemplate, []byte(binaryPlaceholder), []byte(binary)), nil
}

// IsManaged reports whether existing file contents are owned by kontext setup.
func IsManaged(data []byte) bool {
	return bytes.Contains(data, []byte(managedMarker))
}

// Install writes the managed extension, refusing to overwrite files that are
// not owned by kontext setup. It returns the path written.
func Install(kontextBinary string) (string, error) {
	path, err := ExtensionPath()
	if err != nil {
		return "", err
	}
	if existing, err := os.ReadFile(path); err == nil && !IsManaged(existing) {
		return "", fmt.Errorf("refusing to overwrite unmanaged extension at %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read existing extension: %w", err)
	}
	data, err := Render(kontextBinary)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create extensions directory: %w", err)
	}
	// Atomic replacement (temp file + rename): an interrupted reinstall must
	// never leave a truncated extension behind for Prime Agent to load.
	if err := agenthooks.WriteRawFile(path, data); err != nil {
		return "", fmt.Errorf("write extension: %w", err)
	}
	return path, nil
}

// Remove deletes the managed extension if present and owned by kontext setup.
// It reports whether a file was removed.
func Remove() (bool, error) {
	path, err := ExtensionPath()
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read extension: %w", err)
	}
	if !IsManaged(data) {
		return false, fmt.Errorf("refusing to remove unmanaged extension at %s", path)
	}
	if err := os.Remove(path); err != nil {
		return false, fmt.Errorf("remove extension: %w", err)
	}
	return true, nil
}
