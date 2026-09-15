package codexmanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// InstallationPaths describes the system and user hook layers. Diagnostics
// receive explicit paths so tests never inspect the host's managed policy.
type InstallationPaths struct {
	SystemHooks string
	UserHooks   string
	UserConfig  string
}

func DefaultInstallationPaths() (InstallationPaths, error) {
	home := os.Getenv("CODEX_HOME")
	if home == "" {
		userHome, err := os.UserHomeDir()
		if err != nil {
			return InstallationPaths{}, err
		}
		home = filepath.Join(userHome, ".codex")
	}
	return InstallationPaths{
		SystemHooks: "/etc/codex/hooks.json",
		UserHooks:   filepath.Join(home, "hooks.json"),
		UserConfig:  filepath.Join(home, "config.toml"),
	}, nil
}

var ErrIncompleteInstallation = errors.New("Kontext Codex hooks are incomplete")

type Installation struct {
	Paths  []string
	Binary string
}

// InspectInstallation reads both additive hook layers. Empty hook maps and foreign
// hooks do not hide a complete Kontext installation in the other layer. Invalid
// JSON and invalid Kontext commands are still reported, even beside valid hooks.
// This checks configuration, not Codex's runtime trust or approval state.
func InspectInstallation(paths InstallationPaths) (Installation, error) {
	result := Installation{}
	combined := Settings{Hooks: make(map[string][]MatcherGroup)}
	for _, path := range []string{paths.SystemHooks, paths.UserHooks} {
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return result, fmt.Errorf("read %s: %w", path, err)
		}
		var settings Settings
		if err := json.Unmarshal(raw, &settings); err != nil {
			return result, fmt.Errorf("parse %s: %w", path, err)
		}
		found := false
		for event, groups := range settings.Hooks {
			combined.Hooks[event] = append(combined.Hooks[event], groups...)
			for _, group := range groups {
				for _, handler := range group.Hooks {
					found = found || IsManagedHookCommand(handler.Command)
				}
			}
		}
		if found {
			result.Paths = append(result.Paths, path)
		}
	}
	raw, err := json.Marshal(combined)
	if err != nil {
		return result, err
	}
	result.Binary, err = ValidateInstalled(raw)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrIncompleteInstallation, err)
	}
	return result, nil
}
