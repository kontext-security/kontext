package codexmanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const SystemHooksPath = "/etc/codex/hooks.json"

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
		SystemHooks: SystemHooksPath,
		UserHooks:   filepath.Join(home, "hooks.json"),
		UserConfig:  filepath.Join(home, "config.toml"),
	}, nil
}

var ErrIncompleteInstallation = errors.New("Kontext Codex hooks are incomplete")

// Installation retains complete layers even when another layer is broken, so
// discovery can report wiring independently of doctor's stricter health check.
type Installation struct {
	Layers []InstallationLayer
}

type InstallationLayer struct {
	Path, Binary string
}

// InspectInstallation validates each additive layer independently. A complete
// layer cannot fill gaps in another one, and two installs need not use the same
// binary. Empty hook maps are inert; nonempty layers need valid Kontext hooks.
// This checks configuration, not Codex's runtime trust or approval state.
func InspectInstallation(paths InstallationPaths) (Installation, error) {
	result := Installation{}
	var problems []error
	for _, path := range []string{paths.SystemHooks, paths.UserHooks} {
		if path == "" {
			continue
		}
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("read %s: %w", path, err))
			continue
		}
		var settings Settings
		if err := json.Unmarshal(raw, &settings); err != nil {
			problems = append(problems, fmt.Errorf("parse %s: %w", path, err))
			continue
		}
		if settings.Hooks != nil && len(settings.Hooks) == 0 {
			continue
		}
		binary, err := ValidateInstalled(raw)
		if err != nil {
			problems = append(problems, fmt.Errorf("%w (%s): %v", ErrIncompleteInstallation, path, err))
			continue
		}
		result.Layers = append(result.Layers, InstallationLayer{Path: path, Binary: binary})
	}
	if len(result.Layers) == 0 && len(problems) == 0 {
		return result, ErrIncompleteInstallation
	}
	return result, errors.Join(problems...)
}
