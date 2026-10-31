package codexmanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

// Installation retains valid layers even when another layer is broken, so
// discovery can report wiring independently of doctor's stricter health check.
type Installation struct {
	Layers []InstallationLayer
}

type InstallationLayer struct {
	Path, Binary string
	// Events lists the hooks.json events the layer's Kontext hooks cover.
	Events []string
}

// Missing lists the events no layer covers.
func (i Installation) Missing() []string {
	var missing []string
	for _, event := range SupportedEvents {
		if !slices.ContainsFunc(i.Layers, func(layer InstallationLayer) bool { return slices.Contains(layer.Events, event.Name.String()) }) {
			missing = append(missing, event.Name.String())
		}
	}
	return missing
}

// Complete reports whether the layers together cover every event.
func (i Installation) Complete() bool { return len(i.Missing()) == 0 }

// InspectInstallation validates both additive layers. Codex runs the hooks of
// both, so self-serve leaves out of the user file the events a machine-wide
// file covers; together the layers need every event, and two installs need not
// use the same binary. A layer without Kontext hooks is inert; one Codex cannot
// load or with an invalid Kontext hook fails. This checks configuration, not
// Codex's runtime trust or approval state.
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
		if err := loadable(raw); err != nil {
			problems = append(problems, fmt.Errorf("parse %s: %w", path, err))
			continue
		}
		binary, covered, invalid := inspect(settings, false)
		if len(invalid) > 0 {
			problems = append(problems, fmt.Errorf("%w (%s): %s", ErrIncompleteInstallation, path, strings.Join(invalid, "; ")))
			continue
		}
		layer := InstallationLayer{Path: path, Binary: binary}
		for _, event := range SupportedEvents {
			if covered[event.Name.String()] != "" {
				layer.Events = append(layer.Events, event.Name.String())
			}
		}
		if len(layer.Events) > 0 {
			result.Layers = append(result.Layers, layer)
		}
	}
	if len(result.Layers) == 0 && len(problems) == 0 {
		return result, ErrIncompleteInstallation
	}
	if missing := result.Missing(); len(result.Layers) > 0 && len(missing) > 0 {
		files := make([]string, len(result.Layers))
		for i, layer := range result.Layers {
			files[i] = layer.Path
		}
		problems = append(problems, fmt.Errorf("%w (%s): missing %s", ErrIncompleteInstallation, strings.Join(files, ", "), strings.Join(missing, ", ")))
	}
	return result, errors.Join(problems...)
}
