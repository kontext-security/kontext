package hookinstall

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

// Diagnose uses the same definitions for both installation channels. Agent
// presence comes from executables/apps, never the inert files we install.
func Diagnose(out io.Writer, scope Scope, home string) bool {
	defs, err := Definitions(scope, home)
	if err != nil {
		fmt.Fprintf(out, "Hooks: %v\n", err)
		return false
	}
	userConfig := filepath.Join(home, ".codex", "config.toml")
	if codexHome := os.Getenv("CODEX_HOME"); codexHome != "" {
		userConfig = filepath.Join(codexHome, "config.toml")

	}
	otherHooks := codexmanaged.SystemHooksPath
	if scope == System {
		otherHooks = filepath.Join(filepath.Dir(userConfig), "hooks.json")
	}
	return diagnose(out, defs, func(agent string) bool { return AgentPresent(agent, home) }, userConfig, otherHooks)
}

func diagnose(out io.Writer, defs []Definition, present func(string) bool, userConfig, otherCodexHooks string) bool {
	healthy := true
	for _, def := range defs {
		if !present(def.Agent) {
			fmt.Fprintf(out, "%s hooks: not installed (agent not present)\n", def.Name)
			continue
		}
		for _, file := range def.Files {
			if file.Kind == "feature" {
				if err := checkFeature(file.Path, userConfig); err != nil {
					fmt.Fprintf(out, "%s hooks feature: %v\n", def.Name, err)
					healthy = false
				} else {
					fmt.Fprintf(out, "%s hooks feature: enabled (%s)\n", def.Name, file.Path)
				}
				continue
			}
			raw, err := os.ReadFile(file.Path)
			binary := ""
			if err == nil {
				binary, err = def.Validate(raw)
			}
			if err == nil && !executable(binary) {
				err = fmt.Errorf("configured binary is not executable (%s)", binary)
			}
			if err != nil {
				fmt.Fprintf(out, "%s hooks: %v (%s)\n", def.Name, err, file.Path)
				healthy = false
			} else {
				fmt.Fprintf(out, "%s hooks: installed (%s; binary %s)\n", def.Name, file.Path, binary)
				if def.Agent == "codex" && otherCodexHooks != "" {
					installation, err := codexmanaged.InspectInstallation(codexmanaged.InstallationPaths{SystemHooks: file.Path, UserHooks: otherCodexHooks})
					if err != nil {
						fmt.Fprintf(out, "Codex hooks: %v\n", err)
						healthy = false
					}
					for _, layer := range installation.Layers {
						if layer.Path == file.Path {
							continue
						}
						if !executable(layer.Binary) {
							fmt.Fprintf(out, "Codex hooks: configured binary is not executable (%s; binary %s)\n", layer.Path, layer.Binary)
							healthy = false
						} else if layer.Binary != binary {
							path := layer.Path
							if home, err := os.UserHomeDir(); err == nil && path == filepath.Join(home, ".codex", "hooks.json") {
								path = "~/.codex/hooks.json"
							}
							fmt.Fprintf(out, "Codex hooks: another Kontext install also hooks Codex (%s → %s); run kontext setup --uninstall on an organization-managed Mac\n", path, layer.Binary)
							// Match the existing both-scopes LaunchAgent warning's health effect.
							healthy = false
						}
					}
				}
			}
		}
	}
	return healthy
}

func checkFeature(installed, user string) error {
	raw, err := os.ReadFile(installed)
	if err != nil {
		return err
	}
	enabled, _, err := codexmanaged.HooksFeature(string(raw))
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("disabled (set [features].hooks = true in %s)", installed)
	}
	if user != installed {
		raw, err = os.ReadFile(user)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil {
			value, set, err := codexmanaged.HooksFeature(string(raw))
			if err != nil {
				return err
			}
			if set && !value {
				return fmt.Errorf("disabled by user override (%s)", user)
			}
		}
	}
	return nil
}

func executable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0111 != 0
}

func AgentPresent(agent, home string) bool {
	command, app := "claude", "Claude.app"
	if agent == "codex" {
		command, app = "codex", "Codex.app"
	}
	if _, err := exec.LookPath(command); err == nil {
		return true
	}
	for _, dir := range []string{"/opt/homebrew/bin", "/usr/local/bin", filepath.Join(home, ".local", "bin")} {
		if executable(filepath.Join(dir, command)) {
			return true
		}
	}
	for _, dir := range []string{"/Applications", filepath.Join(home, "Applications")} {
		if info, err := os.Stat(filepath.Join(dir, app)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}
