package hookinstall

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/hook"
)

// promptHookMissing explains what an installed hook set without
// UserPromptSubmit costs: no turn is minted, so nothing is attributed to one.
const promptHookMissing = "prompt hook missing: turns and type of work unavailable"

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
	healthy := diagnose(out, scope, defs, func(agent string) bool { return AgentPresent(agent, home) }, userConfig, otherHooks)
	if scope == User {
		fmt.Fprintln(out, "Hook repair: with a Homebrew install, the background agent restores removed Kontext hooks within a minute; `kontext setup --uninstall` switches Kontext off")
	}
	if AgentPresent("claude_code", home) {
		userPath, err := claudemanaged.UserSettingsPathNoCreate(home)
		if err != nil {
			fmt.Fprintf(out, "Claude Code hook sources: %v\n", err)
			return false
		}
		if !diagnoseClaudeSources(out, claudemanaged.ManagedSettingsDropInPath, userPath) {
			healthy = false
		}
		if scope == User {
			if CoworkGoverned(machineClaudeDropIn, filepath.Join(filepath.Dir(filepath.Dir(machineClaudeDropIn)), "managed-settings.json")) {
				fmt.Fprintln(out, "Cowork hooks: installed (machine-wide Claude settings from an earlier setup or your organization)")
			} else {
				fmt.Fprintln(out, "Cowork hooks: not governed. Cowork reads only machine-wide Claude settings, which need an organization install")
			}
		}
	}
	return healthy
}

// diagnoseCursorLayers checks the events both Cursor files cover together: a
// self-serve user file leaves out what an earlier machine-wide file covers.
func diagnoseCursorLayers(out io.Writer, user, machine string) bool {
	covered := map[string]string{}
	var twice []string
	for _, path := range []string{machine, user} {
		if raw, err := os.ReadFile(path); err == nil {
			for event, binary := range cursormanaged.Coverage(raw) {
				if !executable(binary) {
					continue
				}
				if covered[event] != "" {
					twice = append(twice, event)
				}
				covered[event] = path
			}
		}
	}
	if len(twice) > 0 {
		slices.Sort(twice)
		fmt.Fprintf(out, "Cursor hooks: %s run twice, from %s and %s. Run `kontext hooks install --scope user` to drop the user copies.\n", strings.Join(twice, ", "), machine, user)
		return false
	}
	var missing []string
	files := map[string]bool{}
	for _, event := range cursormanaged.Events {
		if covered[event.Cursor] == "" {
			missing = append(missing, event.Cursor)
		}
		files[covered[event.Cursor]] = true
	}
	if len(missing) > 0 {
		fmt.Fprintf(out, "Cursor hooks: missing %s (%s). Run `kontext hooks install --scope user`.\n", strings.Join(missing, ", "), user)
		return false
	}
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	fmt.Fprintf(out, "Cursor hooks: installed (%s)\n", strings.Join(paths, ", "))
	return true
}

// CoworkGoverned reports whether Claude's machine-wide managed settings carry
// the complete Kontext hook set. Cowork starts Claude with a per-session
// CLAUDE_CONFIG_DIR, so only those reach it; self-serve never writes them, but
// a drop-in from an earlier setup or an organization's settings still govern it.
func CoworkGoverned(dropin, managedSettings string) bool {
	var sources [][]byte
	covered := map[string]bool{}
	for _, path := range claudemanaged.MachineSettingsFiles(dropin, managedSettings) {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		sources = append(sources, raw)
		// Hooks that name a binary an upgrade or uninstall removed cannot run.
		for event := range claudemanaged.RunnableEvents(raw) {
			covered[event] = true
		}
	}
	return !claudemanaged.MachineHooksDisabled(sources) && len(covered) == len(claudemanaged.SupportedEvents)
}

func diagnose(out io.Writer, scope Scope, defs []Definition, present func(string) bool, userConfig, otherCodexHooks string) bool {
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
			if def.Agent == "codex" {
				if !diagnoseCodexHooks(out, scope, file.Path, otherCodexHooks) {
					healthy = false
				}
				continue
			}
			if def.Agent == "cursor" && file.Scope == User {
				if !diagnoseCursorLayers(out, file.Path, machineCursorHooks) {
					healthy = false
				}
				continue
			}
			raw, err := os.ReadFile(file.Path)
			binary := ""
			if err == nil {
				binary, err = def.Validate(raw)
			}
			var machine [][]byte
			if file.Kind == "claude-user" {
				machine = machineClaudeSources(Options{})
				// Handlers mirrored from machine-wide sources that name different
				// binaries are correct, though no single binary validates them.
				if err != nil {
					if mirrored, ok := mirroredClaudeBinary(raw, machine); ok {
						binary, err = mirrored, nil
					}
				}
			}
			if err == nil && !executable(binary) {
				err = fmt.Errorf("configured binary is not executable (%s)", binary)
			}
			if err != nil {
				healthy = false
				if def.Agent == "claude_code" {
					missing, binary := claudemanaged.MissingRequiredEvents(raw)
					info, statErr := os.Lstat(file.Path)
					if len(missing) > 0 && executable(binary) && statErr == nil && info.Mode().IsRegular() {
						prefix := ""
						if scope == System {
							prefix = "sudo "
						}
						fmt.Fprintf(out, "%s hooks: out of date (missing %s). Run `%s%s hooks install --scope %s --binary %s`.\n", def.Name, strings.Join(missing, ", "), prefix, agenthooks.ShellQuote(binary), scope, agenthooks.ShellQuote(binary))
						if slices.Contains(missing, hook.HookUserPromptSubmit.String()) {
							fmt.Fprintf(out, "%s hooks: %s\n", def.Name, promptHookMissing)
						}
						continue
					}
				}
				fmt.Fprintf(out, "%s hooks: %v (%s)\n", def.Name, err, file.Path)
			} else {
				fmt.Fprintf(out, "%s hooks: installed (%s; binary %s)\n", def.Name, file.Path, binary)
				if file.Kind == "claude-user" && !diagnoseClaudeUser(out, file.Path, binary, machine) {
					healthy = false
				}
			}
		}
	}
	return healthy
}

// Both Codex hook layers are additive, and Codex runs a hook found in both
// twice. Self-serve leaves out of the user file what a runnable machine-wide
// hook covers, so together the layers must run each event once; a malformed
// layer or a missing event still fails. Validate both before choosing the
// installed binary instead of requiring the daemon's setup scope to contain
// hooks of its own.
func diagnoseCodexHooks(out io.Writer, scope Scope, preferred, other string) bool {
	installation, err := codexmanaged.InspectInstallation(codexmanaged.InstallationPaths{SystemHooks: preferred, UserHooks: other})
	healthy := err == nil
	if err != nil {
		fmt.Fprintf(out, "Codex hooks: %v\n", err)
	}
	if missing := installation.Missing(); len(installation.Layers) > 0 && slices.Contains(missing, hook.HookUserPromptSubmit.String()) {
		files := make([]string, len(installation.Layers))
		for i, layer := range installation.Layers {
			files[i] = layer.Path
		}
		fmt.Fprintf(out, "Codex hooks: %s (%s)\n", promptHookMissing, strings.Join(files, ", "))
	}
	runs := map[string]int{}
	var twice []string
	var repeated codexmanaged.InstallationLayer
	for _, layer := range installation.Layers {
		if !executable(layer.Binary) {
			fmt.Fprintf(out, "Codex hooks: configured binary is not executable (%s; binary %s)\n", layer.Path, layer.Binary)
			healthy = false
			continue
		}
		fmt.Fprintf(out, "Codex hooks: installed (%s; binary %s)\n", layer.Path, layer.Binary)
		// Codex skips a user hook the user has not trusted in the Codex CLI's
		// /hooks; the trust lives in config.toml next to hooks.json.
		if layer.Path != codexmanaged.SystemHooksPath {
			untrusted, err := codexmanaged.UntrustedHooks(layer.Path, filepath.Join(filepath.Dir(layer.Path), "config.toml"))
			switch {
			case err != nil:
				fmt.Fprintf(out, "Codex hook trust: unknown (%v)\n", err)
			case len(untrusted) > 0:
				fmt.Fprintf(out, "Codex hooks: not trusted in Codex (%s); Codex skips them until you run `codex`, open /hooks and trust each Kontext hook\n", strings.Join(untrusted, ", "))
			}
		}
		for _, event := range layer.Events {
			if runs[event]++; runs[event] == 2 {
				twice = append(twice, event)
				repeated = layer
			}
		}
	}
	if len(twice) == 0 {
		return healthy
	}
	if scope == User {
		fmt.Fprintf(out, "Codex hooks: %s run twice, from %s and %s. Run `kontext hooks install --scope user` to drop the user copies.\n", strings.Join(twice, ", "), other, preferred)
	} else {
		path := repeated.Path
		if home, err := os.UserHomeDir(); err == nil && path == filepath.Join(home, ".codex", "hooks.json") {
			path = "~/.codex/hooks.json"
		}
		fmt.Fprintf(out, "Codex hooks: another Kontext install also hooks Codex (%s → %s); run kontext setup --uninstall on an organization-managed Mac\n", path, repeated.Binary)
	}
	return false
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
	switch agent {
	case "codex":
		command, app = "codex", "Codex.app"
	case "cursor":
		command, app = "cursor-agent", "Cursor.app"
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
