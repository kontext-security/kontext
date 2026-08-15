package claudemanaged

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/agenthooks"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

// User-level Claude Code settings (~/.claude/settings.json) integration for
// self-serve installs. Unlike the MDM managed-settings drop-in (root-owned,
// tamper-resistant), this file belongs to the user: the merge must preserve
// foreign JSON content (their hooks, permissions, env, unknown keys), be
// idempotent, and be cleanly reversible.

// UserSettingsPath returns ~/.claude/settings.json, creating ~/.claude.
func UserSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(claudeDir, "settings.json"), nil
}

// ReadUserSettings parses the settings file into a generic map so unknown
// keys survive a read-merge-write round trip. A missing file is an empty map.
func ReadUserSettings(path string) (map[string]any, error) {
	return agenthooks.ReadJSONFile(path, "Claude settings")
}

// WriteUserSettings writes the settings back atomically (temp file + rename,
// so a crash mid-write can never leave a truncated settings.json behind),
// preserving the existing file's permission bits (a user may keep their
// settings private); new files are created 0600.
func WriteUserSettings(path string, settings map[string]any) error {
	return agenthooks.WriteJSONFile(path, settings)
}

// BackupUserSettings copies the file aside (timestamped, same permissions)
// before a mutation. Missing file is a no-op.
func BackupUserSettings(path, label string) error {
	return agenthooks.BackupFile(path, label)
}

// IsGuardHookCommand reports whether a hook command belongs to Kontext Guard
// (the local-only enforcement product). Shared with guard/cli so the two
// installers agree on whose entries are whose.
func IsGuardHookCommand(command string) bool {
	normalized := strings.ReplaceAll(command, "'", "")
	return strings.Contains(normalized, "kontext guard hook claude-code") ||
		(strings.Contains(normalized, "kontext hook --agent claude") && strings.Contains(normalized, "--mode"))
}

// IsManagedHookCommand reports whether a hook command is one of OURS: the
// flagless managed-observe form `'<binary>' hook '<alias>'`. Guard hooks
// (`kontext guard hook claude-code`, `kontext hook --agent claude … --mode …`)
// are deliberately excluded so the two installers never touch each other's
// entries. Matching on the alias rather than the exact binary path means a
// re-run after the binary moved (brew prefix change) replaces stale entries.
func IsManagedHookCommand(command string) bool {
	fields, ok := agenthooks.SplitCommand(command)
	if !ok {
		return false
	}
	return isManagedHookFields(fields)
}

func isGuardHookHandler(handler agenthooks.CommandHandler) bool {
	if len(handler.Args) == 0 {
		return IsGuardHookCommand(handler.Command)
	}
	fields, ok := commandHandlerFields(handler)
	if !ok {
		return false
	}
	return isGuardHookFields(fields)
}

func isManagedHookHandler(handler agenthooks.CommandHandler) bool {
	if len(handler.Args) == 0 {
		return IsManagedHookCommand(handler.Command)
	}
	fields, ok := commandHandlerFields(handler)
	if !ok {
		return false
	}
	return isManagedHookFields(fields)
}

func commandHandlerFields(handler agenthooks.CommandHandler) ([]string, bool) {
	command := strings.TrimSpace(handler.Command)
	if command == "" {
		return nil, false
	}
	if fields, ok := agenthooks.SplitCommand(command); ok && len(fields) == 1 {
		command = fields[0]
	}
	fields := make([]string, 0, 1+len(handler.Args))
	fields = append(fields, command)
	fields = append(fields, handler.Args...)
	return fields, true
}

func isGuardHookFields(fields []string) bool {
	if len(fields) < 4 || filepath.Base(fields[0]) != "kontext" {
		return false
	}
	if fields[1] == "guard" && fields[2] == "hook" && fields[3] == "claude-code" {
		return true
	}
	if fields[1] != "hook" || fields[2] != "--agent" || fields[3] != "claude" {
		return false
	}
	for _, field := range fields[4:] {
		if field == "--mode" {
			return true
		}
	}
	return false
}

func isManagedHookFields(fields []string) bool {
	if len(fields) != 3 {
		return false
	}
	for _, field := range fields {
		if strings.HasPrefix(field, "--") {
			return false
		}
	}
	if filepath.Base(fields[0]) != "kontext" || fields[1] != "hook" {
		return false
	}
	for _, event := range SupportedEvents {
		if fields[2] == event.Alias {
			return true
		}
	}
	return false
}

// MergeManagedHooks installs/refreshes the five managed-observe hooks in the
// settings map: for each supported event it removes any existing Kontext
// managed handlers (stale binary paths included) and appends the canonical
// group from Template. Everything else in the map is untouched. Idempotent:
// merging twice is a fixpoint. Returns non-fatal warnings for conditions the
// user should know about.
func MergeManagedHooks(settings map[string]any, kontextBinary string) ([]string, error) {
	var warnings []string

	if disabled, ok := settings["disableAllHooks"].(bool); ok && disabled {
		warnings = append(warnings, "Claude Code hooks are globally disabled (disableAllHooks) in settings.json; Kontext hooks will not fire until you remove that setting")
	}

	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "settings.json hooks",
	}
	hooks, err := config.HooksMap()
	if err != nil {
		return nil, err
	}

	if agenthooks.HasCommand(hooks, isGuardHookHandler) {
		warnings = append(warnings, "Kontext Guard hooks are also installed; consider `kontext guard hooks uninstall claude-code` to avoid duplicate processing")
	}

	// Build the typed plan before touching the map, so an error can
	// never leave the caller's settings half-merged.
	plan := managedHookPlan(kontextBinary)
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	if err := config.Merge(plan, isManagedHookHandler); err != nil {
		return nil, err
	}
	return warnings, nil
}

func managedHookPlan(kontextBinary string) agenthooks.Plan {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}

	events := make(map[hook.HookName]agenthooks.EventPlan, len(SupportedEvents))
	for _, event := range SupportedEvents {
		handler := agenthooks.CommandHook{
			Command: hookCommand(kontextBinary, event.Alias),
			Timeout: eventTimeout(event),
		}
		if event.Async {
			value := true
			handler.Async = &value
		}
		events[event.Name] = agenthooks.EventPlan{
			Match: agenthooks.MatchSpec{
				Pattern: "",
			},
			Command:   handler,
			Placement: agenthooks.PlacementAppend,
		}
	}

	return agenthooks.Plan{
		Version:  agenthooks.SchemaVersionV1,
		Provider: agenthooks.ProviderClaudeCode,
		Owner:    agenthooks.OwnerKontextManagedObserve,
		Events:   events,
	}
}

// RemoveManagedHooks strips OUR handlers (and only ours) from the settings
// map, pruning groups and event keys that end up empty. Foreign hooks,
// including Guard's, survive untouched. Idempotent.
func RemoveManagedHooks(settings map[string]any) error {
	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "settings.json hooks",
	}
	return config.Remove(managedHookPlan(DefaultKontextBinary), isManagedHookHandler)
}
