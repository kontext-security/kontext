package claudemanaged

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// User-level Claude Code settings (~/.claude/settings.json) integration for
// self-serve installs. Unlike the MDM managed-settings drop-in (root-owned,
// tamper-resistant), this file belongs to the user: the merge must preserve
// foreign JSON content (their hooks, permissions, env, unknown keys), be
// idempotent, and be cleanly reversible.

// UserSettingsPath resolves the active user settings and creates its directory.
func UserSettingsPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path, err := UserSettingsPathNoCreate(home)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// UserSettingsPathNoCreate honors Claude's configuration-directory override.
// Discovery, dry runs and daemon preflight must not create settings directories.
func UserSettingsPathNoCreate(home string) (string, error) {
	dir := os.Getenv("CLAUDE_CONFIG_DIR")
	if dir == "" {
		dir = filepath.Join(home, ".claude")
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("Claude configuration directory must be absolute: %s", dir)
	}
	return filepath.Join(dir, "settings.json"), nil
}

// CanonicalManagedHooks checks the complete owned groups, including command
// spelling, matcher, timeout and extra handler fields. Claude deduplicates equal
// handlers across settings sources, but semantically equivalent commands or
// different timeout values can execute twice. Foreign groups are ignored.
func CanonicalManagedHooks(data []byte, binary string) bool {
	return UserHooksMatch(data, binary)
}

// UserHooksMatch reports whether data's Kontext handlers are exactly the ones
// MergeManagedHooksMirroring writes for binary and the machine-wide sources.
func UserHooksMatch(data []byte, binary string, machine ...[]byte) bool {
	var settings map[string]any
	if json.Unmarshal(data, &settings) != nil || settings == nil {
		return false
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	owned := map[string]any{}
	for _, event := range SupportedEvents {
		name := event.Name.String()
		groups, _ := hooks[name].([]any)
		var ownedGroups []any
		for _, raw := range groups {
			group, _ := raw.(map[string]any)
			handlers, _ := group["hooks"].([]any)
			var ownedHandlers []any
			for _, handler := range handlers {
				// Use the same command/args ownership rules as installation.
				probe := map[string]any{name: []any{map[string]any{"hooks": []any{handler}}}}
				if agenthooks.HasCommand(probe, isManagedHookHandler) {
					ownedHandlers = append(ownedHandlers, handler)
				}
			}
			if len(ownedHandlers) > 0 {
				next := maps.Clone(group)
				next["hooks"] = ownedHandlers
				ownedGroups = append(ownedGroups, next)
			}
		}
		owned[name] = ownedGroups
	}
	canonical, err := agenthooks.ToJSONAny(expectedUserHooks(binary, machine).Hooks)
	return err == nil && reflect.DeepEqual(owned, canonical)
}

// RunnableEvents lists the events data carries a valid Kontext hook for whose
// binary exists and is executable.
func RunnableEvents(data []byte) map[string]bool {
	var settings Settings
	covered := map[string]bool{}
	if json.Unmarshal(data, &settings) != nil {
		return covered
	}
	for _, event := range SupportedEvents {
		for _, group := range settings.Hooks[event.Name.String()] {
			for _, handler := range group.Hooks {
				// A handler with an `if` condition runs for some calls only.
				if binary, ok := kontextHook(group, handler, event); ok && runnable(binary) && validateAsync(event, handler.Async) == nil && handler.Extra["if"] == nil {
					covered[event.Name.String()] = true
				}
			}
		}
	}
	return covered
}

// kontextHook returns the binary of a Kontext hook for event: a command
// handler for every tool that runs `<dir>/kontext hook <alias>`, as one command
// string or as a command with args.
func kontextHook(group MatcherGroup, handler Handler, event Event) (string, bool) {
	if handler.Type != "command" || !isAllMatcher(group.Matcher) {
		return "", false
	}
	fields, ok := agenthooks.SplitCommand(handler.Command)
	if len(handler.Args) > 0 {
		// Exec form: command is the executable's path, not a shell line.
		fields, ok = commandHandlerFields(agenthooks.CommandHandler{Command: handler.Command, Args: handler.Args})
	}
	if !ok || len(fields) != 3 || filepath.Base(fields[0]) != "kontext" || fields[1] != "hook" || fields[2] != event.Alias {
		return "", false
	}
	return fields[0], true
}

// MachineSettingsFiles lists the machine-wide files Claude Code merges hooks
// from, in its merge order: managedSettings, then every JSON drop-in in
// dropIn's folder by name (Claude skips hidden ones). dropIn is always listed,
// so a broken one is noticed.
func MachineSettingsFiles(dropIn, managedSettings string) []string {
	files := []string{managedSettings}
	// Listing a folder linked into ~/Documents or iCloud would prompt for access.
	if privacyfolder.Guarded("", filepath.Dir(dropIn)) {
		return append(files, dropIn)
	}
	entries, err := os.ReadDir(filepath.Dir(dropIn))
	if err != nil {
		return append(files, dropIn)
	}
	for _, entry := range entries {
		path := filepath.Join(filepath.Dir(dropIn), entry.Name())
		if path == dropIn || !entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") && strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, path)
		}
	}
	return files
}

// KontextBinaries lists the distinct binaries data's Kontext hook commands name.
func KontextBinaries(data []byte) []string {
	var settings Settings
	if json.Unmarshal(data, &settings) != nil {
		return nil
	}
	var binaries []string
	for _, event := range SupportedEvents {
		for _, group := range settings.Hooks[event.Name.String()] {
			for _, handler := range group.Hooks {
				if binary, ok := kontextHook(group, handler, event); ok && !slices.Contains(binaries, binary) {
					binaries = append(binaries, binary)
				}
			}
		}
	}
	return binaries
}

// expectedUserHooks is Template(binary), except that each event a machine-wide
// source already hooks with a runnable Kontext handler repeats that exact
// handler. Claude runs a handler present in two sources once only when both
// are identical.
func expectedUserHooks(binary string, machine [][]byte) Settings {
	// Events machine-wide settings lack use that binary too, so every handler
	// in the user copy names one executable, as doctor expects.
	for _, data := range machine {
		if machineBinary, ok := ManagedObserveHookBinary(data); ok && runnable(machineBinary) {
			binary = machineBinary
			break
		}
		if _, machineBinary := MissingRequiredEvents(data); machineBinary != "" && runnable(machineBinary) {
			binary = machineBinary
			break
		}
	}
	expected := Template(binary)
	for _, data := range machine {
		var settings Settings
		if json.Unmarshal(data, &settings) != nil {
			continue
		}
		for _, event := range SupportedEvents {
			for _, group := range settings.Hooks[event.Name.String()] {
				for _, handler := range group.Hooks {
					// Repeat it exactly, whatever binary it names: a machine-wide
					// source with another binary (managed-settings.json next to an
					// earlier drop-in) still runs, and a differing copy runs twice.
					if binary, ok := kontextHook(group, handler, event); !ok || !runnable(binary) {
						continue
					}
					expected.Hooks[event.Name.String()] = []MatcherGroup{{Matcher: group.Matcher, Hooks: []Handler{handler}}}
				}
			}
		}
	}
	return expected
}

func runnable(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0
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

// MergeManagedHooks installs/refreshes the managed-observe hooks in the
// settings map: for each supported event it removes any existing Kontext
// managed handlers (stale binary paths included) and appends the canonical
// group from Template. Everything else in the map is untouched. Idempotent:
// merging twice is a fixpoint. Returns non-fatal warnings for conditions the
// user should know about.
func MergeManagedHooks(settings map[string]any, kontextBinary string) ([]string, error) {
	return MergeManagedHooksMirroring(settings, kontextBinary)
}

// MergeManagedHooksMirroring is MergeManagedHooks, except that each event a
// machine-wide source (Claude's managed drop-in or managed-settings.json)
// already hooks with a runnable Kontext handler gets that exact handler, so
// Claude runs it once.
func MergeManagedHooksMirroring(settings map[string]any, kontextBinary string, machine ...[]byte) ([]string, error) {
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
	plan := managedHookPlanFrom(expectedUserHooks(kontextBinary, machine))
	if err := plan.Validate(); err != nil {
		return nil, err
	}

	if err := config.Merge(plan, isManagedHookHandler); err != nil {
		return nil, err
	}
	return warnings, nil
}

func managedHookPlan(kontextBinary string) agenthooks.Plan {
	return managedHookPlanFrom(Template(kontextBinary))
}

func managedHookPlanFrom(settings Settings) agenthooks.Plan {
	events := make(map[hook.HookName]agenthooks.EventPlan, len(SupportedEvents))
	for _, event := range SupportedEvents {
		group := settings.Hooks[event.Name.String()][0]
		handler := group.Hooks[0]
		events[event.Name] = agenthooks.EventPlan{
			Match: agenthooks.MatchSpec{
				Pattern: group.Matcher,
			},
			Command:   agenthooks.CommandHook{Command: handler.Command, Args: handler.Args, Timeout: handler.Timeout, Async: handler.Async, Extra: handler.Extra},
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
