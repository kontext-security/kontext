// Package cursormanaged owns Kontext's entries in Cursor's machine-wide
// hooks.json. Cursor 2.4+ reads it before team, project and user hooks; a deny
// from any source blocks the call, and a user cannot turn the file off.
package cursormanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
)

const (
	DefaultKontextBinary = "/usr/local/bin/kontext"
	DefaultHookTimeout   = 20
)

// SystemHooksPath is Cursor's enterprise hooks file on macOS, the only
// platform managed installs target (like Claude Code's managed settings).
// ponytail: Linux reads /etc/cursor/hooks.json; add it with Linux packages.
const SystemHooksPath = "/Library/Application Support/Cursor/hooks.json"

// Events lists the Cursor events Kontext registers and the Kontext event
// alias each one runs. preToolUse/postToolUse also fire for MCP calls without
// the server name; the adapter skips those and decides MCP calls on
// beforeMCPExecution instead. No matcher is set: a matcher Cursor cannot parse
// would invalidate the whole enterprise file.
var Events = []struct{ Cursor, Alias string }{
	{"sessionStart", "session-start"},
	{"sessionEnd", "session-end"},
	{"beforeSubmitPrompt", "user-prompt-submit"},
	{"preToolUse", "pre-tool-use"},
	{"beforeMCPExecution", "pre-tool-use"},
	{"postToolUse", "post-tool-use"},
	{"afterMCPExecution", "post-tool-use"},
	{"postToolUseFailure", "post-tool-use-failure"},
	{"stop", "stop"},
}

func hookCommand(kontextBinary, alias string) string {
	return agenthooks.ShellQuote(kontextBinary) + " hook --agent " + agenthooks.ShellQuote("cursor") + " " + agenthooks.ShellQuote(alias)
}

// IsManagedHookCommand matches on the agent and alias rather than the binary
// path, so an install replaces entries left by a moved binary. Only literal
// words count: "audit;/usr/local/bin/kontext hook …" belongs to an
// administrator, while a quoted path such as '/Applications/Kontext (Dev)/kontext'
// is ours.
func IsManagedHookCommand(command string) bool {
	fields, ok := agenthooks.SplitLiteralCommand(command)
	if !ok || len(fields) != 5 {
		return false
	}
	if !filepath.IsAbs(fields[0]) || filepath.Base(fields[0]) != "kontext" ||
		fields[1] != "hook" || fields[2] != "--agent" || fields[3] != "cursor" {
		return false
	}
	for _, event := range Events {
		if fields[4] == event.Alias {
			return true
		}
	}
	return false
}

// MergeManagedHooks replaces Kontext's entries and keeps every other hook,
// including other entries an administrator put in the same file.
func MergeManagedHooks(settings map[string]any, kontextBinary string) error {
	return MergeManagedHooksExcept(settings, kontextBinary, nil)
}

// MergeManagedHooksExcept leaves out the events in skip. Cursor runs every
// hooks file it finds without deduplicating, so a user file skips the events
// a machine-wide file already covers.
func MergeManagedHooksExcept(settings map[string]any, kontextBinary string, skip map[string]bool) error {
	hooks, _, err := withoutManagedHooks(settings)
	if err != nil {
		return err
	}
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}
	for _, event := range Events {
		if skip[event.Cursor] {
			continue
		}
		entries, _ := hooks[event.Cursor].([]any)
		hooks[event.Cursor] = append(entries, map[string]any{
			"command": hookCommand(kontextBinary, event.Alias),
			"timeout": DefaultHookTimeout,
		})
	}
	if !validVersion(settings["version"]) {
		// Cursor rejects a file without a positive integer version.
		settings["version"] = 1
	}
	settings["hooks"] = hooks
	return nil
}

// RemoveManagedHooks drops Kontext's entries. A file left with nothing but the
// version key ends up empty, so the installer can delete it.
func RemoveManagedHooks(settings map[string]any) error {
	hooks, removed, err := withoutManagedHooks(settings)
	if err != nil || removed == 0 {
		return err
	}
	if len(hooks) > 0 {
		settings["hooks"] = hooks
		return nil
	}
	delete(settings, "hooks")
	if len(settings) == 1 && settings["version"] != nil {
		delete(settings, "version")
	}
	return nil
}

func withoutManagedHooks(settings map[string]any) (map[string]any, int, error) {
	if settings == nil {
		return nil, 0, errors.New("hooks.json must be a JSON object")
	}
	removed := 0
	hooks := map[string]any{}
	if raw, ok := settings["hooks"]; ok && raw != nil {
		existing, ok := raw.(map[string]any)
		if !ok {
			return nil, 0, errors.New("hooks.json hooks must be an object")
		}
		hooks = existing
	}
	for name, raw := range hooks {
		entries, ok := raw.([]any)
		if !ok {
			return nil, 0, fmt.Errorf("hooks.json %s must be an array", name)
		}
		kept := entries[:0:0]
		for _, entry := range entries {
			if object, ok := entry.(map[string]any); ok {
				if command, _ := object["command"].(string); IsManagedHookCommand(command) {
					removed++
					continue
				}
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 && len(entries) > 0 {
			delete(hooks, name)
		} else {
			hooks[name] = kept
		}
	}
	return hooks, removed, nil
}

func validVersion(value any) bool {
	number, ok := value.(float64)
	if !ok {
		if n, isNumber := value.(json.Number); isNumber {
			parsed, err := n.Float64()
			number, ok = parsed, err == nil
		}
	}
	return ok && number >= 1 && number == float64(int64(number))
}

// ErrMalformed marks a hooks.json that is not the shape Cursor reads.
var ErrMalformed = errors.New("malformed Cursor hooks.json")

type handler struct {
	Command    string `json:"command"`
	Type       string `json:"type"`
	Timeout    int    `json:"timeout"`
	Matcher    string `json:"matcher"`
	FailClosed bool   `json:"failClosed"`
}

// Coverage maps each Cursor event that carries a valid Kontext hook in data to
// the binary that hook runs. Cursor ignores a file without a valid version, so
// such a file covers nothing.
func Coverage(data []byte) map[string]string {
	var settings struct {
		Version any                  `json:"version"`
		Hooks   map[string][]handler `json:"hooks"`
	}
	covered := map[string]string{}
	if json.Unmarshal(data, &settings) != nil || !validVersion(settings.Version) {
		return covered
	}
	for _, event := range Events {
		for _, h := range settings.Hooks[event.Cursor] {
			if !IsManagedHookCommand(h.Command) {
				continue
			}
			fields, _ := agenthooks.SplitCommand(h.Command)
			if fields[4] == event.Alias && (h.Type == "" || h.Type == "command") && h.Timeout > 0 && (h.Matcher == "" || h.Matcher == "*") {
				covered[event.Cursor] = fields[0]
			}
		}
	}
	return covered
}

// ValidateInstalled checks every event Kontext needs and returns the binary
// the hooks run.
func ValidateInstalled(data []byte) (string, error) {
	var settings struct {
		Version any                  `json:"version"`
		Hooks   map[string][]handler `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	var binary string
	var problems []string
	if !validVersion(settings.Version) {
		problems = append(problems, "version must be a positive integer")
	}
	for _, event := range Events {
		found := false
		for _, h := range settings.Hooks[event.Cursor] {
			if !IsManagedHookCommand(h.Command) {
				continue
			}
			fields, _ := agenthooks.SplitCommand(h.Command)
			if fields[4] != event.Alias || (h.Type != "" && h.Type != "command") || h.Timeout <= 0 ||
				(h.Matcher != "" && h.Matcher != "*") {
				problems = append(problems, event.Cursor+" hook is invalid")
				continue
			}
			found = true
			if binary == "" {
				binary = fields[0]
			} else if binary != fields[0] {
				problems = append(problems, "Kontext hooks use different binary paths")
			}
		}
		if !found {
			problems = append(problems, event.Cursor+" hook missing")
		}
	}
	if len(problems) > 0 {
		return "", errors.New(strings.Join(problems, "; "))
	}
	return binary, nil
}
