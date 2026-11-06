// Package antigravitymanaged owns Kontext's named hook in Antigravity's
// hooks.json. The app, CLI and IDE all read ~/.gemini/config/hooks.json and pick
// up edits without a restart. Antigravity documents no machine-wide location, so
// unlike Claude Code, Codex and Cursor this file is the only one, and a person
// can switch the hook off; the inventory reports that as not wired, and a
// self-serve daemon restores it.
package antigravitymanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
)

const (
	// HookName is the top-level key Kontext owns. Antigravity merges named hooks,
	// so the file's other entries are left as they are.
	HookName           = "kontext"
	DefaultHookTimeout = 20
	// commandSuffix keeps a missing binary from blocking the agent: Antigravity
	// blocks a tool call whenever its PreToolUse hook exits non-zero, while empty
	// stdout is its no-decision answer. Its docs say the hook fails open; measured
	// on 2.29.0 it does not. sh and cmd both read this suffix.
	commandSuffix = " || exit 0"
	agentName     = "antigravity"
)

// Events lists the Antigravity events Kontext registers and the Kontext event
// alias each one runs. The tool events take a matcher group, the others a flat
// list of handlers. PreInvocation runs under user-prompt-submit: it is the only
// event before a turn's first model call, and the adapter ignores later calls.
var Events = []struct {
	Antigravity, Alias string
	Grouped            bool
}{
	{"SessionStart", "session-start", false},
	{"PreInvocation", "user-prompt-submit", false},
	{"PreToolUse", "pre-tool-use", true},
	{"PostToolUse", "post-tool-use", true},
	{"Stop", "stop", false},
}

// UserHooksPath is the hooks file every Antigravity surface reads.
func UserHooksPath(home string) string {
	return filepath.Join(home, ".gemini", "config", "hooks.json")
}

func hookCommand(binary, alias string) string {
	return agenthooks.ShellQuote(binary) + " hook --agent " + agenthooks.ShellQuote(agentName) + " " + agenthooks.ShellQuote(alias) + commandSuffix
}

// parseHookCommand reads back a command hookCommand wrote. Only literal words
// count: a command that merely contains the path belongs to someone else.
func parseHookCommand(command string) (binary, alias string, ok bool) {
	rest, found := strings.CutSuffix(command, commandSuffix)
	if !found {
		return "", "", false
	}
	fields, literal := agenthooks.SplitLiteralCommand(rest)
	if !literal || len(fields) != 5 || !filepath.IsAbs(fields[0]) || filepath.Base(fields[0]) != "kontext" ||
		fields[1] != "hook" || fields[2] != "--agent" || fields[3] != agentName {
		return "", "", false
	}
	return fields[0], fields[4], true
}

// MergeManagedHooks writes Kontext's named hook, replacing any earlier one, and
// keeps every other entry in the file.
func MergeManagedHooks(settings map[string]any, binary string) error {
	if settings == nil {
		return errors.New("hooks.json must be a JSON object")
	}
	binary = strings.TrimSpace(binary)
	if binary == "" {
		return errors.New("hook binary is required")
	}
	group := map[string]any{}
	for _, event := range Events {
		handler := map[string]any{
			"type":    "command",
			"command": hookCommand(binary, event.Alias),
			"timeout": DefaultHookTimeout,
		}
		if event.Grouped {
			group[event.Antigravity] = []any{map[string]any{"matcher": "*", "hooks": []any{handler}}}
		} else {
			group[event.Antigravity] = []any{handler}
		}
	}
	settings[HookName] = group
	return nil
}

// RemoveManagedHooks drops Kontext's named hook. A file left empty can be
// deleted by the installer.
func RemoveManagedHooks(settings map[string]any) {
	delete(settings, HookName)
}

// ErrMalformed marks a hooks.json that is not the shape Antigravity reads.
var ErrMalformed = errors.New("malformed Antigravity hooks.json")

type handler struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}

// ValidateInstalled checks every event Kontext needs and returns the binary the
// hooks run. A hook switched off, by hand or from the app's settings, counts as
// not installed.
func ValidateInstalled(data []byte) (string, error) {
	var file map[string]json.RawMessage
	if err := json.Unmarshal(data, &file); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	raw, ok := file[HookName]
	if !ok {
		return "", errors.New("Kontext hook missing")
	}
	var group map[string]json.RawMessage
	if err := json.Unmarshal(raw, &group); err != nil {
		return "", fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if enabled, ok := group["enabled"]; ok && string(enabled) == "false" {
		return "", errors.New("Kontext hook is switched off")
	}
	var binary string
	var problems []string
	for _, event := range Events {
		found := false
		for _, h := range eventHandlers(group[event.Antigravity], event.Grouped) {
			parsed, alias, ok := parseHookCommand(h.Command)
			if !ok {
				continue
			}
			if alias != event.Alias || (h.Type != "" && h.Type != "command") || h.Timeout <= 0 {
				problems = append(problems, event.Antigravity+" hook is invalid")
				continue
			}
			found = true
			if binary == "" {
				binary = parsed
			} else if binary != parsed {
				problems = append(problems, "Kontext hooks use different binary paths")
			}
		}
		if !found {
			problems = append(problems, event.Antigravity+" hook missing")
		}
	}
	if len(problems) > 0 {
		return "", errors.New(strings.Join(problems, "; "))
	}
	return binary, nil
}

func eventHandlers(raw json.RawMessage, grouped bool) []handler {
	if len(raw) == 0 {
		return nil
	}
	if !grouped {
		var handlers []handler
		_ = json.Unmarshal(raw, &handlers)
		return handlers
	}
	var groups []struct {
		Matcher string    `json:"matcher"`
		Hooks   []handler `json:"hooks"`
	}
	_ = json.Unmarshal(raw, &groups)
	var handlers []handler
	for _, group := range groups {
		// A narrower matcher would leave tools unobserved.
		if group.Matcher == "*" || group.Matcher == "" {
			handlers = append(handlers, group.Hooks...)
		}
	}
	return handlers
}
