package claudemanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/hook"
)

const (
	ManagedSettingsPath        = "/Library/Application Support/ClaudeCode/managed-settings.json"
	ManagedSettingsDropInPath  = "/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json"
	LinuxManagedSettingsPath   = "/etc/claude-code/managed-settings.json"
	WindowsManagedSettingsPath = `C:\Program Files\ClaudeCode\managed-settings.json`
	DefaultKontextBinary       = "/usr/local/bin/kontext"
	DefaultHookTimeout         = 20
	PromptHookTimeout          = 65
)

type Event struct {
	Name    hook.HookName
	Alias   string
	Async   bool
	Timeout int
}

var SupportedEvents = []Event{
	{Name: hook.HookSessionStart, Alias: "session-start", Async: true},
	{Name: hook.HookPreToolUse, Alias: "pre-tool-use"},
	{Name: hook.HookPostToolUse, Alias: "post-tool-use"},
	{Name: hook.HookPostToolUseFailed, Alias: "post-tool-use-failure"},
	{Name: hook.HookSessionEnd, Alias: "session-end", Async: true},
	{Name: hook.HookUserPromptSubmit, Alias: "user-prompt-submit", Timeout: PromptHookTimeout},
}

func DefaultManagedSettingsPath() string {
	return managedSettingsPathForGOOS(runtime.GOOS)
}

func managedSettingsPathForGOOS(goos string) string {
	switch goos {
	case "windows":
		return WindowsManagedSettingsPath
	case "linux":
		return LinuxManagedSettingsPath
	default:
		return ManagedSettingsPath
	}
}

type Settings struct {
	Hooks                 map[string][]MatcherGroup `json:"hooks"`
	DisableAllHooks       *bool                     `json:"disableAllHooks,omitempty"`
	AllowManagedHooksOnly *bool                     `json:"allowManagedHooksOnly,omitempty"`
}

type MatcherGroup struct {
	Matcher string    `json:"matcher"`
	Hooks   []Handler `json:"hooks"`
}

type Handler struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout,omitempty"`
	Async   *bool    `json:"async,omitempty"`
}

func Template(kontextBinary string) Settings {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}
	settings := Settings{Hooks: make(map[string][]MatcherGroup, len(SupportedEvents))}
	for _, event := range SupportedEvents {
		handler := Handler{
			Type:    "command",
			Command: hookCommand(kontextBinary, event.Alias),
			Timeout: eventTimeout(event),
		}
		if event.Async {
			value := true
			handler.Async = &value
		}
		settings.Hooks[event.Name.String()] = []MatcherGroup{{
			Matcher: "",
			Hooks:   []Handler{handler},
		}}
	}
	return settings
}

func TemplateJSON(kontextBinary string) ([]byte, error) {
	data, err := json.MarshalIndent(Template(kontextBinary), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal managed settings template: %w", err)
	}
	return append(data, '\n'), nil
}

func Validate(data []byte, kontextBinary string) error {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}

	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse managed settings: %w", err)
	}

	var problems []string
	if settings.Hooks == nil {
		problems = append(problems, "hooks missing")
	}
	if settings.DisableAllHooks != nil && *settings.DisableAllHooks {
		problems = append(problems, "disableAllHooks must not be true")
	}

	for _, event := range SupportedEvents {
		if err := validateEvent(settings.Hooks[event.Name.String()], event, kontextBinary); err != nil {
			problems = append(problems, err.Error())
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

// IsManagedSettingsDropIn reports whether data is a Kontext-owned managed
// settings drop-in — a file we are safe to refresh (setup) or delete
// (uninstall) without destroying state we don't own. It is ours iff:
//
//  1. The ONLY top-level key is "hooks" — exactly what Template emits. A file
//     carrying any other top-level field (enterprise policy, metadata, or a
//     future Claude managed-settings key) is not solely ours, so we leave it
//     untouched even when its hooks match.
//  2. Every handler command is one of our flagless managed-observe hooks
//     (IsManagedHookCommand). Matching on the alias, not the binary path, means
//     a drop-in from an older self-serve run (a stale path after `brew upgrade`)
//     still reads as ours.
//
// Empty/garbage data is not ours.
func IsManagedSettingsDropIn(data []byte) bool {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return false
	}
	if len(top) != 1 {
		return false
	}
	for key := range top {
		if key != "hooks" {
			return false
		}
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	if len(settings.Hooks) != len(SupportedEvents) {
		return false
	}
	for _, event := range SupportedEvents {
		groups := settings.Hooks[event.Name.String()]
		if len(groups) != 1 || groups[0].Matcher != "" || len(groups[0].Hooks) != 1 {
			return false
		}
		if !isCanonicalManagedDropInHandler(groups[0].Hooks[0], event) {
			return false
		}
	}
	return true
}

func HasManagedObserveHooks(data []byte) bool {
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	if settings.DisableAllHooks != nil && *settings.DisableAllHooks {
		return false
	}
	for _, event := range SupportedEvents {
		if !hasManagedObserveHook(settings.Hooks[event.Name.String()], event) {
			return false
		}
	}
	return true
}

// ManagedObserveHookBinary returns the common binary path referenced by every
// managed-observe hook. It validates the same effective hook shape as
// HasManagedObserveHooks while preserving the path for read-only diagnostics.
func ManagedObserveHookBinary(data []byte) (string, bool) {
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil || (settings.DisableAllHooks != nil && *settings.DisableAllHooks) {
		return "", false
	}
	binary := ""
	for _, event := range SupportedEvents {
		found := false
		for _, group := range settings.Hooks[event.Name.String()] {
			if !isAllMatcher(group.Matcher) {
				continue
			}
			for _, handler := range group.Hooks {
				if handler.Type != "command" || len(handler.Args) != 0 || validateAsync(event, handler.Async) != nil {
					continue
				}
				fields, ok := agenthooks.SplitCommand(handler.Command)
				if !ok || len(fields) != 3 || filepath.Base(fields[0]) != "kontext" || fields[1] != "hook" || fields[2] != event.Alias {
					continue
				}
				if binary == "" {
					binary = fields[0]
				} else if binary != fields[0] {
					return "", false
				}
				found = true
			}
		}
		if !found {
			return "", false
		}
	}
	return binary, binary != ""
}

func DisablesAllHooks(data []byte) bool {
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	return settings.DisableAllHooks != nil && *settings.DisableAllHooks
}

func hasManagedObserveHook(groups []MatcherGroup, event Event) bool {
	for _, group := range groups {
		if !isAllMatcher(group.Matcher) {
			continue
		}
		for _, handler := range group.Hooks {
			if handler.Type != "command" || len(handler.Args) != 0 {
				continue
			}
			if err := validateAsync(event, handler.Async); err != nil {
				continue
			}
			fields, ok := agenthooks.SplitCommand(handler.Command)
			if ok && len(fields) == 3 && filepath.Base(fields[0]) == "kontext" && fields[1] == "hook" && fields[2] == event.Alias {
				return true
			}
		}
	}
	return false
}

func isCanonicalManagedDropInHandler(handler Handler, event Event) bool {
	if handler.Type != "command" || len(handler.Args) != 0 || handler.Timeout != eventTimeout(event) {
		return false
	}
	if event.Async {
		if handler.Async == nil || !*handler.Async {
			return false
		}
	} else if handler.Async != nil {
		return false
	}
	fields, ok := agenthooks.SplitCommand(handler.Command)
	return ok && len(fields) == 3 &&
		filepath.Base(fields[0]) == "kontext" &&
		fields[1] == "hook" &&
		fields[2] == event.Alias
}

func eventTimeout(event Event) int {
	if event.Timeout > 0 {
		return event.Timeout
	}
	return DefaultHookTimeout
}

func ParseEventAlias(value string) (hook.HookName, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, event := range SupportedEvents {
		if normalized == event.Alias {
			return event.Name, true
		}
	}
	return "", false
}

func AliasForEvent(name hook.HookName) (string, bool) {
	for _, event := range SupportedEvents {
		if event.Name == name {
			return event.Alias, true
		}
	}
	return "", false
}

func validateEvent(groups []MatcherGroup, event Event, kontextBinary string) error {
	if len(groups) == 0 {
		return fmt.Errorf("%s hook missing", event.Name)
	}

	foundValid := false
	firstRestrictiveMatcher := ""
	for _, group := range groups {
		for _, handler := range group.Hooks {
			if handler.Command != hookCommand(kontextBinary, event.Alias) {
				continue
			}
			if handler.Type != "command" {
				return fmt.Errorf("%s Kontext handler type = %q, want command", event.Name, handler.Type)
			}
			if len(handler.Args) > 0 {
				return fmt.Errorf("%s Kontext handler args must be omitted", event.Name)
			}
			if err := validateAsync(event, handler.Async); err != nil {
				return err
			}
			if !isAllMatcher(group.Matcher) {
				if firstRestrictiveMatcher == "" {
					firstRestrictiveMatcher = group.Matcher
				}
				continue
			}
			foundValid = true
		}
	}

	if foundValid {
		return nil
	}
	if firstRestrictiveMatcher != "" {
		return fmt.Errorf("%s Kontext command hook uses matcher %q; use an empty matcher for full event coverage", event.Name, firstRestrictiveMatcher)
	}
	return fmt.Errorf("%s Kontext command hook missing for %s", event.Name, kontextBinary)
}

func validateAsync(event Event, async *bool) error {
	if event.Async {
		if async == nil || !*async {
			return fmt.Errorf("%s Kontext handler async must be true", event.Name)
		}
		return nil
	}
	if async != nil {
		return fmt.Errorf("%s Kontext handler async must be omitted", event.Name)
	}
	return nil
}

func hookCommand(kontextBinary, alias string) string {
	return agenthooks.ShellQuote(kontextBinary) + " hook " + agenthooks.ShellQuote(alias)
}

func isAllMatcher(value string) bool {
	matcher := strings.TrimSpace(value)
	return matcher == "" || matcher == "*"
}
