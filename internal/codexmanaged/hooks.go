package codexmanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/hook"
)

const (
	DefaultKontextBinary = "/usr/local/bin/kontext"
	DefaultHookTimeout   = 20
)

var SupportedEvents = []hook.EventAlias{
	{Name: hook.HookSessionStart, Alias: "session-start"},
	{Name: hook.HookPreToolUse, Alias: "pre-tool-use"},
	{Name: hook.HookPostToolUse, Alias: "post-tool-use"},
	{Name: hook.HookUserPromptSubmit, Alias: "user-prompt-submit"},
	{Name: hook.HookStop, Alias: "stop"},
}

type Settings struct {
	Hooks map[string][]MatcherGroup `json:"hooks"`
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

// UserHooksPath returns ~/.codex/hooks.json, creating ~/.codex.
func UserHooksPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	codexDir := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		return "", err
	}
	return filepath.Join(codexDir, "hooks.json"), nil
}

// UserHooksPathNoCreate returns ~/.codex/hooks.json without creating ~/.codex.
func UserHooksPathNoCreate() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".codex", "hooks.json"), nil
}

func ReadHooks(path string) (map[string]any, error) {
	return agenthooks.ReadJSONFile(path, "Codex hooks")
}

func WriteHooks(path string, settings map[string]any) error {
	return agenthooks.WriteJSONFile(path, settings)
}

func BackupHooks(path, label string) error {
	return agenthooks.BackupFile(path, label)
}

func Template(kontextBinary string) Settings {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}
	settings := Settings{Hooks: make(map[string][]MatcherGroup, len(SupportedEvents))}
	for _, event := range SupportedEvents {
		settings.Hooks[event.Name.String()] = []MatcherGroup{{
			Matcher: "",
			Hooks: []Handler{{
				Type:    "command",
				Command: hookCommand(kontextBinary, event.Alias),
				Timeout: DefaultHookTimeout,
			}},
		}}
	}
	return settings
}

func TemplateJSON(kontextBinary string) ([]byte, error) {
	data, err := json.MarshalIndent(Template(kontextBinary), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Codex hooks template: %w", err)
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
		return fmt.Errorf("parse Codex hooks: %w", err)
	}

	var problems []string
	if settings.Hooks == nil {
		problems = append(problems, "hooks missing")
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

// ValidateInstalled validates hooks without assuming the path of the running
// binary. Setup deliberately writes a stable Homebrew symlink while the
// process itself can run from a versioned Cellar path. It returns that shared
// configured binary path so diagnostics can check that it still exists.
func ValidateInstalled(data []byte) (string, error) {
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return "", fmt.Errorf("parse Codex hooks: %w", err)
	}
	if settings.Hooks == nil {
		return "", errors.New("hooks missing")
	}
	binary, _, problems := inspect(settings, true)
	if len(problems) > 0 {
		return "", errors.New(strings.Join(problems, "; "))
	}
	return binary, nil
}

// Coverage maps each Codex event that carries a valid Kontext hook in data to
// the binary that hook runs. Codex skips a hooks.json it cannot load as a
// whole, so such a file covers nothing.
func Coverage(data []byte) map[string]string {
	var settings Settings
	if loadable(data) != nil || json.Unmarshal(data, &settings) != nil {
		return map[string]string{}
	}
	_, covered, _ := inspect(settings, false)
	return covered
}

// loadable mirrors where Codex rejects a whole hooks.json: a top-level key
// other than description and hooks, or a handler of a type it does not know.
func loadable(data []byte) error {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(data, &keys); err != nil {
		return err
	}
	for key := range keys {
		if key != "description" && key != "hooks" {
			return fmt.Errorf("Codex does not load a hooks.json with the top-level key %q", key)
		}
	}
	var file struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Type string `json:"type"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return err
	}
	for event, groups := range file.Hooks {
		for _, group := range groups {
			for _, handler := range group.Hooks {
				switch handler.Type {
				case "command", "mcp_tool", "prompt", "agent":
				default:
					return fmt.Errorf("Codex does not load a hooks.json with a %s handler of type %q", event, handler.Type)
				}
			}
		}
	}
	return nil
}

// inspect checks Kontext's handlers event by event. covered maps each event
// with a valid handler to the binary it names; a missing event is a problem
// only when every event is required.
func inspect(settings Settings, requireAll bool) (binary string, covered map[string]string, problems []string) {
	covered = map[string]string{}
	var differentBinaries bool
	for _, event := range SupportedEvents {
		name := event.Name.String()
		for _, group := range settings.Hooks[name] {
			for _, handler := range group.Hooks {
				if !IsManagedHookCommand(handler.Command) {
					continue
				}
				if handler.Type != "command" || len(handler.Args) > 0 || handler.Timeout <= 0 || (handler.Async != nil && *handler.Async) || !isAllMatcher(group.Matcher) {
					problems = append(problems, fmt.Sprintf("%s hook is invalid", event.Name))
					continue
				}
				fields, _ := agenthooks.SplitCommand(handler.Command)
				if fields[4] != event.Alias {
					problems = append(problems, fmt.Sprintf("%s hook uses %q, want %q", event.Name, fields[4], event.Alias))
					continue
				}
				covered[name] = fields[0]
				if binary == "" {
					binary = fields[0]
				} else if binary != fields[0] {
					if !differentBinaries {
						problems = append(problems, "Kontext hooks use different binary paths")
						differentBinaries = true
					}
				}
			}
		}
		if covered[name] == "" && requireAll {
			problems = append(problems, fmt.Sprintf("%s hook missing", event.Name))
		}
	}
	return binary, covered, problems
}

// IsManagedHookCommand reports whether a hook command is one of OUR Codex
// self-serve hooks. Matching on the alias rather than the exact binary path
// lets setup replace stale entries after the binary moves.
func IsManagedHookCommand(command string) bool {
	fields, ok := agenthooks.SplitCommand(command)
	if !ok || len(fields) != 5 {
		return false
	}
	if filepath.Base(fields[0]) != "kontext" || fields[1] != "hook" || fields[2] != "--agent" || fields[3] != "codex" {
		return false
	}
	for _, event := range SupportedEvents {
		if fields[4] == event.Alias {
			return true
		}
	}
	return false
}

func isManagedHookHandler(handler agenthooks.CommandHandler) bool {
	if len(handler.Args) > 0 {
		return false
	}
	return IsManagedHookCommand(handler.Command)
}

func managedHookPlan(kontextBinary string) agenthooks.Plan {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}

	events := make(map[hook.HookName]agenthooks.EventPlan, len(SupportedEvents))
	for _, event := range SupportedEvents {
		events[event.Name] = agenthooks.EventPlan{
			Match: agenthooks.MatchSpec{
				Pattern: "",
			},
			Command: agenthooks.CommandHook{
				Command: hookCommand(kontextBinary, event.Alias),
				Timeout: DefaultHookTimeout,
			},
			Placement: agenthooks.PlacementAppend,
		}
	}

	return agenthooks.Plan{
		Version:  agenthooks.SchemaVersionV1,
		Provider: agenthooks.ProviderCodex,
		Owner:    agenthooks.OwnerKontextManagedObserve,
		Events:   events,
	}
}

func MergeManagedHooks(settings map[string]any, kontextBinary string) error {
	return MergeManagedHooksExcept(settings, kontextBinary, nil)
}

// MergeManagedHooksExcept leaves out the events in skip (hooks.json names) and
// drops Kontext's entries there. Codex runs every hooks.json it finds without
// deduplicating, so a user file skips the events a machine-wide file covers.
func MergeManagedHooksExcept(settings map[string]any, kontextBinary string, skip map[string]bool) error {
	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "hooks.json hooks",
	}
	plan, covered := managedHookPlan(kontextBinary), managedHookPlan(kontextBinary)
	for event := range plan.Events {
		if skip[event.String()] {
			delete(plan.Events, event)
		} else {
			delete(covered.Events, event)
		}
	}
	if len(covered.Events) > 0 {
		if err := config.Remove(covered, isManagedHookHandler); err != nil || len(plan.Events) == 0 {
			return err
		}
	}
	return config.Merge(plan, isManagedHookHandler)
}

func RemoveManagedHooks(settings map[string]any) error {
	config := agenthooks.Config{
		Settings:         settings,
		HooksDescription: "hooks.json hooks",
	}
	return config.Remove(managedHookPlan(DefaultKontextBinary), isManagedHookHandler)
}

func validateEvent(groups []MatcherGroup, event hook.EventAlias, kontextBinary string) error {
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
			if handler.Timeout <= 0 {
				return fmt.Errorf("%s Kontext handler timeout must be positive", event.Name)
			}
			if handler.Async != nil && *handler.Async {
				return fmt.Errorf("%s Kontext handler async must not be true", event.Name)
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

func hookCommand(kontextBinary, alias string) string {
	return agenthooks.ShellQuote(kontextBinary) + " hook --agent " + agenthooks.ShellQuote("codex") + " " + agenthooks.ShellQuote(alias)
}

func isAllMatcher(value string) bool {
	matcher := strings.TrimSpace(value)
	return matcher == "" || matcher == "*"
}
