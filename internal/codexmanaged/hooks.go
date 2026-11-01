package codexmanaged

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

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
// the binaries its Kontext hooks run. Codex skips a hooks.json it cannot load
// as a whole, so such a file covers nothing.
func Coverage(data []byte) map[string][]string {
	var settings Settings
	if loadable(data) != nil || json.Unmarshal(data, &settings) != nil {
		return map[string][]string{}
	}
	_, covered, _ := inspect(settings, false)
	return covered
}

// loadable reports why Codex would skip data as a hooks.json. Codex skips a
// whole file it cannot parse into its HooksFile type (codex-rs config and
// protocol hooks), so this follows that type: only description and hooks at
// the top, each field of its type, each handler of a type Codex knows with
// its required fields. Where it cannot tell it rejects too: at worst a user
// hook then runs beside the machine-wide one, never an event without a hook.
func loadable(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeUnique(decoder, 0)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("data after the top-level object")
	}
	file, ok := value.(map[string]any)
	if !ok {
		return errors.New("not an object")
	}
	for key, value := range file {
		switch key {
		case "description":
			if !optionalString(value, true) {
				return errors.New("description is not a string")
			}
		case "hooks":
			events, ok := value.(map[string]any)
			if !ok {
				return errors.New("hooks is not an object")
			}
			for event, groups := range events {
				if err := loadableGroups(groups); err != nil {
					return fmt.Errorf("%s: %w", event, err)
				}
			}
		default:
			return fmt.Errorf("the top-level key %q", key)
		}
	}
	return nil
}

// maxCodexDepth stays under the 128 levels serde_json, which Codex parses
// with, nests.
const maxCodexDepth = 100

// decodeUnique decodes one value like encoding/json with UseNumber, but fails
// on a key repeated within an object, which Codex rejects, or on nesting past
// maxCodexDepth.
func decodeUnique(decoder *json.Decoder, depth int) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if token != json.Delim('[') && token != json.Delim('{') {
		return token, nil
	}
	if depth == maxCodexDepth {
		return nil, errors.New("nested too deep")
	}
	if token == json.Delim('[') {
		var items []any
		for decoder.More() {
			item, err := decodeUnique(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		_, err := decoder.Token()
		return items, err
	}
	object := map[string]any{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key := token.(string)
		if _, repeated := object[key]; repeated {
			return nil, fmt.Errorf("the key %q twice", key)
		}
		if object[key], err = decodeUnique(decoder, depth+1); err != nil {
			return nil, err
		}
	}
	_, err = decoder.Token()
	return object, err
}

// loadableGroups checks one event's matcher groups.
func loadableGroups(value any) error {
	groups, ok := value.([]any)
	if !ok {
		return errors.New("not a list")
	}
	for _, value := range groups {
		group, ok := value.(map[string]any)
		if !ok {
			return errors.New("a matcher group is not an object")
		}
		if !optionalString(group["matcher"], true) {
			return errors.New("a matcher is not a string")
		}
		handlers, present := group["hooks"]
		list, ok := handlers.([]any)
		if present && !ok {
			return errors.New("a group's hooks is not a list")
		}
		for _, handler := range list {
			if err := loadableHandler(handler); err != nil {
				return err
			}
		}
	}
	return nil
}

// codexHandlerFields is how Codex parses each field of a handler, by type; it
// ignores fields not listed.
var codexHandlerFields = map[string]map[string]func(value any, present bool) bool{
	"command": {
		"command": requiredString, "commandWindows": optionalString, "command_windows": optionalString,
		"timeout": optionalUint, "async": presentBool, "statusMessage": optionalString, "additionalContextLimit": optionalUint,
	},
	"mcp_tool": {
		"server": requiredString, "tool": requiredString, "input": tomlTable,
		"timeout": optionalUint, "statusMessage": optionalString,
	},
	"prompt": {},
	"agent":  {},
}

func loadableHandler(value any) error {
	handler, ok := value.(map[string]any)
	if !ok {
		return errors.New("a handler is not an object")
	}
	kind, _ := handler["type"].(string)
	fields, known := codexHandlerFields[kind]
	if !known {
		return fmt.Errorf("a handler of type %v", handler["type"])
	}
	for name, parses := range fields {
		value, present := handler[name]
		if !parses(value, present) {
			return fmt.Errorf("a %s handler with a missing or mistyped %s", kind, name)
		}
	}
	// command_windows is an alias of commandWindows: both is a repeated field.
	_, windows := handler["commandWindows"]
	if _, alias := handler["command_windows"]; kind == "command" && windows && alias {
		return errors.New("a command handler with both commandWindows and command_windows")
	}
	return nil
}

func requiredString(value any, _ bool) bool {
	_, ok := value.(string)
	return ok
}

// optionalString accepts an absent or null field, like Option<String>.
func optionalString(value any, _ bool) bool {
	return value == nil || requiredString(value, true)
}

// optionalUint accepts an absent or null field, or a whole number in u64.
func optionalUint(value any, _ bool) bool {
	number, ok := value.(json.Number)
	if !ok {
		return value == nil
	}
	_, err := strconv.ParseUint(string(number), 10, 64)
	return err == nil
}

// presentBool accepts an absent field, which defaults, but not a null one.
func presentBool(value any, present bool) bool {
	_, ok := value.(bool)
	return !present || ok
}

// tomlTable accepts an absent field or an object Codex can hash as TOML: no
// null and no whole number above i64 anywhere in it.
func tomlTable(value any, present bool) bool {
	table, ok := value.(map[string]any)
	return !present || ok && representable(table)
}

func representable(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case json.Number:
		n, err := strconv.ParseUint(string(value), 10, 64)
		return err != nil || n <= math.MaxInt64
	case []any:
		return !slices.ContainsFunc(value, func(item any) bool { return !representable(item) })
	case map[string]any:
		for _, item := range value {
			if !representable(item) {
				return false
			}
		}
	}
	return true
}

// inspect checks Kontext's handlers event by event. covered maps each event
// with a valid handler to the binaries those handlers name; a missing event is
// a problem only when every event is required.
func inspect(settings Settings, requireAll bool) (binary string, covered map[string][]string, problems []string) {
	covered = map[string][]string{}
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
				covered[name] = append(covered[name], fields[0])
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
		if len(covered[name]) == 0 && requireAll {
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
