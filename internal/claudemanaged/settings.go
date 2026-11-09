package claudemanaged

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/platform"
)

const (
	DefaultKontextBinary = "/usr/local/bin/kontext"
	DefaultHookTimeout   = 20
	// SavedOutputReadRule lets Claude Code read back, without asking, the
	// full outputs that tool output compaction saves in the daemon's data
	// directory (internal/tooloutput). The Read tool otherwise asks before
	// reading outside the project. It names that directory only.
	SavedOutputReadRule = "Read(~/Library/Application Support/Kontext/**/managed-observe/tool-output/**)"
)

// ExecForm makes Template write each hook in Claude Code's exec form: the
// binary in `command` and `hook <alias>` in `args`, which Claude Code runs
// without a shell. Windows needs it, because a shell-form hook runs in
// PowerShell there, which can't parse the POSIX-quoted command line. Reading
// accepts both forms on every OS. A variable so tests can pin either form.
var ExecForm = runtime.GOOS == "windows"

type Event struct {
	Name  hook.HookName
	Alias string
	Async bool
}

var SupportedEvents = []Event{
	{Name: hook.HookSessionStart, Alias: "session-start", Async: true},
	{Name: hook.HookPreToolUse, Alias: "pre-tool-use"},
	{Name: hook.HookPostToolUse, Alias: "post-tool-use"},
	{Name: hook.HookPostToolUseFailed, Alias: "post-tool-use-failure"},
	// Keep prompt capture ordered before the turn's tool calls. Merlin itself
	// still runs asynchronously after the PreToolUse response.
	{Name: hook.HookUserPromptSubmit, Alias: "user-prompt-submit"},
	{Name: hook.HookSessionEnd, Alias: "session-end", Async: true},
	{Name: hook.HookStop, Alias: "stop", Async: true},
	{Name: hook.HookSubagentStop, Alias: "subagent-stop", Async: true},
}

// DefaultManagedSettingsPath is Claude Code's managed settings file on this OS.
func DefaultManagedSettingsPath() string {
	return filepath.Join(platform.ClaudeManagedDir(), "managed-settings.json")
}

// DefaultManagedSettingsDropInPath is the file Kontext owns beside it, which
// Claude Code merges into its managed settings.
func DefaultManagedSettingsDropInPath() string {
	return filepath.Join(platform.ClaudeManagedDir(), "managed-settings.d", "20-kontext.json")
}

type Settings struct {
	Hooks                 map[string][]MatcherGroup `json:"hooks"`
	Permissions           *Permissions              `json:"permissions,omitempty"`
	DisableAllHooks       *bool                     `json:"disableAllHooks,omitempty"`
	AllowManagedHooksOnly *bool                     `json:"allowManagedHooksOnly,omitempty"`
}

type Permissions struct {
	Allow []string `json:"allow,omitempty"`
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
	// Extra keeps the fields Kontext does not write, such as an `if`
	// condition, so a mirrored handler stays identical to its source.
	Extra map[string]any `json:"-"`
}

type plainHandler Handler

func (h *Handler) UnmarshalJSON(data []byte) error {
	var extra map[string]any
	if err := json.Unmarshal(data, (*plainHandler)(h)); err != nil {
		return err
	}
	if err := json.Unmarshal(data, &extra); err != nil {
		return err
	}
	for _, known := range []string{"type", "command", "args", "timeout", "async"} {
		delete(extra, known)
	}
	h.Extra = nil
	if len(extra) > 0 {
		h.Extra = extra
	}
	return nil
}

// MarshalJSON writes the struct as is when there is no extra field, so
// templates keep their exact bytes.
func (h Handler) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(plainHandler(h))
	if err != nil || len(h.Extra) == 0 {
		return data, err
	}
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return nil, err
	}
	for key, value := range h.Extra {
		if _, set := all[key]; !set {
			all[key] = value
		}
	}
	return json.Marshal(all)
}

func Template(kontextBinary string) Settings {
	kontextBinary = strings.TrimSpace(kontextBinary)
	if kontextBinary == "" {
		kontextBinary = DefaultKontextBinary
	}
	settings := Settings{
		Hooks:       make(map[string][]MatcherGroup, len(SupportedEvents)),
		Permissions: &Permissions{Allow: []string{SavedOutputReadRule}},
	}
	for _, event := range SupportedEvents {
		handler := Handler{
			Type:    "command",
			Command: hookCommand(kontextBinary, event.Alias),
			Timeout: DefaultHookTimeout,
		}
		if ExecForm {
			handler.Command, handler.Args = kontextBinary, []string{"hook", event.Alias}
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
//  1. Its top-level keys are what Template emits: "hooks", and "permissions"
//     allowing exactly SavedOutputReadRule (templates before tool output
//     compaction carry hooks alone). A file carrying any other top-level field
//     or permission (enterprise policy, metadata, or a future Claude
//     managed-settings key) is not solely ours, so we leave it untouched even
//     when its hooks match.
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
	if _, ok := top["hooks"]; !ok {
		return false
	}
	for key, value := range top {
		if key != "hooks" && (key != "permissions" || !ownPermissions(value)) {
			return false
		}
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	if len(settings.Hooks) > len(SupportedEvents) || len(settings.Hooks) < len(SupportedEvents)-3 {
		return false
	}
	for name := range settings.Hooks {
		known := false
		for _, event := range SupportedEvents {
			known = known || event.Name.String() == name
		}
		if !known {
			return false
		}
	}
	for _, event := range SupportedEvents {
		groups := settings.Hooks[event.Name.String()]
		// Recognize both the original five-event drop-in and the later usage
		// hooks, so setup can add prompt capture without replacing foreign hooks.
		if (event.Name == hook.HookStop || event.Name == hook.HookSubagentStop || event.Name == hook.HookUserPromptSubmit) && len(groups) == 0 {
			continue
		}
		if len(groups) != 1 || groups[0].Matcher != "" || len(groups[0].Hooks) != 1 {
			return false
		}
		if !isCanonicalManagedDropInHandler(groups[0].Hooks[0], event) {
			return false
		}
	}
	return true
}

// ownPermissions reports whether a drop-in's permissions are exactly the ones
// Template writes.
func ownPermissions(data json.RawMessage) bool {
	var permissions map[string][]string
	return json.Unmarshal(data, &permissions) == nil && len(permissions) == 1 &&
		slices.Equal(permissions["allow"], []string{SavedOutputReadRule})
}

// MissingRequiredEvents returns missing event names and the configured binary
// only when an owned drop-in's remaining hooks pass validation. Other failures
// and current configurations return nil and an empty binary.
func MissingRequiredEvents(data []byte) ([]string, string) {
	if !IsManagedSettingsDropIn(data) {
		return nil, ""
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, ""
	}
	var missing []string
	binary := ""
	for _, event := range SupportedEvents {
		groups := settings.Hooks[event.Name.String()]
		if len(groups) == 0 {
			missing = append(missing, event.Name.String())
			continue
		}
		if binary == "" {
			if len(groups[0].Hooks) == 0 {
				return nil, ""
			}
			fields, ok := hookFields(groups[0].Hooks[0], agenthooks.SplitLiteralCommand)
			if !ok || len(fields) != 3 {
				return nil, ""
			}
			binary = fields[0]
		}
		if validateEvent(groups, event, binary) != nil {
			return nil, ""
		}
	}
	if len(missing) == 0 {
		return nil, ""
	}
	return missing, binary
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
				if handler.Type != "command" || validateAsync(event, handler.Async) != nil {
					continue
				}
				fields, ok := hookFields(handler, agenthooks.SplitCommand)
				if !ok || !isHookCall(fields, event.Alias) {
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

// MachineHooksDisabled is the disableAllHooks value Claude ends with after
// merging sources in order: a later Boolean or null replaces an earlier value;
// a value of another type is invalid and changes nothing.
func MachineHooksDisabled(sources [][]byte) bool {
	disabled := false
	for _, data := range sources {
		var settings map[string]any
		if json.Unmarshal(data, &settings) != nil {
			continue
		}
		if value, set := settings["disableAllHooks"]; set && value == nil {
			disabled = false
		} else if value, ok := value.(bool); ok {
			disabled = value
		}
	}
	return disabled
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
			if handler.Type != "command" {
				continue
			}
			if err := validateAsync(event, handler.Async); err != nil {
				continue
			}
			fields, ok := hookFields(handler, agenthooks.SplitCommand)
			if ok && isHookCall(fields, event.Alias) {
				return true
			}
		}
	}
	return false
}

func isCanonicalManagedDropInHandler(handler Handler, event Event) bool {
	if handler.Type != "command" || handler.Timeout != DefaultHookTimeout {
		return false
	}
	if event.Async {
		if handler.Async == nil || !*handler.Async {
			return false
		}
	} else if handler.Async != nil {
		return false
	}
	fields, ok := hookFields(handler, agenthooks.SplitCommand)
	return ok && isHookCall(fields, event.Alias)
}

// hookFields returns the words a handler runs: its shell command line split
// into words or, in exec form, its command followed by its args. Exec form has
// no shell, so the command is the executable's path exactly as written.
func hookFields(handler Handler, split func(string) ([]string, bool)) ([]string, bool) {
	if len(handler.Args) == 0 {
		return split(handler.Command)
	}
	if handler.Command == "" {
		return nil, false
	}
	return append([]string{handler.Command}, handler.Args...), true
}

// isHookCall reports whether fields run Kontext's flagless `hook <alias>`.
func isHookCall(fields []string, alias string) bool {
	return len(fields) == 3 && agenthooks.IsKontextBinary(fields[0]) && fields[1] == "hook" && fields[2] == alias
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
			fields, ok := agenthooks.SplitLiteralCommand(handler.Command)
			shell := ok && len(fields) == 3 && fields[0] == kontextBinary && fields[1] == "hook" && fields[2] == event.Alias
			// Claude Code runs the exec form on every OS; only Windows requires it.
			exec := handler.Command == kontextBinary && slices.Equal(handler.Args, []string{"hook", event.Alias})
			if !shell && !exec {
				continue
			}
			if handler.Type != "command" {
				return fmt.Errorf("%s Kontext handler type = %q, want command", event.Name, handler.Type)
			}
			if ExecForm && !exec {
				return fmt.Errorf("%s Kontext handler must name the binary in command and %q in args", event.Name, "hook "+event.Alias)
			}
			if !exec && len(handler.Args) > 0 {
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
