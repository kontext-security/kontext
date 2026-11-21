package readers

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// HookSettings is what a Claude Code settings file, a managed drop-in or a
// plugin's hooks/hooks.json says about hooks. Handlers stay raw: the scanner
// fingerprints them as written and reads only the fields it reports.
type HookSettings struct {
	Hooks map[string][]HookGroup `json:"hooks"`
	// Present only in settings files; a plugin's hooks.json has none of them.
	DisableAllHooks               *bool           `json:"-"`
	DisableAllHooksSet            bool            `json:"-"`
	AllowManagedHooksOnly         *bool           `json:"allowManagedHooksOnly"`
	AllowedHTTPHookURLs           *[]string       `json:"allowedHttpHookUrls"`
	StrictPluginOnlyCustomization json.RawMessage `json:"strictPluginOnlyCustomization"`
	EnabledPlugins                map[string]bool `json:"enabledPlugins"`
	// SwitchInvalid: a switch held a value of the wrong type. Its effect
	// depends on the agent's version, so the scanner doesn't guess it.
	SwitchInvalid bool `json:"-"`
	// PolicyHelper: the file names a policy helper, a program whose output
	// replaces the managed settings and can't be read without running it.
	PolicyHelper bool `json:"-"`
}

type HookGroup struct {
	Matcher *string           `json:"matcher"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// UnmarshalJSON reads a group by its exact keys: Claude Code ignores a
// `Matcher` or `Hooks` spelled in another case, so the inventory does too.
func (g *HookGroup) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*g = HookGroup{}
	if raw, ok := fields["matcher"]; ok {
		if err := json.Unmarshal(raw, &g.Matcher); err != nil {
			return err
		}
	}
	if raw, ok := fields["hooks"]; ok {
		if err := json.Unmarshal(raw, &g.Hooks); err != nil {
			return err
		}
	}
	return nil
}

// HookHandler is the part of one handler the inventory reports. Fields an
// agent version adds later are kept in the raw entry, never dropped. Args is
// nil when absent and empty, not nil, for "args": [] (exec form with no
// arguments).
type HookHandler struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args"`
	URL     string   `json:"url"`
	Server  string   `json:"server"`
	Tool    string   `json:"tool"`
	Timeout *float64 `json:"timeout"`
	// If narrows the handler to matching calls (Claude Code's handler-level
	// `if`, a permission rule such as "Bash(git *)").
	If string `json:"if"`
	// Async runs the handler without waiting for it: its decision is
	// ignored.
	Async bool `json:"async"`
	// AsyncRewake runs it in the background too, waking the agent later.
	AsyncRewake bool `json:"asyncRewake"`
	// prompt is what a prompt or agent handler asks; it is only checked for
	// presence, never reported.
	prompt string
}

var errHooksShape = errors.New("hooks is not an object of matcher groups")

var errSettingsShape = errors.New("settings is not an object")

// Hooks parses one hook source. disableAllHooks follows Claude's merge rule:
// a Boolean sets it, null clears an earlier value, anything else changes
// nothing, so it is read apart from the struct.
func Hooks(data []byte) (HookSettings, error) {
	// Claude reads an empty settings file as {}: emptying it removes its
	// hooks.
	if len(bytes.TrimSpace(data)) == 0 {
		return HookSettings{}, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return HookSettings{}, err
	}
	// The literal null is no settings object: reading it as empty would
	// withdraw every hook the file held.
	if top == nil {
		return HookSettings{}, errSettingsShape
	}
	var s HookSettings
	if raw, ok := top["hooks"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &s.Hooks); err != nil {
			return HookSettings{}, errHooksShape
		}
	}
	if raw, ok := top["policyHelper"]; ok && string(raw) != "null" {
		s.PolicyHelper = true
	}
	if raw, ok := top["disableAllHooks"]; ok {
		var value *bool
		if json.Unmarshal(raw, &value) == nil {
			s.DisableAllHooks, s.DisableAllHooksSet = value, true
		}
	}
	for key, target := range map[string]any{
		"allowManagedHooksOnly":         &s.AllowManagedHooksOnly,
		"allowedHttpHookUrls":           &s.AllowedHTTPHookURLs,
		"strictPluginOnlyCustomization": &s.StrictPluginOnlyCustomization,
		"enabledPlugins":                &s.EnabledPlugins,
	} {
		if raw, ok := top[key]; ok {
			// A wrong type in one switch must not hide the file's hooks,
			// nor read as a value it doesn't hold.
			if err := json.Unmarshal(raw, target); err != nil {
				s.SwitchInvalid = true
				switch t := target.(type) {
				case **bool:
					*t = nil
				case **[]string:
					*t = nil
				case *json.RawMessage:
					*t = nil
				case *map[string]bool:
					*t = nil
				}
			}
		}
	}
	return s, nil
}

// Handler reads the reported fields of one raw handler, by their exact keys:
// Claude Code doesn't read `Type` or `Command` as `type` or `command`. A
// handler that is not an object is reported with an empty type, which the
// scanner calls unknown; a field of the wrong type is left empty.
func Handler(raw json.RawMessage) HookHandler {
	var fields map[string]json.RawMessage
	var h HookHandler
	if json.Unmarshal(raw, &fields) != nil {
		return h
	}
	malformed := false
	for key, target := range map[string]any{
		"type": &h.Type, "command": &h.Command, "args": &h.Args, "url": &h.URL,
		"server": &h.Server, "tool": &h.Tool, "timeout": &h.Timeout, "if": &h.If,
		"async": &h.Async, "asyncRewake": &h.AsyncRewake, "prompt": &h.prompt,
	} {
		if value, ok := fields[key]; ok && json.Unmarshal(value, target) != nil {
			malformed = true
		}
	}
	if malformed || missingRequired(h) {
		// Claude doesn't run a handler whose fields don't fit its shape
		// (`args` as a string) or that lacks what its type needs (a command
		// handler without a command): it is unknown, never verified as ours.
		return HookHandler{}
	}
	h.prompt = ""
	return h
}

// missingRequired reports a known handler type without the field it runs.
func missingRequired(h HookHandler) bool {
	switch h.Type {
	case "command":
		return strings.TrimSpace(h.Command) == ""
	case "http":
		return strings.TrimSpace(h.URL) == ""
	case "mcp_tool":
		return h.Server == "" || h.Tool == ""
	case "prompt", "agent":
		return strings.TrimSpace(h.prompt) == ""
	}
	return false
}
