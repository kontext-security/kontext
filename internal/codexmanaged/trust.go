package codexmanaged

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode"

	"github.com/BurntSushi/toml"
)

// Codex runs a user hook only after the user trusts it in the Codex CLI's
// /hooks, which saves [hooks.state."<hooks.json>:<event>:<group>:<handler>"]
// trusted_hash in config.toml. The hash covers a normalized form of the hook,
// so a hook whose command changed (another binary path) needs trusting again.
// This mirrors codex-rs hooks discovery (hook_hash) and config fingerprint
// (version_for_toml), verified against Codex 0.165.

// defaultContextLimit is Codex's default additionalContextLimit, which it
// leaves out of the hash.
const defaultContextLimit = 2500

// UntrustedHooks lists, by Codex event label, the Kontext hooks in hooksPath
// that Codex skips because configPath holds no matching trust.
func UntrustedHooks(hooksPath, configPath string) ([]string, error) {
	raw, err := os.ReadFile(hooksPath)
	if err != nil {
		return nil, err
	}
	var file struct {
		Hooks map[string][]struct {
			Matcher *string          `json:"matcher"`
			Hooks   []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	states := map[string]any{}
	if data, err := os.ReadFile(configPath); err == nil {
		var config map[string]any
		if _, err := toml.Decode(string(data), &config); err != nil {
			return nil, err
		}
		hooks, _ := config["hooks"].(map[string]any)
		if state, ok := hooks["state"].(map[string]any); ok {
			states = state
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var untrusted []string
	for event, groups := range file.Hooks {
		label := eventLabel(event)
		for gi, group := range groups {
			for hi, handler := range group.Hooks {
				command, _ := handler["command"].(string)
				if handler["type"] != "command" || !IsManagedHookCommand(command) {
					continue
				}
				state, _ := states[fmt.Sprintf("%s:%s:%d:%d", hooksPath, label, gi, hi)].(map[string]any)
				trusted, _ := state["trusted_hash"].(string)
				if state["enabled"] == false || trusted != hookHash(label, group.Matcher, handler) {
					untrusted = append(untrusted, label)
				}
			}
		}
	}
	slices.Sort(untrusted)
	return slices.Compact(untrusted), nil
}

// eventLabel turns a hooks.json event name (PreToolUse) into Codex's key label
// (pre_tool_use).
func eventLabel(event string) string {
	var b strings.Builder
	for i, r := range event {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

// hookHash is Codex's trust identity for one command handler: SHA-256 of the
// compact, key-sorted JSON of {event_name, matcher, hooks: [handler]}, with the
// timeout normalized, absent options left out and the matcher kept only for
// events that use one.
func hookHash(label string, matcher *string, handler map[string]any) string {
	normalized := map[string]any{
		"type":    "command",
		"command": handler["command"],
		"async":   handler["async"] == true,
		"timeout": normalizedTimeout(label, handler["timeout"]),
	}
	if message, ok := handler["statusMessage"].(string); ok {
		normalized["statusMessage"] = message
	}
	if limit, ok := handler["additionalContextLimit"].(float64); ok && limit != defaultContextLimit {
		normalized["additionalContextLimit"] = uint64(limit)
	}
	identity := map[string]any{"event_name": label, "hooks": []any{normalized}}
	switch label {
	case "user_prompt_submit", "stop", "interrupt", "pre_model_request", "post_model_request":
	default:
		if matcher != nil {
			identity["matcher"] = *matcher
		}
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(identity)
	sum := sha256.Sum256(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
	return fmt.Sprintf("sha256:%x", sum)
}

func normalizedTimeout(label string, value any) uint64 {
	seconds, ok := value.(float64)
	if label == "session_end" || label == "interrupt" {
		if !ok {
			return 1
		}
		return uint64(min(max(seconds, 1), 3))
	}
	if !ok {
		return 600
	}
	return uint64(max(seconds, 1))
}
