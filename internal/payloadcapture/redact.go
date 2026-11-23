package payloadcapture

import (
	"slices"
	"strings"
)

// RedactJSON returns a deep copy of value with credential-looking content
// replaced by RedactedPlaceholder: values of sensitive keys are replaced
// wholesale, and every string value is run through the ruleset's value
// patterns. The input is never mutated. Redaction is coverage-oriented — the
// guarantee is that a matched secret does not survive, not that every engine
// produces identical bytes.
func RedactJSON(value map[string]any) (map[string]any, bool) {
	redacted, changed := redactValue(value)
	out, ok := redacted.(map[string]any)
	if !ok {
		// redactValue preserves container types; this cannot happen.
		return map[string]any{}, changed
	}
	return out, changed
}

func redactValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return RedactText(typed)
	case map[string]any:
		changed := false
		out := make(map[string]any, len(typed))
		masked := commandArgsMasked(typed)
		for key, entry := range typed {
			if value, ok := masked[key]; ok {
				entry, changed = value, true
			}
			if isSensitiveKey(key) {
				out[key] = RedactedPlaceholder
				changed = true
				continue
			}
			redacted, entryChanged := redactValue(entry)
			out[key] = redacted
			changed = changed || entryChanged
		}
		return out, changed
	case []any:
		changed := false
		out := make([]any, len(typed))
		masked := argvMasked(typed)
		changed = masked != nil
		for index, entry := range typed {
			if masked != nil {
				entry = masked[index]
			}
			redacted, entryChanged := redactValue(entry)
			out[index] = redacted
			changed = changed || entryChanged
		}
		return out, changed
	default:
		return value, false
	}
}

// RedactValue is RedactJSON for any decoded JSON value: a string is run
// through RedactText, and an object or array is redacted as RedactJSON
// redacts one.
func RedactValue(value any) (any, bool) {
	return redactValue(value)
}

// argvMasked is an array with what the command rules mask in its strings,
// read as one argument vector (["mysql", "-pX"]), written as placeholders,
// or nil when they mask nothing. Other entries stay as they are.
func argvMasked(entries []any) []any {
	var argv []string
	var at []int
	for index, entry := range entries {
		if text, ok := entry.(string); ok {
			argv = append(argv, text)
			at = append(at, index)
		}
	}
	spans := argvSpans(argv)
	if spans == nil || !slices.ContainsFunc(spans, func(s []Span) bool { return len(s) > 0 }) {
		return nil
	}
	out := slices.Clone(entries)
	for i, index := range at {
		if len(spans[i]) > 0 {
			out[index] = maskText(argv[i], spans[i])
		}
	}
	return out
}

// commandArgsMasked reads a {"command": "mysql", "args": ["-pX"]} pair as
// one argument vector and returns the entries the command rules change.
func commandArgsMasked(object map[string]any) map[string]any {
	command, ok := object["command"].(string)
	args, isArray := object["args"].([]any)
	if !ok || !isArray {
		return nil
	}
	masked := argvMasked(append([]any{command}, args...))
	if masked == nil {
		return nil
	}
	out := map[string]any{}
	if text, _ := masked[0].(string); text != command {
		out["command"] = text
	}
	for index, arg := range args {
		if text, isText := arg.(string); isText && masked[index+1] != text {
			out["args"] = masked[1:]
			break
		}
	}
	return out
}

// maskText is text with each span (sorted and apart) as a placeholder.
func maskText(text string, spans []Span) string {
	var out strings.Builder
	at := 0
	for _, span := range spans {
		out.WriteString(text[at:span.Start])
		out.WriteString(RedactedPlaceholder)
		at = span.End
	}
	out.WriteString(text[at:])
	return out.String()
}
