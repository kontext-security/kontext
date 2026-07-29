package payloadcapture

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
		for key, entry := range typed {
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
		for index, entry := range typed {
			redacted, entryChanged := redactValue(entry)
			out[index] = redacted
			changed = changed || entryChanged
		}
		return out, changed
	default:
		return value, false
	}
}
