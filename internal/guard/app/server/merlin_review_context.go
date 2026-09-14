package server

import (
	"encoding/json"
	"regexp"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// Capture the evidence at the assessed action, before the session advances.
// This separately bounded, redacted review input never changes Merlin's input.
func merlinReviewContext(request, history string) *risk.MerlinReviewContext {
	request = redactMerlinReviewText(request)
	var events []any
	if json.Unmarshal([]byte(history), &events) == nil {
		// Observations contain serialized tool responses. Decode them before
		// key-based redaction, including secrets with otherwise ordinary values.
		for _, event := range events {
			if object, ok := event.(map[string]any); ok {
				if observation, ok := object["observation"].(string); ok {
					var response any
					if json.Unmarshal([]byte(observation), &response) == nil {
						object["observation"] = response
					}
				}
			}
		}
		// Redact full URL credentials before the shared HTTP rule can remove
		// the scheme and leave a password suffix that no longer looks like a URL.
		redacted, _ := payloadcapture.RedactJSON(map[string]any{"events": redactMerlinReviewURLValues(events)})
		encoded, err := json.Marshal(redacted["events"])
		if err == nil {
			history = redactMerlinReviewText(string(encoded))
		} else {
			history = ""
		}
	} else {
		history = ""
	}
	request, requestCut := boundedReviewText(request, 2000)
	history, historyCut := boundedReviewText(history, 6000)
	return &risk.MerlinReviewContext{UserRequest: request, InteractionHistory: history, Truncated: requestCut || historyCut}
}

func boundedReviewText(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	const marker = "\n[Context omitted]\n"
	head := (limit - len(marker)) / 2
	tail := len(value) - (limit - len(marker) - head)
	for head > 0 && !utf8.RuneStart(value[head]) {
		head--
	}
	for tail < len(value) && !utf8.RuneStart(value[tail]) {
		tail++
	}
	return value[:head] + marker + value[tail:], true
}

// Tool errors can contain connection URLs outside the shared HTTP-only rules.
// Match through the last @ in the authority, including literal password @s.
var merlinReviewURLUserinfo = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)[^/?#\s"'<>]+@`)

func redactMerlinReviewURLValues(value any) any {
	switch typed := value.(type) {
	case string:
		return merlinReviewURLUserinfo.ReplaceAllString(typed, "${1}"+payloadcapture.RedactedPlaceholder+"@")
	case map[string]any:
		for key, child := range typed {
			typed[key] = redactMerlinReviewURLValues(child)
		}
	case []any:
		for i, child := range typed {
			typed[i] = redactMerlinReviewURLValues(child)
		}
	}
	return value
}

func redactMerlinReviewText(value string) string {
	value = merlinReviewURLUserinfo.ReplaceAllString(value, "${1}"+payloadcapture.RedactedPlaceholder+"@")
	value, _ = payloadcapture.RedactText(value)
	return value
}
