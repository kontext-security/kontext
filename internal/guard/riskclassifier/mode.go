package riskclassifier

import (
	"fmt"
	"strings"
)

// Mode governs whether the guardrail LLM runs. The SVM is embedded and always
// runs; the LLM needs a local endpoint and costs a round trip plus inference
// (~44 ms against a local Qwen3-0.6B) rather than the SVM's microseconds.
//
// Either way the risk verdict is an annotation on the tool call, never a
// decision. It is computed in the hook path but only after the decision is
// final, and nothing in the guard consults it. Gating on it is a separate,
// later choice.
type Mode string

const (
	// ModeOff records the SVM alone. No LLM, no sidecar needed.
	ModeOff Mode = "off"

	// ModeOn records both models.
	ModeOn Mode = "on"
)

// DefaultMode records both models when an endpoint is available.
const DefaultMode = ModeOn

// ParseMode normalizes a configured mode, defaulting when empty.
func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return DefaultMode, nil
	case ModeOff:
		return ModeOff, nil
	case ModeOn:
		return ModeOn, nil
	default:
		return "", fmt.Errorf("unknown risk classifier mode %q (want on or off)", value)
	}
}

// UsesLLM reports whether the mode needs a guardrail endpoint at all.
func (m Mode) UsesLLM() bool {
	return m == ModeOn
}
