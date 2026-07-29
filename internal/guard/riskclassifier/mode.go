package riskclassifier

import (
	"fmt"
	"strings"
)

// Mode selects where the guardrail LLM runs relative to the hook path.
//
// The SVM is embedded and always runs; this only governs the LLM, whose cost is
// a network round trip plus inference (~44 ms warm against a local
// Qwen3-0.6B) rather than the SVM's microseconds.
type Mode string

const (
	// ModeOff records the SVM alone. No LLM, no sidecar needed.
	ModeOff Mode = "off"

	// ModeAsync classifies off the hook path: the verdict lands in the feedback
	// log and cannot affect or delay the tool call. This is the default — it
	// collects the data the classifier exists to collect while keeping the
	// LLM's precision out of anything user-visible.
	ModeAsync Mode = "async"

	// ModeSync puts the LLM on the decision path, where it replaces the JSON
	// judge as the probabilistic layer for shell commands and its verdict is
	// recorded without a second inference. It adds inference latency to every
	// gated bash call, and in enforce mode its false-positive rate becomes
	// false blocks — see docs/guard.md before turning this on.
	ModeSync Mode = "sync"
)

// DefaultMode is async: measured latency makes sync affordable, but the
// guardrail's precision is not yet good enough to gate on.
const DefaultMode = ModeAsync

// ParseMode normalizes a configured mode, defaulting when empty.
func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "":
		return DefaultMode, nil
	case ModeOff:
		return ModeOff, nil
	case ModeAsync:
		return ModeAsync, nil
	case ModeSync:
		return ModeSync, nil
	default:
		return "", fmt.Errorf("unknown risk classifier mode %q (want off, async, or sync)", value)
	}
}

// UsesLLM reports whether the mode needs a guardrail endpoint at all.
func (m Mode) UsesLLM() bool {
	return m == ModeAsync || m == ModeSync
}
