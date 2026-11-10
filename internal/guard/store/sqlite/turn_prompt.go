package sqlite

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/modelusage"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const MaxTurnPromptBytes = 1 << 20
const TurnExcerptBytes = 64_000

// CaptureTurnPrompt applies the same capture policy, redaction and bounds to
// hook prompts and recovered transcript prompts.
func CaptureTurnPrompt(prompt string, capture payloadcapture.RuntimeConfiguration) TurnPrompt {
	capture = payloadcapture.SafeRuntimeConfiguration(capture)
	chars := int64(utf8.RuneCountInString(prompt))
	if capture.EffectiveMode == payloadcapture.ModeOmitted {
		return SizeOnlyTurnPrompt(TurnPromptOmitted, chars)
	}
	if !capture.WorkTypeClassification || len(prompt) > MaxTurnPromptBytes {
		return SizeOnlyTurnPrompt(TurnPromptSkipped, chars)
	}
	digest := sha256.Sum256([]byte(strings.Join(strings.Fields(prompt), " ")))
	text, _ := payloadcapture.RedactText(modelusage.HarnessBlocks.ReplaceAllString(prompt, " "))
	text = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text)), " ")
	const limit = TurnExcerptBytes
	truncated := len(text) > limit
	if truncated {
		const marker = "\n[Context omitted]\n"
		head := (limit - len(marker)) / 2
		tail := len(text) - (limit - len(marker) - head)
		for head > 0 && !utf8.RuneStart(text[head]) {
			head--
		}
		for tail < len(text) && !utf8.RuneStart(text[tail]) {
			tail++
		}
		text = text[:head] + marker + text[tail:]
	}
	return ExcerptTurnPrompt(text, chars, truncated, hex.EncodeToString(digest[:]))
}
