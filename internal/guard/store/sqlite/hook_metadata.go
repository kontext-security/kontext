package sqlite

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// hookMetadata records only what the provider supplied. Duration is the
// provider's execution duration, not the elapsed time between received hooks;
// permission_mode is not Kontext's observe/enforce mode. Missing fields remain
// absent, including on historical rows. This is evidence, not policy input.
func hookMetadata(event risk.HookEvent, errorRedacted string) map[string]any {
	metadata := map[string]any{}
	// The ledger exporter and hosted JavaScript API use float64 JSON numbers.
	// Omit invalid durations before hashing/signing rather than let an unsafe
	// integer round during export and invalidate the receipt. Match the hosted
	// hook-metadata contract; explicit zero is still valid.
	const maxSafeDurationMs = int64(1<<53 - 1)
	if event.DurationMs != nil && *event.DurationMs >= 0 && *event.DurationMs <= maxSafeDurationMs {
		metadata["duration_ms"] = *event.DurationMs
	}
	if event.IsInterrupt != nil {
		metadata["is_interrupt"] = *event.IsInterrupt
	}
	if event.PermissionMode != "" {
		metadata["permission_mode"] = redactHookText(event.PermissionMode, 256)
	}
	if errorRedacted != "" {
		metadata["error_redacted"] = errorRedacted
	}
	return metadata
}

// Bound work on untrusted provider text. Redact before truncating so a secret
// crossing the display limit cannot leave an unredacted prefix in evidence.
func redactHookText(value string, maxBytes int) string {
	if value == "" {
		return ""
	}
	const maxRedactionInputBytes = 1 << 20
	if len(value) > maxRedactionInputBytes {
		return "[omitted: hook metadata exceeds redaction limit]"
	}
	redacted, _ := payloadcapture.RedactText(value)
	if len(redacted) <= maxBytes {
		return redacted
	}
	end := maxBytes - len("...")
	for end > 0 && !utf8.RuneStart(redacted[end]) {
		end--
	}
	return redacted[:end] + "..."
}

// Keep the exact JSON values (not float64-decoded numbers) when carrying
// metadata from the persisted context into a new signed receipt.
func hookMetadataFromContext(contextJSON string) json.RawMessage {
	var context struct {
		HookMetadata json.RawMessage `json:"hook_metadata"`
	}
	if err := json.Unmarshal([]byte(contextJSON), &context); err != nil {
		return nil
	}
	return context.HookMetadata
}
