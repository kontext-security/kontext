package payloadcapture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"unicode/utf8"
)

// Mode controls how much of a tool payload is captured. It is org policy,
// resolved elsewhere; this package only executes it.
type Mode string

const (
	// ModeOmitted records that a payload existed and how large it was,
	// without content and without a fingerprint.
	ModeOmitted Mode = "omitted"
	// ModeSummary is the default: no captured payload record is produced.
	ModeSummary Mode = "summary"
	// ModeFull captures the redacted payload, truncating oversized content.
	ModeFull Mode = "full"
)

// RuntimeConfiguration is the atomic evidence snapshot applied to one
// recorded decision. ConfiguredMode records the validated server directive;
// EffectiveMode records the privacy-safe mode actually used for capture.
type RuntimeConfiguration struct {
	ConfiguredMode Mode   `json:"configured_mode"`
	EffectiveMode  Mode   `json:"effective_mode"`
	ConfigIdentity string `json:"config_identity,omitempty"`
	Confirmed      bool   `json:"confirmed"`
	FallbackReason string `json:"fallback_reason,omitempty"`
	// WorkTypeClassification is the workspace's work-type switch from the
	// same directive, deciding whether turn records carry prompt excerpts.
	// It travels with the capture mode so each turn snapshots both at once,
	// and stays out of the serialized evidence recorded on every action.
	WorkTypeClassification bool `json:"-"`
}

func DefaultRuntimeConfiguration() RuntimeConfiguration {
	return RuntimeConfiguration{
		ConfiguredMode: ModeSummary,
		EffectiveMode:  ModeSummary,
		FallbackReason: "no_confirmed_config",
	}
}

// SafeRuntimeConfiguration prevents malformed or unconfirmed state from
// enabling capture. It retains configured evidence while forcing effective
// behavior to summary.
func SafeRuntimeConfiguration(config RuntimeConfiguration) RuntimeConfiguration {
	config.ConfiguredMode = NormalizeMode(string(config.ConfiguredMode))
	config.EffectiveMode = NormalizeMode(string(config.EffectiveMode))
	if !config.Confirmed || config.ConfigIdentity == "" {
		config.Confirmed = false
		config.EffectiveMode = ModeSummary
		config.WorkTypeClassification = false
		if config.FallbackReason == "" {
			config.FallbackReason = "unconfirmed"
		}
	}
	if config.Confirmed {
		config.FallbackReason = ""
	}
	return config
}

// NormalizeMode maps an org-policy mode string to a Mode. Absent ("") or
// unrecognized values normalize to ModeSummary: an unknown mode must never
// mean "send content".
func NormalizeMode(raw string) Mode {
	switch Mode(raw) {
	case ModeOmitted, ModeSummary, ModeFull:
		return Mode(raw)
	default:
		return ModeSummary
	}
}

// FailureReason explains a capture_failed record. Failures never carry
// payload content.
type FailureReason string

const (
	ReasonSerializationError   FailureReason = "serialization_error"
	ReasonRedactionError       FailureReason = "redaction_error"
	ReasonSizePrecheckExceeded FailureReason = "size_precheck_exceeded"
	ReasonInvalidPayload       FailureReason = "invalid_payload"
)

const (
	// MaxPayloadBytes caps the serialized captured payload record. The fit
	// test applies to the WHOLE serialized record, not the content alone:
	// JSON escaping can inflate content substantially.
	MaxPayloadBytes = 64_000
	// InputHardCapBytes bounds the raw canonical input this package will
	// process at all.
	InputHardCapBytes = 1 << 20
)

const (
	modeFullTruncated = "full_truncated"
	modeFailed        = "capture_failed"
)

// Payload is one captured tool payload record. Exactly one of the shapes
// implied by Mode is serialized; illegal field combinations are not
// representable on the wire (see MarshalJSON).
type Payload struct {
	Mode             string
	Value            map[string]any
	Preview          string
	Redacted         bool
	Reason           FailureReason
	SourceSha256     string
	SourceByteLength int
	StoredSha256     string
	StoredByteLength int

	hasSourceCommitment bool
}

// MarshalJSON emits only the fields that belong to the record's mode.
//
// It uses a value receiver on purpose: encoding/json only finds
// pointer-receiver marshalers on addressable values, and a value receiver
// works for both Payload and *Payload. Output is encoded without HTML
// escaping so serializedSize measures what JSON consumers measure.
func (p Payload) MarshalJSON() ([]byte, error) {
	record := map[string]any{"mode": p.Mode}
	switch p.Mode {
	case string(ModeOmitted):
		record["sourceByteLength"] = p.SourceByteLength
	case string(ModeFull):
		record["value"] = p.Value
		p.fillContentFields(record)
	case modeFullTruncated:
		record["preview"] = p.Preview
		p.fillContentFields(record)
	case modeFailed:
		record["reason"] = p.Reason
		if p.hasSourceCommitment {
			record["sourceSha256"] = p.SourceSha256
			record["sourceByteLength"] = p.SourceByteLength
		}
	default:
		return nil, fmt.Errorf("payloadcapture: unknown mode %q", p.Mode)
	}
	return marshalNoEscape(record)
}

func marshalNoEscape(value any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func (p Payload) fillContentFields(record map[string]any) {
	record["redacted"] = p.Redacted
	record["redactorVersion"] = RedactorVersion
	record["sourceSha256"] = p.SourceSha256
	record["sourceByteLength"] = p.SourceByteLength
	record["storedSha256"] = p.StoredSha256
	record["storedByteLength"] = p.StoredByteLength
}

// Capture turns a decoded tool payload into a captured payload record.
//
// It returns nil when nothing should be recorded: empty input, summary mode,
// or an unrecognized mode (unknown never means "send content"). Every error
// path returns a capture_failed record and never any input content. The
// returned record does not alias the input: mutating input after Capture
// cannot change the record, and vice versa.
func Capture(input map[string]any, mode Mode) *Payload {
	if len(input) == 0 {
		return nil
	}
	if mode != ModeOmitted && mode != ModeFull {
		return nil
	}

	canonical, err := CanonicalJSON(input)
	if err != nil {
		return failedPayload(ReasonSerializationError)
	}
	if len(canonical) > InputHardCapBytes {
		return failedPayload(ReasonSizePrecheckExceeded)
	}

	sourceSha := sha256Hex(canonical)
	sourceLen := len(canonical)

	if mode == ModeOmitted {
		return &Payload{
			Mode:             string(ModeOmitted),
			SourceByteLength: sourceLen,
		}
	}

	return captureFull(input, sourceSha, sourceLen)
}

func captureFull(input map[string]any, sourceSha string, sourceLen int) (payload *Payload) {
	// Redaction runs on untrusted content; any panic must degrade to a
	// content-free failure record instead of escaping with raw data.
	defer func() {
		if recover() != nil {
			payload = failedWithCommitment(ReasonRedactionError, sourceSha, sourceLen)
		}
	}()

	redactedValue, changed := RedactJSON(input)
	redactedCanonical, err := CanonicalJSON(redactedValue)
	if err != nil {
		return failedWithCommitment(ReasonRedactionError, sourceSha, sourceLen)
	}

	full := &Payload{
		Mode:             string(ModeFull),
		Value:            redactedValue,
		Redacted:         changed,
		SourceSha256:     sourceSha,
		SourceByteLength: sourceLen,
		StoredSha256:     sha256Hex(redactedCanonical),
		StoredByteLength: len(redactedCanonical),
	}
	size, err := serializedSize(full)
	if err != nil {
		// A record we cannot serialize must not degrade into a bogus
		// truncation of content that was never too large.
		return failedWithCommitment(ReasonSerializationError, sourceSha, sourceLen)
	}
	if size <= MaxPayloadBytes {
		return full
	}

	return truncatedPayload(redactedCanonical, changed, sourceSha, sourceLen)
}

// truncatedPayload cuts the redacted canonical string so that the WHOLE
// serialized record fits MaxPayloadBytes. The cut lands on a UTF-8 boundary
// and is deterministic: identical input, mode, and ruleset version produce
// identical bytes.
func truncatedPayload(redactedCanonical []byte, changed bool, sourceSha string, sourceLen int) *Payload {
	marker := fmt.Sprintf("[truncated %d bytes total]", len(redactedCanonical))

	build := func(cut int) *Payload {
		preview := string(redactedCanonical[:cut]) + marker
		return &Payload{
			Mode:             modeFullTruncated,
			Preview:          preview,
			Redacted:         changed,
			SourceSha256:     sourceSha,
			SourceByteLength: sourceLen,
			StoredSha256:     sha256Hex([]byte(preview)),
			StoredByteLength: len(preview),
		}
	}

	fits := func(cut int) bool {
		size, err := serializedSize(build(cut))
		return err == nil && size <= MaxPayloadBytes
	}

	// The envelope plus marker is a few hundred bytes; if even a
	// content-free preview cannot fit, something is structurally wrong
	// with the record — fail closed rather than emit an oversized one.
	if !fits(0) {
		return failedWithCommitment(ReasonSerializationError, sourceSha, sourceLen)
	}

	// fits is monotone in the cut (larger preview, larger record), so
	// sort.Search finds the first cut that no longer fits; the largest
	// fitting cut is its boundary-snapped predecessor. The search space
	// deliberately stops at len-1: a full_truncated record must always
	// remove at least one byte, so the mode stays honest even if the
	// string-preview envelope happens to be smaller than the full record's
	// object envelope for the same content.
	firstTooBig := sort.Search(len(redactedCanonical), func(cut int) bool {
		return !fits(utf8Boundary(redactedCanonical, cut))
	})

	return build(utf8Boundary(redactedCanonical, firstTooBig-1))
}

// utf8Boundary clamps cut into range and moves it backwards until it does
// not split a multi-byte rune. A cut may still land inside a JSON escape
// sequence within the canonical string; the preview is an opaque string, not
// parseable JSON, so that is accepted.
func utf8Boundary(data []byte, cut int) int {
	if cut > len(data) {
		cut = len(data)
	}
	for cut > 0 && cut < len(data) && !utf8.RuneStart(data[cut]) {
		cut--
	}
	return cut
}

// serializedSize measures the record the way JSON consumers measure it:
// MarshalJSON already emits the final, HTML-escape-free bytes. One remaining
// divergence is accepted as conservative: encoding/json always escapes
// U+2028/U+2029 (6 bytes) where other serializers emit them raw (3 bytes),
// so this measurement can only overcount, never undercount, against the cap.
func serializedSize(payload *Payload) (int, error) {
	raw, err := payload.MarshalJSON()
	if err != nil {
		return 0, err
	}
	return len(raw), nil
}

func failedPayload(reason FailureReason) *Payload {
	return &Payload{Mode: modeFailed, Reason: reason}
}

func failedWithCommitment(reason FailureReason, sourceSha string, sourceLen int) *Payload {
	return &Payload{
		Mode:                modeFailed,
		Reason:              reason,
		SourceSha256:        sourceSha,
		SourceByteLength:    sourceLen,
		hasSourceCommitment: true,
	}
}
