package browserevents

import (
	"context"
	"encoding/json"
	"errors"
)

// Handler answers the extension's messages for the daemon.
type Handler struct {
	// Store is nil when it could not be opened; every message is then
	// answered "unavailable".
	Store *Store
	// CaptureMode is the Data collection step to send the extension
	// (CaptureCommands, CaptureFull or CapturePrompts). Nil reads as
	// CaptureCommands, the most restrictive.
	CaptureMode func() string
	// Changed, when set, is told that the store has rows to send.
	Changed func()
	// Refresh, if set, binds the store to the current enrollment. A hello
	// calls it, so a new connection learns of an enrollment change at once.
	// If it fails, the enrollment is not known and the answer is
	// unavailable.
	Refresh func(context.Context) error
	// Logf reports what the extension cannot be told.
	Logf func(format string, args ...any)
}

// Answer handles one message and returns the answer to write back. It never
// fails: a message it cannot take gets an error answer.
func (h *Handler) Answer(ctx context.Context, raw json.RawMessage) json.RawMessage {
	msg, err := DecodeMessage(raw)
	if errors.Is(err, ErrUnsupportedContract) {
		return encode(NewError(ErrorUnsupportedContract))
	}
	if err != nil {
		h.logf("browser events: refused a message: %v", err)
		return encode(NewError(ErrorInvalidMessage))
	}
	if h.Store == nil {
		return encode(NewError(ErrorUnavailable))
	}
	if msg.Type == TypeHello && h.Refresh != nil {
		if err := h.Refresh(ctx); err != nil {
			h.logf("browser events: could not confirm the enrollment: %v", err)
			return encode(NewError(ErrorUnavailable))
		}
	}
	enrollment, confirmed := h.Store.Confirmed()
	if !confirmed {
		// Not a change of enrollment: the extension keeps its counts and
		// asks again.
		return encode(NewError(ErrorUnavailable))
	}
	settings := h.settings()
	settings.Enrollment = enrollment
	if msg.Type == TypeHello {
		return encode(settings)
	}
	valid, rejected, err := DecodeRecords(msg.Records)
	if err != nil {
		h.logf("browser events: refused records: %v", err)
		return encode(NewError(ErrorInvalidMessage))
	}
	applied, err := h.Store.Apply(msg.Extension, msg.Enrollment, valid)
	if err != nil {
		h.logf("browser events: store: %v", err)
		return encode(NewError(ErrorUnavailable))
	}
	// The answer names the enrollment the records were judged by, so an
	// extension refused for an old one learns the new one from it.
	settings.Enrollment = applied.Enrollment
	rejected = append(rejected, applied.Rejected...)
	if rejected == nil {
		rejected = []Rejection{}
	}
	settings.Accepted = len(valid) - len(applied.Rejected)
	settings.Rejected = rejected
	if settings.Accepted > 0 && h.Changed != nil {
		h.Changed()
	}
	return encode(settings)
}

func (h *Handler) settings() Settings {
	mode := CaptureCommands
	if h.CaptureMode != nil {
		switch m := h.CaptureMode(); m {
		case CaptureFull, CapturePrompts:
			mode = m
		}
	}
	return Settings{
		Contract: Contract, Type: TypeSettings, CaptureMode: mode,
		// Both get a server source with the endpoint configuration; until
		// then the daemon has none and never pauses the extension.
		CorporateDomains: []string{}, Paused: false,
		Rejected: []Rejection{},
	}
}

func (h *Handler) logf(format string, args ...any) {
	if h.Logf != nil {
		h.Logf(format, args...)
	}
}

func encode(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
