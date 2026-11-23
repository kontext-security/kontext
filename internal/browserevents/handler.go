package browserevents

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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
	// CorporateDomains are the organisation's email domains, which make a
	// signed-in account a company account. Nil reads as none.
	CorporateDomains func() []string
	// Changed, when set, is told that the store has rows to send.
	Changed func()
	// Logf reports what the extension cannot be told.
	Logf func(format string, args ...any)
}

// Answer handles one message and returns the answer to write back. It never
// fails: a message it cannot take gets an error answer.
func (h *Handler) Answer(_ context.Context, raw json.RawMessage) json.RawMessage {
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
	settings := h.settings()
	settings.Enrollment = h.Store.Enrollment()
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
		// Paused gets a server source with the endpoint configuration;
		// until then the daemon never pauses the extension.
		CorporateDomains: h.corporateDomains(), Paused: false,
		Rejected: []Rejection{},
	}
}

// corporateDomains are the valid, distinct domains of CorporateDomains, at
// most the 50 the contract allows.
func (h *Handler) corporateDomains() []string {
	domains := []string{}
	if h.CorporateDomains == nil {
		return domains
	}
	seen := map[string]bool{}
	for _, domain := range h.CorporateDomains() {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if seen[domain] || len(domain) > 253 || !hostPattern.MatchString(domain) || len(domains) == maxCorporateDomains {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	return domains
}

// maxCorporateDomains is the contract's limit on corporate_domains.
const maxCorporateDomains = 50

// consumerMailDomains are webmail domains that never make an account a
// company one, even when the enrolled user's address is on one of them.
var consumerMailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true,
	"live.com": true, "msn.com": true, "yahoo.com": true, "icloud.com": true, "me.com": true,
	"mac.com": true, "aol.com": true, "gmx.de": true, "gmx.net": true, "web.de": true,
	"t-online.de": true, "proton.me": true, "protonmail.com": true, "pm.me": true,
}

// EmailDomains is the corporate domain of each address: the part after the
// last @, lowercased, unless it is a consumer webmail domain.
func EmailDomains(addresses ...string) []string {
	domains := []string{}
	for _, address := range addresses {
		at := strings.LastIndex(address, "@")
		if at < 0 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(address[at+1:]))
		if domain == "" || consumerMailDomains[domain] {
			continue
		}
		domains = append(domains, domain)
	}
	return domains
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
