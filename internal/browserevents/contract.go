// Package browserevents is the daemon's side of the browser extension: the
// event contract (browser/contract), the per-day snapshots it keeps, and the
// batches it sends to the cloud.
package browserevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// Contract is the version of the browser event contract this build speaks.
const Contract = 1

// CloudSchema names the batch the daemon sends to the cloud.
const CloudSchema = "browser-activity-v1"

// Limits from the contract. A message over MaxMessageBytes is refused before
// it is decoded.
const (
	MaxMessageBytes      = 1 << 20
	MaxRecordsPerMessage = 200
	MaxRecordsPerBatch   = 500
	MaxRequestsPerDay    = 100000
)

// Message types.
const (
	TypeHello    = "hello"
	TypeRecords  = "records"
	TypeSettings = "settings"
	TypeError    = "error"
)

// Record kinds in contract v1.
const (
	KindHealth = "health"
	KindVisit  = "visit"
)

// Answers to a message that cannot be taken.
const (
	ErrorUnsupportedContract = "unsupported_contract"
	ErrorInvalidMessage      = "invalid_message"
	ErrorUnavailable         = "unavailable"
)

// Capture steps, as the dashboard's Data collection setting names them.
const (
	CaptureCommands = "commands"
	CaptureFull     = "full"
	CapturePrompts  = "prompts"
)

var (
	profilePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	appPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	hostPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	dayPattern     = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
	installPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)
)

// Extension says which extension, browser and profile a message came from.
// Profile is a random id the extension makes, never the profile's email.
type Extension struct {
	Version string `json:"version"`
	Browser string `json:"browser"`
	Profile string `json:"profile"`
}

// Record is one health or visit record. Fields that belong to the other kind
// stay empty.
type Record struct {
	Kind string `json:"kind"`

	// health
	ConnectedSince string `json:"connected_since,omitempty"`
	ObservedAt     string `json:"observed_at,omitempty"`

	// visit
	Day       string `json:"day,omitempty"`
	App       string `json:"app,omitempty"`
	AppName   string `json:"app_name,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Surface   string `json:"surface,omitempty"`
	Host      string `json:"host,omitempty"`
	FirstSeen string `json:"first_seen,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Requests  int    `json:"requests,omitempty"`
}

// Message is what the extension sends: a hello, or records.
type Message struct {
	Contract  int             `json:"contract"`
	Type      string          `json:"type"`
	Extension Extension       `json:"extension"`
	Records   json.RawMessage `json:"records,omitempty"`
}

// Rejection names a record that was not taken, by its index in the message
// or batch, and why.
type Rejection struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// Settings is the daemon's answer to every message.
type Settings struct {
	Contract         int         `json:"contract"`
	Type             string      `json:"type"`
	CaptureMode      string      `json:"capture_mode"`
	CorporateDomains []string    `json:"corporate_domains"`
	Paused           bool        `json:"paused"`
	Accepted         int         `json:"accepted"`
	Rejected         []Rejection `json:"rejected"`
}

// ErrorAnswer is the daemon's answer to a message it cannot take at all.
type ErrorAnswer struct {
	Contract int    `json:"contract"`
	Type     string `json:"type"`
	Error    string `json:"error"`
}

// NewError is the answer for code.
func NewError(code string) ErrorAnswer {
	return ErrorAnswer{Contract: Contract, Type: TypeError, Error: code}
}

// CloudRecord is a record as the cloud gets it, with the browser, profile and
// extension version it came from.
type CloudRecord struct {
	Browser          string `json:"browser"`
	Profile          string `json:"profile"`
	ExtensionVersion string `json:"extension_version"`
	Record
}

// CloudBatch is the body of POST /api/v1/browser-activity/batches.
type CloudBatch struct {
	Schema         string        `json:"schema"`
	InstallationID string        `json:"installation_id"`
	SentAt         string        `json:"sent_at"`
	Records        []CloudRecord `json:"records"`
}

// CloudResponse is the cloud's answer: records it took and records it
// rejected, which are dropped, not sent again.
type CloudResponse struct {
	Accepted int         `json:"accepted"`
	Rejected []Rejection `json:"rejected"`
}

// ErrUnsupportedContract is returned for a message of another contract
// version.
var ErrUnsupportedContract = errors.New("browser events: unsupported contract version")

// DecodeMessage reads one message from the extension. Unknown fields are
// ignored. It returns ErrUnsupportedContract for another version, and an
// error for a message that is not a valid hello or records message. Records
// are checked one by one with DecodeRecords, so one bad record does not
// refuse the others.
func DecodeMessage(data []byte) (Message, error) {
	if len(data) > MaxMessageBytes {
		return Message{}, fmt.Errorf("browser events: message exceeds %d bytes", MaxMessageBytes)
	}
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return Message{}, fmt.Errorf("browser events: decode message: %w", err)
	}
	if msg.Contract != Contract {
		return Message{}, ErrUnsupportedContract
	}
	if err := msg.Extension.validate(); err != nil {
		return Message{}, err
	}
	switch msg.Type {
	case TypeHello:
		return msg, nil
	case TypeRecords:
		if len(bytes.TrimSpace(msg.Records)) == 0 {
			return Message{}, errors.New("browser events: records message without records")
		}
		return msg, nil
	default:
		return Message{}, fmt.Errorf("browser events: unknown message type %q", msg.Type)
	}
}

// DecodeRecords checks each record of a records message. It returns the
// valid ones with their index in the message, and a rejection for each other
// one. The whole array is refused only when it is not an array of 1 to
// MaxRecordsPerMessage entries.
func DecodeRecords(raw json.RawMessage) ([]IndexedRecord, []Rejection, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, nil, fmt.Errorf("browser events: records is not an array: %w", err)
	}
	if len(items) == 0 || len(items) > MaxRecordsPerMessage {
		return nil, nil, fmt.Errorf("browser events: %d records, want 1 to %d", len(items), MaxRecordsPerMessage)
	}
	var valid []IndexedRecord
	var rejected []Rejection
	for i, item := range items {
		var record Record
		if err := json.Unmarshal(item, &record); err != nil {
			rejected = append(rejected, Rejection{Index: i, Reason: "not a record"})
			continue
		}
		record = record.own()
		if err := record.Validate(); err != nil {
			rejected = append(rejected, Rejection{Index: i, Reason: err.Error()})
			continue
		}
		valid = append(valid, IndexedRecord{Index: i, Record: record})
	}
	return valid, rejected, nil
}

// IndexedRecord is a valid record and its index in the message.
type IndexedRecord struct {
	Index  int
	Record Record
}

func (e Extension) validate() error {
	if !versionPattern.MatchString(e.Version) {
		return errors.New("browser events: extension version must be X.Y.Z")
	}
	switch e.Browser {
	case "chrome", "edge", "chromium":
	default:
		return fmt.Errorf("browser events: unknown browser %q", e.Browser)
	}
	if !profilePattern.MatchString(e.Profile) {
		return errors.New("browser events: profile must be a random id of 8 to 64 letters, digits, - or _")
	}
	return nil
}

// own keeps only the fields of the record's kind. The schema ignores fields
// it does not name, so a health record may carry a visit's fields; those are
// never checked, and must not travel on to the store or the cloud.
func (r Record) own() Record {
	switch r.Kind {
	case KindHealth:
		return Record{Kind: r.Kind, ConnectedSince: r.ConnectedSince, ObservedAt: r.ObservedAt}
	case KindVisit:
		visit := r
		visit.ConnectedSince, visit.ObservedAt = "", ""
		return visit
	default:
		return Record{Kind: r.Kind}
	}
}

// Validate checks a record against the contract. The reasons are short and
// name no values, as they travel back to the extension and into logs. A
// record that carries the other kind's fields is refused, so a batch built
// from anything but DecodeRecords is held to the same rule.
func (r Record) Validate() error {
	if r != r.own() {
		return errors.New("record carries fields of another kind")
	}
	switch r.Kind {
	case KindHealth:
		if !isTime(r.ConnectedSince) || !isTime(r.ObservedAt) {
			return errors.New("health needs connected_since and observed_at")
		}
		return nil
	case KindVisit:
		if !isDay(r.Day) {
			return errors.New("visit day must be a UTC date")
		}
		if !appPattern.MatchString(r.App) {
			return errors.New("visit app id is invalid")
		}
		if !isLabel(r.AppName) || !isLabel(r.Provider) {
			return errors.New("visit app_name and provider are required")
		}
		if r.Surface != "web" {
			return errors.New("visit surface must be web")
		}
		if len(r.Host) > 253 || !hostPattern.MatchString(r.Host) {
			return errors.New("visit host must be a bare hostname")
		}
		if !isTime(r.FirstSeen) || !isTime(r.LastSeen) {
			return errors.New("visit needs first_seen and last_seen")
		}
		if r.Requests < 1 || r.Requests > MaxRequestsPerDay {
			return errors.New("visit requests out of range")
		}
		return nil
	default:
		return errors.New("unknown record kind")
	}
}

// Validate checks a batch before it is sent.
func (b CloudBatch) Validate() error {
	if b.Schema != CloudSchema {
		return fmt.Errorf("browser events: batch schema must be %s", CloudSchema)
	}
	if !installPattern.MatchString(b.InstallationID) {
		return errors.New("browser events: invalid installation id")
	}
	if !isTime(b.SentAt) {
		return errors.New("browser events: sent_at must be RFC 3339")
	}
	if len(b.Records) == 0 || len(b.Records) > MaxRecordsPerBatch {
		return fmt.Errorf("browser events: %d records in a batch, want 1 to %d", len(b.Records), MaxRecordsPerBatch)
	}
	for i, record := range b.Records {
		source := Extension{Version: record.ExtensionVersion, Browser: record.Browser, Profile: record.Profile}
		if err := source.validate(); err != nil {
			return fmt.Errorf("browser events: record %d: %w", i, err)
		}
		if err := record.Record.Validate(); err != nil {
			return fmt.Errorf("browser events: record %d: %w", i, err)
		}
	}
	return nil
}

func isTime(value string) bool {
	if value == "" || len(value) > 40 {
		return false
	}
	_, err := time.Parse(time.RFC3339, value)
	return err == nil
}

func isDay(value string) bool {
	if !dayPattern.MatchString(value) {
		return false
	}
	_, err := time.Parse(time.DateOnly, value)
	return err == nil
}

// isLabel counts characters, as the schema's maxLength does, not bytes.
func isLabel(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 80
}
