// Package browserevents is the daemon's side of the browser extension: the
// event contract (browser/contract), the per-day snapshots it keeps, and the
// batches it sends to the cloud.
package browserevents

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Contract is the version of the browser event contract this build speaks.
const Contract = 2

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

// Record kinds in contract v2.
const (
	KindHealth  = "health"
	KindVisit   = "visit"
	KindAccount = "account"
)

// Account types an account record names: which type of account was signed
// in to an app, never which one, and never its plan. Company is a managed
// workspace (team or enterprise) whose owner is not checked: it may be
// another organisation's, so nothing may treat it as the customer's own on
// this value alone. Personal is any other signed-in account, also on a work
// email. None is the app's answer that nobody is signed in, and unknown an
// answer the extension could not read.
const (
	AccountCompany  = "company"
	AccountPersonal = "personal"
	AccountNone     = "none"
	AccountUnknown  = "unknown"
)

// accountKeys are the only keys an account record may have. An account is
// read from a signed-in page, so a record with any other key is refused
// whole rather than read in part: an address or a token never passes as an
// extra field. It names its app by catalog id and has no host, so no value
// on it is free text: a tenant subdomain or an email domain has no field to
// travel in.
var accountKeys = map[string]bool{
	"kind": true, "day": true, "app": true, "account_type": true, "observed_at": true,
}

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
	timePattern    = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)
	installPattern = regexp.MustCompile(`^ins_[A-Za-z0-9_-]{32}$`)
	// enrollmentPattern is Store.Enrollment's shape, or "" for none yet.
	enrollmentPattern = regexp.MustCompile(`^([0-9a-f]{16})?$`)
	// labelPattern holds a catalog name such as "ChatGPT" or "OpenAI": no
	// punctuation a sentence, path or query would need.
	labelPattern = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} .&+'()-]{0,39}$`)
)

// Field limits beyond the patterns.
const (
	maxVersionLength = 32
	maxReasonLength  = 200
)

// Extension says which extension, browser and profile a message came from.
// Profile is a random id the extension makes, never the profile's email.
type Extension struct {
	Version string `json:"version"`
	Browser string `json:"browser"`
	Profile string `json:"profile"`
}

// Record is one health, visit or account record. Fields that belong to
// another kind stay empty.
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
	// Messages is how many of the requests were sends to the app's
	// message endpoint, approximately: a regenerate or an edit is a send
	// too. Missing reads as 0, as from an extension before it.
	Messages int `json:"messages,omitempty"`

	// account, with day, app and observed_at, and no host: the type alone,
	// never a plan, an address, a domain or a name.
	AccountType string `json:"account_type,omitempty"`
}

// Message is what the extension sends: a hello, or records.
type Message struct {
	Contract  int             `json:"contract"`
	Type      string          `json:"type"`
	Extension Extension       `json:"extension"`
	Records   json.RawMessage `json:"records,omitempty"`
	// Enrollment is the enrollment id the records' visits were recorded
	// under, as the extension last had it from a settings answer.
	Enrollment string `json:"enrollment,omitempty"`
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
	// Enrollment is an opaque id of the enrollment the daemon records
	// under, empty until it has one. When it changes, the extension drops
	// what it kept for the previous one, so nothing recorded for one
	// workspace reaches another.
	Enrollment string `json:"enrollment"`
}

// MarshalJSON writes empty lists as [], as the schema wants arrays, never
// null.
func (s Settings) MarshalJSON() ([]byte, error) {
	type plain Settings
	if s.CorporateDomains == nil {
		s.CorporateDomains = []string{}
	}
	if s.Rejected == nil {
		s.Rejected = []Rejection{}
	}
	return json.Marshal(plain(s))
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

// DecodeMessage reads one message from the extension. It reads the contract
// version before anything else, so a message of another version gets
// ErrUnsupportedContract whatever shape the rest of it has. Unknown fields
// are ignored, whatever their type, and keys match exactly: encoding/json
// would let "Type" overwrite "type". Records are checked one by one with
// DecodeRecords, so one bad record does not refuse the others.
func DecodeMessage(data []byte) (Message, error) {
	if len(data) > MaxMessageBytes {
		return Message{}, fmt.Errorf("browser events: message exceeds %d bytes", MaxMessageBytes)
	}
	fields, err := readObject(data)
	if err != nil {
		return Message{}, fmt.Errorf("browser events: decode message: %w", err)
	}
	if _, ok := fields["contract"]; !ok {
		return Message{}, errors.New("browser events: message without contract")
	}
	version, ok := fields.integer("contract")
	if !ok {
		return Message{}, errors.New("browser events: contract must be an integer")
	}
	if version != Contract {
		return Message{}, ErrUnsupportedContract
	}
	msg := Message{Contract: version}
	msg.Type, _ = fields.text("type")
	extension, err := readObject(fields["extension"])
	if err != nil {
		return Message{}, errors.New("browser events: message without extension")
	}
	msg.Extension.Version, _ = extension.text("version")
	msg.Extension.Browser, _ = extension.text("browser")
	msg.Extension.Profile, _ = extension.text("profile")
	if err := msg.Extension.validate(); err != nil {
		return Message{}, err
	}
	switch msg.Type {
	case TypeHello:
		return msg, nil
	case TypeRecords:
		msg.Records = fields["records"]
		if len(bytes.TrimSpace(msg.Records)) == 0 {
			return Message{}, errors.New("browser events: records message without records")
		}
		enrollment, ok := fields.text("enrollment")
		if !ok || !enrollmentPattern.MatchString(enrollment) {
			return Message{}, errors.New("browser events: records message without an enrollment id")
		}
		msg.Enrollment = enrollment
		return msg, nil
	default:
		return Message{}, errors.New("browser events: unknown message type")
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
	valid := []IndexedRecord{}
	rejected := []Rejection{}
	for i, item := range items {
		record, err := decodeRecord(item)
		if errors.Is(err, errAccountKeys) {
			rejected = append(rejected, Rejection{Index: i, Reason: err.Error()})
			continue
		}
		if err != nil {
			rejected = append(rejected, Rejection{Index: i, Reason: "not a record"})
			continue
		}
		if err := record.Validate(); err != nil {
			rejected = append(rejected, Rejection{Index: i, Reason: err.Error()})
			continue
		}
		valid = append(valid, IndexedRecord{Index: i, Record: record})
	}
	return valid, rejected, nil
}

// errAccountKeys refuses an account record with a key the contract does not
// name for it.
var errAccountKeys = errors.New("account carries a field the contract does not name")

// decodeRecord reads the kind, then only that kind's fields, so a field the
// schema does not name for a health or visit record is ignored whatever its
// type. An account record may have no other key at all. A field of the
// wrong type reads as missing, and Validate names it.
func decodeRecord(data []byte) (Record, error) {
	fields, err := readObject(data)
	if err != nil {
		return Record{}, err
	}
	record := Record{}
	record.Kind, _ = fields.text("kind")
	switch record.Kind {
	case KindHealth:
		record.ConnectedSince, _ = fields.text("connected_since")
		record.ObservedAt, _ = fields.text("observed_at")
	case KindVisit:
		record.Day, _ = fields.text("day")
		record.App, _ = fields.text("app")
		record.AppName, _ = fields.text("app_name")
		record.Provider, _ = fields.text("provider")
		record.Surface, _ = fields.text("surface")
		record.Host, _ = fields.text("host")
		record.FirstSeen, _ = fields.text("first_seen")
		record.LastSeen, _ = fields.text("last_seen")
		record.Requests, _ = fields.integer("requests")
		if _, present := fields["messages"]; present {
			// Optional, but a present count must be one: a wrong type is
			// refused rather than read as zero.
			if n, ok := fields.integer("messages"); ok {
				record.Messages = n
			} else {
				record.Messages = -1
			}
		}
	case KindAccount:
		for key := range fields {
			if !accountKeys[key] {
				return Record{}, errAccountKeys
			}
		}
		record.Day, _ = fields.text("day")
		record.App, _ = fields.text("app")
		record.AccountType, _ = fields.text("account_type")
		record.ObservedAt, _ = fields.text("observed_at")
	}
	return record, nil
}

// DecodeCloudResponse reads the cloud's answer to a batch of sent records.
// The answer must account for every record exactly once: accepted plus the
// rejected, whose indexes are distinct and inside the batch. Anything else,
// such as {} or null from a proxy, is an error, and the batch is not marked
// sent.
func DecodeCloudResponse(data []byte, sent int) (CloudResponse, error) {
	fields, err := readObject(data)
	if err != nil {
		return CloudResponse{}, fmt.Errorf("browser events: cloud answer is not an object: %w", err)
	}
	// The schema tells the answer apart by having no discriminator: a
	// settings answer or a batch echoed back is not proof of ingestion.
	for _, key := range []string{"type", "schema", "contract"} {
		if _, ok := fields[key]; ok {
			return CloudResponse{}, fmt.Errorf("browser events: cloud answer carries %s", key)
		}
	}
	accepted, ok := fields.integer("accepted")
	if !ok || accepted < 0 {
		return CloudResponse{}, errors.New("browser events: cloud answer without accepted")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(fields["rejected"], &items); err != nil || items == nil {
		return CloudResponse{}, errors.New("browser events: cloud answer without rejected")
	}
	response := CloudResponse{Accepted: accepted, Rejected: make([]Rejection, 0, len(items))}
	seen := map[int]bool{}
	for _, item := range items {
		rejection, err := readObject(item)
		if err != nil {
			return CloudResponse{}, errors.New("browser events: cloud rejection is not an object")
		}
		index, ok := rejection.integer("index")
		if !ok || index < 0 || index >= sent || seen[index] {
			return CloudResponse{}, errors.New("browser events: cloud rejection index is out of range or repeated")
		}
		seen[index] = true
		reason, ok := rejection.text("reason")
		if !ok || utf8.RuneCountInString(reason) > maxReasonLength {
			return CloudResponse{}, errors.New("browser events: cloud rejection without a reason")
		}
		response.Rejected = append(response.Rejected, Rejection{Index: index, Reason: reason})
	}
	if accepted+len(response.Rejected) != sent {
		return CloudResponse{}, fmt.Errorf("browser events: cloud answer accounts for %d of %d records",
			accepted+len(response.Rejected), sent)
	}
	return response, nil
}

// object is a JSON object with its keys exactly as sent.
type object map[string]json.RawMessage

func readObject(data []byte) (object, error) {
	var fields object
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if fields == nil {
		return nil, errors.New("not an object")
	}
	return fields, nil
}

// text is the string at key, and whether there is one. JSON null into a Go
// value is no error, so it is caught here.
func (o object) text(key string) (string, bool) {
	var value string
	if o.null(key) {
		return "", false
	}
	if err := json.Unmarshal(o[key], &value); err != nil {
		return "", false
	}
	return value, true
}

// integer is the integer at key, and whether there is one.
func (o object) integer(key string) (int, bool) {
	var value int
	if o.null(key) {
		return 0, false
	}
	if err := json.Unmarshal(o[key], &value); err == nil {
		return value, true
	}
	// JSON Schema counts 3.0 and 3e0 as integers, so they are read as 3. A
	// fraction, or a number past what a count can be, is not an integer.
	// The number is read exactly, never through a float64, which would
	// round 3.0000000000000001 to 3.
	// json.Number also takes a string such as "3", which is not a number.
	raw := bytes.TrimSpace(o[key])
	var number json.Number
	if raw[0] == '"' || json.Unmarshal(raw, &number) != nil {
		return 0, false
	}
	return exactInteger(number.String())
}

// exactInteger reads a JSON number as an int when its exact value is an
// integer within the int32 range, whatever its notation: 3, 3.0, 3e0, 0e-65
// and 3.000 are all read. It works on the digits, never through a float64,
// so 3.0000000000000001 is not an integer, and a huge exponent costs nothing.
func exactInteger(number string) (int, bool) {
	if len(number) > 4096 {
		return 0, false
	}
	mantissa, exponentText, hasExponent := strings.Cut(strings.ToLower(number), "e")
	negative := strings.HasPrefix(mantissa, "-")
	mantissa = strings.TrimPrefix(mantissa, "-")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	// The value is digits × 10^shift.
	shift := -len(fraction)
	trimmed := strings.TrimRight(digits, "0")
	shift += len(digits) - len(trimmed)
	digits = trimmed
	if digits == "" {
		return 0, true
	}
	if hasExponent {
		exponent, err := strconv.Atoi(exponentText)
		if err != nil || exponent < -4096 || exponent > 4096 {
			return 0, false
		}
		shift += exponent
	}
	// digits has no trailing zero, so a negative shift leaves a fraction.
	if shift < 0 || len(digits)+shift > 10 {
		return 0, false
	}
	n, err := strconv.ParseInt(digits+strings.Repeat("0", shift), 10, 64)
	if err != nil {
		return 0, false
	}
	if negative {
		n = -n
	}
	if n > math.MaxInt32 || n < math.MinInt32 {
		return 0, false
	}
	return int(n), true
}

// null reports whether key is missing or null.
func (o object) null(key string) bool {
	value := bytes.TrimSpace(o[key])
	return len(value) == 0 || bytes.Equal(value, []byte("null"))
}

// IndexedRecord is a valid record and its index in the message.
type IndexedRecord struct {
	Index  int
	Record Record
}

func (e Extension) validate() error {
	if len(e.Version) > maxVersionLength || !versionPattern.MatchString(e.Version) {
		return errors.New("browser events: extension version must be X.Y.Z")
	}
	switch e.Browser {
	case "chrome", "edge", "chromium":
	default:
		// The value stays out of the error: errors reach the logs.
		return errors.New("browser events: unknown browser")
	}
	if !profilePattern.MatchString(e.Profile) {
		return errors.New("browser events: profile must be a random id of 8 to 64 letters, digits, - or _")
	}
	return nil
}

// own keeps only the fields of the record's kind. decodeRecord reads no
// others; Validate uses it to refuse a record built any other way that
// carries them, so they never travel on to the store or the cloud.
func (r Record) own() Record {
	switch r.Kind {
	case KindHealth:
		return Record{Kind: r.Kind, ConnectedSince: r.ConnectedSince, ObservedAt: r.ObservedAt}
	case KindVisit:
		visit := r
		visit.ConnectedSince, visit.ObservedAt = "", ""
		visit.AccountType = ""
		return visit
	case KindAccount:
		return Record{
			Kind: r.Kind, Day: r.Day, App: r.App, ObservedAt: r.ObservedAt,
			AccountType: r.AccountType,
		}
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
		app, known := catalog[r.App]
		if !known {
			return errors.New("visit app is not in the catalog")
		}
		if !isLabel(r.AppName) || !isLabel(r.Provider) || r.AppName != app.Name || r.Provider != app.Provider {
			return errors.New("visit app_name and provider must be catalog names")
		}
		if r.Surface != "web" {
			return errors.New("visit surface must be web")
		}
		if len(r.Host) > 253 || !hostPattern.MatchString(r.Host) {
			return errors.New("visit host must be a bare hostname")
		}
		if !app.matchesHost(r.Host) {
			return errors.New("visit host is not one of its app's hosts")
		}
		if !isTime(r.FirstSeen) || !isTime(r.LastSeen) {
			return errors.New("visit needs first_seen and last_seen")
		}
		if !insideDay(r.Day, r.FirstSeen, r.LastSeen) {
			return errors.New("visit times outside its day")
		}
		if r.Requests < 1 || r.Requests > MaxRequestsPerDay {
			return errors.New("visit requests out of range")
		}
		if r.Messages < 0 || r.Messages > r.Requests {
			// Every send is a POST, so it is one of the requests.
			return errors.New("visit messages out of range")
		}
		return nil
	case KindAccount:
		if !isDay(r.Day) {
			return errors.New("account day must be a UTC date")
		}
		if !appPattern.MatchString(r.App) {
			return errors.New("account app id is invalid")
		}
		if _, known := catalog[r.App]; !known {
			return errors.New("account app is not in the catalog")
		}
		if !isTime(r.ObservedAt) || !insideDay(r.Day, r.ObservedAt, r.ObservedAt) {
			return errors.New("account observed_at must fall on its day")
		}
		switch r.AccountType {
		case AccountCompany, AccountPersonal, AccountNone, AccountUnknown:
			return nil
		default:
			return errors.New("account type must be company, personal, none or unknown")
		}
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
	// time.Parse also takes a comma before the fraction, which RFC 3339 and
	// the schema's date-time do not.
	if !timePattern.MatchString(value) {
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

// insideDay reports whether first and last fall on day in UTC, in order.
func insideDay(day, first, last string) bool {
	from, errFrom := time.Parse(time.RFC3339, first)
	to, errTo := time.Parse(time.RFC3339, last)
	if errFrom != nil || errTo != nil || to.Before(from) {
		return false
	}
	return from.UTC().Format(time.DateOnly) == day && to.UTC().Format(time.DateOnly) == day
}

// isLabel holds a name to the catalog's shape. It counts characters, as the
// schema's maxLength does, not bytes.
func isLabel(value string) bool {
	return utf8.ValidString(value) && utf8.RuneCountInString(value) <= 40 && labelPattern.MatchString(value)
}
