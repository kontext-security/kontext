package browserevents

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtures = "../../browser/contract/fixtures"

// decodeFixture decodes a fixture the way its receiver would, and reports
// whether every part of it is valid. Answers are checked field by field, as
// a missing field would otherwise decode as its zero value.
func decodeFixture(t *testing.T, data []byte) error {
	t.Helper()
	fields, err := readObject(data)
	if err != nil {
		return err
	}
	kind, _ := fields.text("type")
	_, isBatch := fields["schema"]
	switch {
	case isBatch:
		var batch CloudBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return err
		}
		return batch.Validate()
	case kind == TypeSettings:
		return checkSettings(fields)
	case kind == TypeError:
		return checkError(fields)
	case kind == "":
		accepted, _ := fields.integer("accepted")
		var rejected []json.RawMessage
		_ = json.Unmarshal(fields["rejected"], &rejected)
		_, err := DecodeCloudResponse(data, accepted+len(rejected))
		return err
	}
	msg, err := DecodeMessage(data)
	if err != nil {
		return err
	}
	if msg.Type != TypeRecords {
		return nil
	}
	_, rejected, err := DecodeRecords(msg.Records)
	if err != nil {
		return err
	}
	if len(rejected) > 0 {
		return errors.New(rejected[0].Reason)
	}
	return nil
}

// checkSettings holds a settings answer to the schema's settings definition.
func checkSettings(fields object) error {
	for _, key := range []string{"contract", "type", "capture_mode", "corporate_domains", "paused", "accepted", "rejected", "enrollment"} {
		if _, ok := fields[key]; !ok {
			return fmt.Errorf("settings without %s", key)
		}
	}
	if version, ok := fields.integer("contract"); !ok || version != Contract {
		return ErrUnsupportedContract
	}
	switch mode, _ := fields.text("capture_mode"); mode {
	case CaptureCommands, CaptureFull, CapturePrompts:
	default:
		return fmt.Errorf("settings capture_mode %q", mode)
	}
	var domains []string
	if err := json.Unmarshal(fields["corporate_domains"], &domains); err != nil || domains == nil {
		return errors.New("settings corporate_domains must be an array")
	}
	for _, domain := range domains {
		if !hostPattern.MatchString(domain) {
			return fmt.Errorf("settings corporate domain %q", domain)
		}
	}
	var paused bool
	if err := json.Unmarshal(fields["paused"], &paused); err != nil {
		return errors.New("settings paused must be a boolean")
	}
	accepted, ok := fields.integer("accepted")
	if !ok || accepted < 0 {
		return errors.New("settings accepted must be a count")
	}
	var rejected []Rejection
	if err := json.Unmarshal(fields["rejected"], &rejected); err != nil || rejected == nil {
		return errors.New("settings rejected must be an array")
	}
	if enrollment, ok := fields.text("enrollment"); !ok || !enrollmentPattern.MatchString(enrollment) {
		return errors.New("settings enrollment must be empty or 16 hex digits")
	}
	return nil
}

// checkError holds an error answer to the schema's error definition.
func checkError(fields object) error {
	if version, ok := fields.integer("contract"); !ok || version != Contract {
		return ErrUnsupportedContract
	}
	switch code, _ := fields.text("error"); code {
	case ErrorUnsupportedContract, ErrorInvalidMessage, ErrorUnavailable:
		return nil
	default:
		return fmt.Errorf("error code %q", code)
	}
}

func readFixtures(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(fixtures, dir, "*.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures in %s: %v", dir, err)
	}
	out := map[string][]byte{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(path)] = data
	}
	return out
}

func TestValidFixturesDecode(t *testing.T) {
	for name, data := range readFixtures(t, "valid") {
		if err := decodeFixture(t, data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestInvalidFixturesAreRefused(t *testing.T) {
	for name, data := range readFixtures(t, "invalid") {
		if err := decodeFixture(t, data); err == nil {
			t.Errorf("%s: decoded, want refused", name)
		}
	}
}

func TestOtherContractVersionIsNamed(t *testing.T) {
	data := readFixtures(t, "invalid")["records-wrong-contract.json"]
	if _, err := DecodeMessage(data); !errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("err = %v, want ErrUnsupportedContract", err)
	}
}

func TestOneBadRecordDoesNotRefuseTheOthers(t *testing.T) {
	raw := json.RawMessage(`[
		{"kind":"health","connected_since":"2026-11-20T08:00:00Z","observed_at":"2026-11-20T09:00:00Z"},
		{"kind":"keystrokes","text":"secret"},
		{"kind":"visit","day":"2026-11-20","app":"claude","app_name":"Claude","provider":"Anthropic","surface":"web","host":"claude.ai","first_seen":"2026-11-20T08:00:00Z","last_seen":"2026-11-20T09:00:00Z","requests":2}
	]`)
	valid, rejected, err := DecodeRecords(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(valid) != 2 || valid[0].Index != 0 || valid[1].Index != 2 {
		t.Fatalf("valid = %+v, want indexes 0 and 2", valid)
	}
	if len(rejected) != 1 || rejected[0].Index != 1 || rejected[0].Reason != "unknown record kind" {
		t.Fatalf("rejected = %+v", rejected)
	}
}

func TestOversizedMessageIsRefusedBeforeDecoding(t *testing.T) {
	data := make([]byte, MaxMessageBytes+1)
	if _, err := DecodeMessage(data); err == nil {
		t.Fatal("decoded an oversized message")
	}
}

func TestCloudRecordFlattensItsRecord(t *testing.T) {
	encoded, err := json.Marshal(CloudRecord{Browser: "chrome", Profile: "p7Hq2vXkLm9s", ExtensionVersion: "0.1.0",
		Record: Record{Kind: KindHealth, ConnectedSince: "2026-11-20T08:00:00Z", ObservedAt: "2026-11-20T09:00:00Z"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"browser":"chrome","profile":"p7Hq2vXkLm9s","extension_version":"0.1.0","kind":"health","connected_since":"2026-11-20T08:00:00Z","observed_at":"2026-11-20T09:00:00Z"}`
	if string(encoded) != want {
		t.Fatalf("encoded\n%s\nwant\n%s", encoded, want)
	}
}

func TestHealthRecordKeepsOnlyItsOwnFields(t *testing.T) {
	raw := json.RawMessage(`[{"kind":"health","connected_since":"2026-11-20T08:00:00Z","observed_at":"2026-11-20T09:00:00Z","host":"chatgpt.com/c/123?token=secret","app_name":"private text"}]`)
	valid, rejected, err := DecodeRecords(raw)
	if err != nil || len(rejected) != 0 || len(valid) != 1 {
		t.Fatalf("valid = %+v, rejected = %+v, err = %v", valid, rejected, err)
	}
	if got := valid[0].Record; got.Host != "" || got.AppName != "" {
		t.Fatalf("health record kept a visit's fields: %+v", got)
	}
	mixed := Record{Kind: KindHealth, ConnectedSince: "2026-11-20T08:00:00Z", ObservedAt: "2026-11-20T09:00:00Z", Host: "chatgpt.com/c/123"}
	if err := mixed.Validate(); err == nil {
		t.Fatal("Validate took a health record with a host")
	}
}

// A visit names an app of the contract's catalog, with the catalog's own name,
// provider and one of its hosts. Anything else could carry text a page or a
// person wrote, so it is refused.
func TestAVisitNamesACatalogApp(t *testing.T) {
	visit := Record{Kind: KindVisit, Day: "2026-11-20", App: "chatgpt", AppName: "ChatGPT", Provider: "OpenAI", Surface: "web",
		Host: "chatgpt.com", FirstSeen: "2026-11-20T08:00:00Z", LastSeen: "2026-11-20T09:00:00Z", Requests: 1}
	if err := visit.Validate(); err != nil {
		t.Fatalf("a catalog visit refused: %v", err)
	}
	for _, host := range []string{"chat.openai.com"} {
		v := visit
		v.Host = host
		if err := v.Validate(); err != nil {
			t.Errorf("host %q refused: %v", host, err)
		}
	}
	n8n := visit
	n8n.App, n8n.AppName, n8n.Provider, n8n.Host = "n8n-cloud", "n8n cloud", "n8n", "acme.app.n8n.cloud"
	if err := n8n.Validate(); err != nil {
		t.Errorf("a wildcard host refused: %v", err)
	}
	refused := map[string]func(*Record){
		"unknown app":        func(r *Record) { r.App = "qwen" },
		"other name":         func(r *Record) { r.AppName = "Plan cut costs" },
		"other provider":     func(r *Record) { r.Provider = "Anthropic" },
		"text in a name":     func(r *Record) { r.AppName = "chatgpt.com/c/123" },
		"another app's host": func(r *Record) { r.Host = "claude.ai" },
		"host above a wildcard": func(r *Record) {
			r.App, r.AppName, r.Provider, r.Host = "n8n-cloud", "n8n cloud", "n8n", "app.n8n.cloud"
		},
		"host that only ends alike": func(r *Record) { r.Host = "evilchatgpt.com" },
	}
	for name, change := range refused {
		v := visit
		change(&v)
		if err := v.Validate(); err == nil {
			t.Errorf("%s taken", name)
		}
	}
}

func TestVisitTimesMustFallOnItsDay(t *testing.T) {
	visit := Record{Kind: KindVisit, Day: "2026-11-20", App: "chatgpt", AppName: "ChatGPT", Provider: "OpenAI",
		Surface: "web", Host: "chatgpt.com", FirstSeen: "2026-11-20T08:00:00+01:00", LastSeen: "2026-11-20T09:00:00Z", Requests: 1}
	if err := visit.Validate(); err != nil {
		t.Fatalf("a visit inside its UTC day was refused: %v", err)
	}
	for name, change := range map[string]func(*Record){
		"the day before":    func(r *Record) { r.FirstSeen, r.LastSeen = "2026-11-19T08:00:00Z", "2026-11-19T09:00:00Z" },
		"before midnight":   func(r *Record) { r.FirstSeen = "2026-11-20T00:30:00+01:00" },
		"last before first": func(r *Record) { r.FirstSeen, r.LastSeen = "2026-11-20T09:00:00Z", "2026-11-20T08:00:00Z" },
	} {
		changed := visit
		change(&changed)
		if err := changed.Validate(); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

func TestAnUnknownVersionIsNamedWhateverItsShape(t *testing.T) {
	if _, err := DecodeMessage([]byte(`{"contract":3,"type":"hello","extension":"a string in v3"}`)); !errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("contract 3: err = %v, want ErrUnsupportedContract", err)
	}
	for _, data := range []string{`{"type":"hello"}`, `{"contract":null,"type":"hello"}`} {
		if _, err := DecodeMessage([]byte(data)); err == nil || errors.Is(err, ErrUnsupportedContract) {
			t.Errorf("%s: err = %v, want an invalid message", data, err)
		}
	}
}

func TestAnAnswerWithNothingRejectedHasArrays(t *testing.T) {
	_, rejected, err := DecodeRecords(json.RawMessage(`[{"kind":"health","connected_since":"2026-11-20T08:00:00Z","observed_at":"2026-11-20T09:00:00Z"}]`))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(Settings{Contract: Contract, Type: TypeSettings, CaptureMode: CaptureCommands, Accepted: 1, Rejected: rejected})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"contract":2,"type":"settings","capture_mode":"commands","corporate_domains":[],"paused":false,"accepted":1,"rejected":[],"enrollment":""}`
	if string(encoded) != want {
		t.Fatalf("encoded\n%s\nwant\n%s", encoded, want)
	}
	if encoded, _ := json.Marshal(Settings{}); strings.Contains(string(encoded), "null") {
		t.Fatalf("empty settings wrote null: %s", encoded)
	}
}

func TestTheCloudAnswerMustAccountForTheBatch(t *testing.T) {
	if _, err := DecodeCloudResponse([]byte(`{"accepted":2,"rejected":[{"index":0,"reason":"cap"}]}`), 3); err != nil {
		t.Fatalf("a full answer was refused: %v", err)
	}
	for _, data := range []string{
		`{}`, `null`, `[]`,
		`{"accepted":3}`,
		`{"accepted":2,"rejected":[]}`,
		`{"accepted":1,"rejected":[{"index":1,"reason":"a"},{"index":1,"reason":"b"}]}`,
		`{"accepted":2,"rejected":[{"index":3,"reason":"a"}]}`,
		`{"accepted":2,"rejected":[{"index":-1,"reason":"a"}]}`,
		// A settings answer or an echoed batch is no proof of ingestion.
		`{"contract":2,"type":"settings","accepted":3,"rejected":[]}`,
		`{"schema":"browser-activity-v1","accepted":3,"rejected":[]}`,
		`{"accepted":2,"rejected":[{"index":0}]}`,
		`{"accepted":2,"rejected":[{"index":0,"reason":7}]}`,
	} {
		if _, err := DecodeCloudResponse([]byte(data), 3); err == nil {
			t.Errorf("%s: taken for 3 records", data)
		}
	}
}

// Every catalog entry must pass the contract itself, or the extension would
// record visits the daemon refuses.
func TestTheCatalogFitsTheContract(t *testing.T) {
	if len(catalog) == 0 {
		t.Fatal("the catalog is empty")
	}
	for id, app := range catalog {
		if !appPattern.MatchString(id) || !isLabel(app.Name) || !isLabel(app.Provider) || len(app.Hosts) == 0 {
			t.Errorf("catalog entry %q does not fit the contract", id)
		}
		for _, host := range app.Hosts {
			if !hostPattern.MatchString(strings.TrimPrefix(host, "*.")) {
				t.Errorf("catalog host %q of %q is not a hostname", host, id)
			}
		}
	}
}
