package browserevents

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const fixtures = "../../browser/contract/fixtures"

// decodeFixture decodes a fixture the way its receiver would, and reports
// whether every part of it is valid.
func decodeFixture(t *testing.T, data []byte) error {
	t.Helper()
	var head struct {
		Type   string `json:"type"`
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return err
	}
	switch {
	case head.Schema != "":
		var batch CloudBatch
		if err := json.Unmarshal(data, &batch); err != nil {
			return err
		}
		return batch.Validate()
	case head.Type == TypeSettings:
		var settings Settings
		if err := json.Unmarshal(data, &settings); err != nil {
			return err
		}
		if settings.Contract != Contract {
			return ErrUnsupportedContract
		}
		return nil
	case head.Type == TypeError:
		var answer ErrorAnswer
		return json.Unmarshal(data, &answer)
	case head.Type == "":
		var response CloudResponse
		return json.Unmarshal(data, &response)
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
