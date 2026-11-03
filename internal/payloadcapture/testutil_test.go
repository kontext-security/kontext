package payloadcapture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func loadTestdata(t testing.TB, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
}

// decodeUseNumber mirrors how hook payloads are decoded elsewhere in this
// codebase: numbers arrive as json.Number, and canonicalization must still
// produce the shared byte-exact output.
func decodeUseNumber(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode input: %v", err)
	}
	return value
}
