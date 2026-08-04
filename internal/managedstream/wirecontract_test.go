package managedstream

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

// Validates what the daemon actually uploads against the published payload
// schema in docs/schema.
//
// This keeps the documented CLI payload in step with the bytes posted by Flush.
//
// It deliberately validates the bytes captured off the wire rather than a
// hand-built Payload. Records are assembled from database rows into
// map[string]any, so their keys come from the query, not from a Go struct
// literal a test author could keep in sync by hand.

const wireSchemaPath = "../../docs/schema/v1/ledger-batch-v1.json"

func loadWireSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	raw, err := os.ReadFile(wireSchemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", wireSchemaPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", wireSchemaPath, err)
	}

	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("ledger-batch-v1.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile("ledger-batch-v1.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// capturedBatch runs a real flush and returns the exact JSON body posted.
func capturedBatch(t *testing.T) map[string]any {
	t.Helper()

	store, dbPath := testStore(t)
	saveTestDecision(t, store, "sess-wire-contract", "tool-use-wire-contract")

	var raw json.RawMessage
	server := captureWirePayloadServer(t, &raw)
	defer server.Close()

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(filepath.Dir(dbPath), "state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_ABCDEFGHIJKLMNOPQRSTUVWX12345678",
		InstallToken:   "test-install-token",
		DeviceLabel:    "wire-contract-device",
		Diagnostic:     diagnostic.New(nil, false),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode captured payload: %v", err)
	}
	return decoded
}

func captureWirePayloadServer(t *testing.T, captured *json.RawMessage) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, DefaultEndpoint)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q, want bearer install token", got)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if !json.Valid(raw) {
			t.Fatalf("uploaded body is not valid JSON: %s", raw)
		}
		*captured = raw
		w.WriteHeader(http.StatusAccepted)
	}))
}

func TestUploadedBatchMatchesPublishedSchema(t *testing.T) {
	schema := loadWireSchema(t)
	batch := capturedBatch(t)

	// An empty batch satisfies the schema trivially, so assert there is
	// something to validate before trusting the result.
	sessions, _ := batch["agent_sessions"].([]any)
	actions, _ := batch["authorization_actions"].([]any)
	if len(sessions) == 0 || len(actions) == 0 {
		t.Fatalf("captured batch is empty (%d sessions, %d actions); the test would prove nothing",
			len(sessions), len(actions))
	}

	if err := schema.Validate(batch); err != nil {
		t.Fatalf("uploaded batch does not match %s:\n%v", wireSchemaPath, err)
	}
}

func TestPublishedSchemaRejectsMalformedRecordInsideBatch(t *testing.T) {
	// Batch-level checks would still pass here: this proves the contract is
	// enforced down inside the record arrays, where nearly every field lives.
	schema := loadWireSchema(t)
	batch := capturedBatch(t)

	actions, _ := batch["authorization_actions"].([]any)
	first, _ := actions[0].(map[string]any)
	first["id"] = "not-an-action-id"

	if err := schema.Validate(batch); err == nil {
		t.Fatal("schema accepted an action id outside the required format")
	}
}

// The checks below prove the validator can fail. A schema compiled without
// strictness, or a Validate call whose error is dropped, would let the test
// above pass while checking nothing.

func TestPublishedSchemaRejectsUnknownField(t *testing.T) {
	schema := loadWireSchema(t)
	batch := capturedBatch(t)
	batch["unexpected_field"] = true

	if err := schema.Validate(batch); err == nil {
		t.Fatal("schema accepted an unknown field")
	}
}

func TestPublishedSchemaRejectsMissingRequiredField(t *testing.T) {
	schema := loadWireSchema(t)
	batch := capturedBatch(t)
	delete(batch, "installation_id")

	if err := schema.Validate(batch); err == nil {
		t.Fatal("schema accepted a batch with no installation_id")
	}
}

func TestPublishedSchemaPinsTheSchemaVersion(t *testing.T) {
	// The payload schema pins the emitted record-schema label.
	schema := loadWireSchema(t)
	batch := capturedBatch(t)

	if got := batch["schema_version"]; got != SchemaVersion {
		t.Fatalf("schema_version = %v, want %q", got, SchemaVersion)
	}

	batch["schema_version"] = "authorization-ledger-v0"
	if err := schema.Validate(batch); err == nil {
		t.Fatal("schema accepted an unsupported schema_version")
	}
}
