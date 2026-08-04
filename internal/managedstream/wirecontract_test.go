package managedstream

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

// Validates the bytes the daemon actually uploads against the pinned
// published contract (docs/contracts/ledger-ingest/v1).
//
// It deliberately validates bytes captured off the wire, decoded into an
// UNTYPED JSON value: records are assembled from database rows and mapped
// field by field, so a typed test struct could silently hide a dropped or
// misnamed field that the schema would reject.

const batchSchemaPath = "../../docs/contracts/ledger-ingest/v1/ledger-batch.schema.json"

func loadBatchSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(batchSchemaPath)
	if err != nil {
		t.Fatalf("read %s: %v", batchSchemaPath, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", batchSchemaPath, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("ledger-batch.schema.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	schema, err := compiler.Compile("ledger-batch.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return schema
}

// captureRawBodies returns a server recording every posted body verbatim.
func captureRawBodies(t *testing.T, bodies *[][]byte) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		mu.Lock()
		*bodies = append(*bodies, raw)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
}

func flushOptions(dbPath, statePath, serverURL string, client *http.Client) Options {
	return Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       serverURL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    "wire-contract-runner",
		UserEmail:      "operator@example.com",
		HTTPClient:     client,
	}
}

func TestFlushedBatchMatchesPinnedContract(t *testing.T) {
	store, dbPath := testStore(t)

	// Session lifecycle rows are local-only; the tool-call rows below cover
	// every clean lifecycle stage including a captured output and a failure.
	for _, hookEvent := range []string{"SessionStart", "PreToolUse", "PostToolUse", "PostToolUseFailure", "SessionEnd"} {
		decision := risk.RiskDecision{
			Decision:   risk.DecisionAllow,
			ReasonCode: "normal_tool_call",
			Reason:     "normal",
			RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall, RequestSummary: "read a file"},
		}
		if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
			SessionID:     "sess-wire-contract",
			Agent:         "claude",
			CWD:           "/tmp/project",
			HookEventName: hookEvent,
			ToolName:      "Read",
			ToolUseID:     "toolu_wire_contract",
			ToolResponse:  map[string]any{"ok": true},
		}, decision); err != nil {
			t.Fatalf("SaveDecision(%s) error = %v", hookEvent, err)
		}
	}

	var bodies [][]byte
	server := captureRawBodies(t, &bodies)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), flushOptions(dbPath, statePath, server.URL, server.Client())); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if len(bodies) == 0 {
		t.Fatal("no batch was posted")
	}

	schema := loadBatchSchema(t)
	for index, raw := range bodies {
		value, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("decode posted body %d: %v", index, err)
		}
		if err := schema.Validate(value); err != nil {
			t.Fatalf("posted body %d violates the pinned contract: %v\n%s", index, err, raw)
		}
		for _, legacyMarker := range []string{
			`"agent_sessions"`, `"authorization_actions"`, `"authorization_receipts"`,
			`"schema_version"`, `"tool_use_id"`, `"canonical_event_type"`, `_json"`,
		} {
			// decision_fact carries its own schema_version; only the envelope
			// marker is a legacy leak.
			if legacyMarker == `"schema_version"` &&
				bytes.Contains(raw, []byte(`"decision_fact"`)) {
				continue
			}
			if bytes.Contains(raw, []byte(legacyMarker)) {
				t.Fatalf("posted body %d contains legacy field %s:\n%s", index, legacyMarker, raw)
			}
		}
		var batch wireBatch
		if err := json.Unmarshal(raw, &batch); err != nil {
			t.Fatalf("decode batch %d: %v", index, err)
		}
		for _, action := range batch.Actions {
			eventType, _ := action["event_type"].(string)
			if strings.HasPrefix(eventType, "session.") {
				t.Fatalf("session lifecycle row leaked onto the wire: %v", action)
			}
		}
	}
}

func TestHeartbeatMatchesPinnedContract(t *testing.T) {
	_, dbPath := testStore(t)

	var bodies [][]byte
	server := captureRawBodies(t, &bodies)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), flushOptions(dbPath, statePath, server.URL, server.Client())); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("posted %d bodies, want one heartbeat", len(bodies))
	}

	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(bodies[0]))
	if err != nil {
		t.Fatalf("decode heartbeat: %v", err)
	}
	if err := loadBatchSchema(t).Validate(value); err != nil {
		t.Fatalf("heartbeat violates the pinned contract: %v\n%s", err, bodies[0])
	}
}

// Pre-cutover rows (receipts stored before the clean-payload change, marked
// by the payload_form column default) pin their page to the legacy form:
// their payload bytes were hashed under the old serialization and can never
// satisfy the clean contract. This is the deterministic drain path for the
// backlog a daemon upgrade leaves behind.
func TestFlushShipsPreCutoverPagesOnLegacyForm(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "sess-pre-cutover", "toolu_pre_cutover")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`update authorization_receipts set payload_form = 'legacy'`); err != nil {
		t.Fatalf("mark receipts legacy: %v", err)
	}

	var bodies [][]byte
	server := captureRawBodies(t, &bodies)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), flushOptions(dbPath, statePath, server.URL, server.Client())); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if len(bodies) != 1 {
		t.Fatalf("posted %d bodies, want one legacy batch", len(bodies))
	}

	var legacy Payload
	if err := json.Unmarshal(bodies[0], &legacy); err != nil {
		t.Fatalf("decode legacy batch: %v", err)
	}
	if legacy.SchemaVersion != SchemaVersion {
		t.Fatalf("schema_version = %q, want the legacy form for pre-cutover rows", legacy.SchemaVersion)
	}
	if bytes.Contains(bodies[0], []byte(`"batch_version"`)) {
		t.Fatalf("legacy batch carries the v1 marker (hybrid form): %s", bodies[0])
	}
	if bytes.Contains(bodies[0], []byte(`"payload_form"`)) {
		t.Fatalf("local cutover column leaked onto the wire: %s", bodies[0])
	}
	if len(legacy.Actions) == 0 || len(legacy.Receipts) == 0 {
		t.Fatalf("legacy batch counts = actions %d receipts %d, want the full page", len(legacy.Actions), len(legacy.Receipts))
	}
}
