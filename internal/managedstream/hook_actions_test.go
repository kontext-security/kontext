package managedstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The cloud decodes the same bytes with unknown fields refused
// (kontext-cloud packages/shared __fixtures__/hook-actions-v1.json).
const hookActionsFixtureDigest = "bbf13098f9a562fc662399fce19dc76469dc3b70928a9b897b7a1abf47ebf996"

func TestHookActionsMatchTheCloudsFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "hook-actions-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != hookActionsFixtureDigest {
		t.Fatalf("fixture SHA-256 = %s", got)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var report HookActions
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != HookActionsSchema || len(report.Results) != 2 || report.Results[1].Status != HookNeedsPrivileged {
		t.Fatalf("decoded %+v", report)
	}
	// What this side sends is what the cloud reads: the same keys, no more.
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if !bytes.Equal(wantJSON, gotJSON) {
		t.Fatalf("encoded %s\nwant    %s", gotJSON, wantJSON)
	}
	// A report with no nonce still sends the key, as null.
	report.RepairNonce = nil
	encoded, _ = json.Marshal(report)
	if !bytes.Contains(encoded, []byte(`"repair_nonce":null`)) {
		t.Fatalf("no nonce encoded as %s", encoded)
	}
}

// The pending report rides on the heartbeat, and is marked sent only once
// the cloud accepted the post carrying it.
func TestHookActionsGoOnTheHeartbeatUntilAccepted(t *testing.T) {
	_, dbPath := testStore(t)
	status := http.StatusServiceUnavailable
	var bodies []map[string]json.RawMessage
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		var device map[string]json.RawMessage
		_ = json.Unmarshal(body["device"], &device)
		bodies = append(bodies, device)
		w.WriteHeader(status)
		if status < 300 {
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(server.Close)
	nonce := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	report := &HookActions{Schema: HookActionsSchema, Desired: "installed", Generation: 3, RepairNonce: &nonce, FinishedAt: "2026-11-23T10:00:00Z",
		Results: []HookActionResult{{Agent: "claude_code", ScopeKind: "user", Status: HookRestored}}}
	sent := 0
	opts := func() Options {
		return Options{
			DBPath:         dbPath,
			StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
			CloudURL:       server.URL,
			InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
			InstallToken:   "test-install-token",
			HTTPClient:     server.Client(),
			HookActions: func() (*HookActions, func()) {
				if sent > 0 {
					return nil, nil
				}
				return report, func() { sent++ }
			},
		}
	}
	if err := Flush(context.Background(), opts()); err == nil {
		t.Fatal("a refused post succeeded")
	}
	if sent != 0 {
		t.Fatal("a refused post marked the report sent")
	}
	status = http.StatusCreated
	if err := Flush(context.Background(), opts()); err != nil {
		t.Fatal(err)
	}
	if sent != 1 {
		t.Fatalf("an accepted post marked the report sent %d times", sent)
	}
	if len(bodies) != 2 || bodies[1]["hook_actions"] == nil {
		t.Fatalf("posted devices %v", bodies)
	}
	var got HookActions
	if err := json.Unmarshal(bodies[1]["hook_actions"], &got); err != nil || !got.Same(*report) {
		t.Fatalf("posted %s: %v", bodies[1]["hook_actions"], err)
	}
	// Nothing pending: the next heartbeat carries none.
	if err := Flush(context.Background(), opts()); err != nil {
		t.Fatal(err)
	}
	if bodies[2]["hook_actions"] != nil {
		t.Fatalf("a sent report went again: %s", bodies[2]["hook_actions"])
	}
}

// A minimum batch over the cap loses the larger optional blocks first; the
// small hook report stays on it. Dropped too, it is not marked sent, so the
// next post carries it.
func TestDroppingAuthorityKeepsTheHookReportPending(t *testing.T) {
	sent := false
	report := &HookActions{Schema: HookActionsSchema, Desired: "installed", Generation: 1, FinishedAt: "2026-11-23T10:00:00Z", Results: []HookActionResult{}}
	payload := Payload{}
	addHookActions(&payload, Options{HookActions: func() (*HookActions, func()) { return report, func() { sent = true } }})
	dropAuthority(&payload)
	if payload.Device.HookActions != report {
		t.Fatal("dropping the authority report took the hook report too")
	}
	dropHookActions(&payload)
	ackHookActions(payload)
	if payload.Device.HookActions != nil || sent {
		t.Fatalf("dropped report: on payload=%v marked sent=%v", payload.Device.HookActions != nil, sent)
	}
}
