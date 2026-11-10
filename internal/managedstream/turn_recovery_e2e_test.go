package managedstream

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// Real provider JSONL -> durable existing usage -> turn recovery -> revisioned
// HTTP uploads. No API keys, model calls, or live workspace are used.
func TestTranscriptTurnRecoveryE2E(t *testing.T) {
	var reports []map[string]any
	for _, agent := range []string{"claude", "codex"} {
		t.Run(agent, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			dbPath, transcript := filepath.Join(dir, "guard.db"), filepath.Join(dir, "session.jsonl")
			session := "recovery-e2e"
			if agent == "codex" {
				session = "codex-" + session
			}
			base := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
			fixture := func(n int, text string) string {
				at := base.Add(time.Duration(n) * time.Minute)
				stamp := func(delta time.Duration) string { return at.Add(delta).Format(time.RFC3339Nano) }
				if agent == "claude" {
					return fmt.Sprintf("{\"type\":\"user\",\"sessionId\":%q,\"timestamp\":%q,\"message\":{\"content\":%q}}\n{\"type\":\"assistant\",\"sessionId\":%q,\"timestamp\":%q,\"message\":{\"id\":%q,\"model\":\"claude-fable-5-1\",\"content\":[{\"type\":\"tool_use\",\"id\":%q,\"name\":\"Read\"}],\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n", session, stamp(0), text, session, stamp(time.Second), fmt.Sprint("m", n), fmt.Sprint("tool", n))
				}
				return fmt.Sprintf("{\"type\":\"event_msg\",\"timestamp\":%q,\"payload\":{\"type\":\"task_started\"}}\n{\"type\":\"response_item\",\"timestamp\":%q,\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":%q}]}}\n{\"type\":\"turn_context\",\"timestamp\":%q,\"payload\":{\"model\":\"gpt-5.6-luna\"}}\n{\"type\":\"response_item\",\"timestamp\":%q,\"payload\":{\"type\":\"function_call\",\"call_id\":%q,\"name\":\"exec_command\"}}\n{\"type\":\"token_usage_record\",\"timestamp\":%q,\"payload\":{\"thread_id\":\"recovery-e2e\",\"response_id\":%q,\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n", stamp(0), stamp(time.Millisecond), text, stamp(2*time.Millisecond), stamp(time.Second), fmt.Sprint("tool", n), stamp(2*time.Second), fmt.Sprint("m", n))
			}
			data := ""
			if agent == "codex" {
				data = `{"type":"session_meta","payload":{"id":"recovery-e2e","model_provider":"openai"}}` + "\n"
			}
			secret := "ghp_" + strings.Repeat("a", 36)
			data += fixture(0, "Build the missing report export using "+secret) + fixture(1, "Add CSV formatting")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := sqlite.OpenStore(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if _, err := store.EnsureObservedSessionWithMode(ctx, session, agent, dir, "observe"); err != nil {
				t.Fatal(err)
			}
			if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: session, Agent: agent, HookName: hook.HookPostToolUse, TranscriptPath: transcript}); err != nil {
				t.Fatal(err)
			}
			if err := store.ReconcileToolUsage(ctx); err != nil {
				t.Fatal(err)
			}
			original, err := store.PendingToolUsage(ctx, 20)
			if err != nil || len(original) != 2 {
				t.Fatalf("original usage: %+v, %v", original, err)
			}
			ledger := map[string]sqlite.ToolUsageRecord{}
			for _, r := range original {
				if r.TurnID != "" {
					t.Fatal("fixture unexpectedly linked")
				}
				ledger[r.MessageID] = r
			}
			if err := store.AcknowledgeToolUsage(ctx, original); err != nil {
				t.Fatal(err)
			}
			on, off := true, false
			config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &off}
			identity, err := endpointconfig.ComputeIdentity(config)
			if err != nil {
				t.Fatal(err)
			}
			cachePath := endpointconfig.DefaultCachePathForDB(dbPath)
			if agent == "codex" {
				cachePath = filepath.Join(dir, "custom-policy", "endpoint.json")
			}
			cache := endpointconfig.NewCache(cachePath)
			if err := cache.Apply(endpointconfig.FetchResult{Response: &endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}}, time.Now()); err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			turns := map[string]sqlite.TurnRecord{}
			updates := 0
			turnUploads := 0
			recoveryBefore := ""
			cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var batch struct {
					Turns []sqlite.TurnRecord      `json:"turns"`
					Usage []sqlite.ToolUsageRecord `json:"tool_usage"`
				}
				if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				for _, turn := range batch.Turns {
					turnUploads++
					if turn.Prompt.Text == nil {
						t.Errorf("recovered turn has no prompt")
					} else if strings.Contains(*turn.Prompt.Text, secret) {
						t.Errorf("recovery uploaded an unredacted credential")
					}
					turns[turn.ID] = turn
				}
				for _, record := range batch.Usage {
					if record.TurnID != "" {
						if _, ok := turns[record.TurnID]; !ok {
							t.Error("usage arrived before its turn")
						}
					}
					if old, ok := ledger[record.MessageID]; !ok || record.Revision > old.Revision {
						ledger[record.MessageID] = record
						updates++
					}
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(201)
				json.NewEncoder(w).Encode(map[string]string{"turn_recovery_before": recoveryBefore})
			}))
			defer cloud.Close()
			opts := Options{DBPath: dbPath, CloudURL: cloud.URL, InstallationID: "ins_test", InstallToken: "fixture", EndpointConfigCachePath: cachePath, HeartbeatInterval: time.Nanosecond}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if len(turns) != 0 {
				t.Fatal("legacy unknown-policy prompts recovered without explicit authorization")
			}
			mu.Unlock()
			mu.Lock()
			recoveryBefore = time.Now().UTC().Format(time.RFC3339Nano)
			mu.Unlock()
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			} // learns the authenticated workspace request
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if len(turns) != 2 || updates != 2 {
				t.Fatalf("recovery: turns=%d, revised=%d", len(turns), updates)
			}
			for _, before := range original {
				after := ledger[before.MessageID]
				if after.TurnID == "" || after.Revision <= before.Revision || !reflect.DeepEqual(after.Tokens, before.Tokens) {
					t.Fatalf("incorrect recovery: %+v -> %+v", before, after)
				}
			}
			mu.Unlock()
			// A queued prompt hook can arrive after the fallback was exported.
			// Both paths must retain one canonical ID, including queued actions.
			mu.Lock()
			canonical := ledger["m0"].TurnID
			mu.Unlock()
			late := sqlite.TurnRecord{Schema: sqlite.TurnSchemaVersion, ID: "turn_" + uuid.NewString(), SessionID: session, Agent: agent, StartedAt: sqlite.FormatTurnTime(base.Add(100 * time.Millisecond)), Source: sqlite.TurnSourceUserPrompt, Prompt: sqlite.CaptureTurnPrompt("Build the missing report export using "+secret, payloadcapture.RuntimeConfiguration{ConfiguredMode: payloadcapture.ModeFull, EffectiveMode: payloadcapture.ModeFull, Confirmed: true, ConfigIdentity: identity, WorkTypeClassification: true})}
			if err := store.SaveTurn(ctx, late); err != nil {
				t.Fatal(err)
			}
			resolved, err := store.ResolveTurnID(ctx, late.ID)
			if err != nil || resolved != canonical {
				t.Fatalf("late hook alias: %s, %v", resolved, err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if len(turns) != 2 || turnUploads != 2 {
				t.Fatal("one prompt was uploaded as two turns")
			}
			mu.Unlock()
			// The old file is unchanged and its rows were already acknowledged.
			// Repeat after reopening the database: no duplicates or new revisions.
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if updates != 2 || len(ledger) != 2 {
				t.Fatal("repeat recovery duplicated usage")
			}
			mu.Unlock()
			data += fixture(2, "Now add a report preview")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if updates != 3 || len(ledger) != 3 || len(turns) != 3 {
				t.Fatalf("new missed hook not recovered: %d/%d/%d", updates, len(ledger), len(turns))
			}
			mu.Unlock()
			// Retention can remove local turns whose IDs still identify valid
			// hosted usage. An upgrade's historical rescan must preserve them.
			mu.Lock()
			prunedID := ledger["m0"].TurnID
			mu.Unlock()
			prunedDB, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prunedDB.Exec("delete from turns where id=?", prunedID); err != nil {
				t.Fatal(err)
			}
			if _, err := prunedDB.Exec("update tool_usage_sources set turn_recovery_version=0"); err != nil {
				t.Fatal(err)
			}
			prunedDB.Close()
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if turnUploads != 3 || ledger["m0"].TurnID != prunedID {
				t.Fatal("rescan replaced an existing hosted turn after local retention")
			}
			mu.Unlock()
			// A deliberately disabled workspace must not recover subsequent text,
			// including after the setting is enabled again.
			oldDB, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := oldDB.Exec("delete from turns where id=(select json_extract(payload,'$.turn_id') from tool_usage_records where message_id='m1')"); err != nil {
				t.Fatal(err)
			}
			if _, err := oldDB.Exec("update tool_usage_records set payload=json_remove(payload,'$.turn_id') where message_id='m1'"); err != nil {
				t.Fatal(err)
			}
			if _, err := oldDB.Exec("update tool_usage_sources set turn_recovery_version=0"); err != nil {
				t.Fatal(err)
			}
			oldDB.Close()
			config.WorkTypeClassification = &off
			identity, _ = endpointconfig.ComputeIdentity(config)
			if err := cache.Apply(endpointconfig.FetchResult{Response: &endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}}, time.Now()); err != nil {
				t.Fatal(err)
			}
			data += fixture(3, "Do not capture this opted-out request")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			config.WorkTypeClassification = &on
			identity, _ = endpointconfig.ComputeIdentity(config)
			if err := cache.Apply(endpointconfig.FetchResult{Response: &endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if ledger["m3"].TurnID != "" || len(turns) != 3 {
				t.Fatal("recovery captured an explicitly opted-out prompt")
			}
			if ledger["m1"].TurnID == "" {
				t.Fatal("a disabled read consumed historical recovery for a previously permitted prompt")
			}
			mu.Unlock()
			data += fixture(4, "Capture the new request after the setting is enabled")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			if ledger["m3"].TurnID != "" || ledger["m4"].TurnID == "" || len(turns) != 4 {
				t.Fatal("file growth lost the stored opt-out decision")
			}
			mu.Unlock()
			mu.Lock()
			recoveryBefore = ""
			mu.Unlock()
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			data += fixture(5, "A legacy prompt outside the withdrawn request")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			// A new prompt after recovery was introduced is prospective, not
			// historical. It requires no operator backfill request.
			epochDB, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := epochDB.Exec("update turn_recovery_policy set started_at=?", sqlite.FormatTurnTime(base.Add(-time.Minute))); err != nil {
				t.Fatal(err)
			}
			epochDB.Close()
			data += fixture(6, "A newly observed permitted prompt")
			if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			if err := Flush(ctx, opts); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if ledger["m5"].TurnID != "" || ledger["m6"].TurnID == "" {
				t.Fatal("historical request revocation or prospective recovery failed")
			}
			reports = append(reports, map[string]any{"agent": agent, "existingRequestsRecovered": 2, "futureMissedHooksRecovered": 2, "totalRequests": len(ledger), "recoveredTurns": len(turns), "repeatWasIdempotent": true, "optOutRespected": true, "hostedLinksSurviveLocalRetention": true})
		})
	}
	if path := os.Getenv("KONTEXT_RECOVERY_E2E_ARTIFACT"); path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		body, _ := json.MarshalIndent(reports, "", "  ")
		if err := os.WriteFile(path, append(body, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSkippedPromptRecoveryE2E(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var jobs []func(context.Context) error
	host, err := server.NewServerWithPolicyAndOptions(store, nil, server.Options{DeferRecord: func(job func(context.Context) error) error { jobs = append(jobs, job); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	text := "Recover the prompt skipped during the configuration outage"
	if _, err := host.ProcessHookEvent(ctx, risk.HookEvent{Agent: "claude", HookEventName: "UserPromptSubmit", SessionID: "skipped-recovery", ToolInput: map[string]any{"prompt": text}}); err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if err := job(ctx); err != nil {
			t.Fatal(err)
		}
	}
	turns, err := store.PendingTurns(ctx, 10)
	if err != nil || len(turns) != 1 || turns[0].Prompt.Mode != sqlite.TurnPromptSkipped {
		t.Fatalf("skipped fixture: %+v, %v", turns, err)
	}
	old := turns[0]
	base := time.Now().UTC().Add(-time.Hour)
	// Seed the historical clock of this real hook-created fixture; the action
	// retains the original unconfirmed capture evidence.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("update turns set started_at=? where id=?", sqlite.FormatTurnTime(base), old.ID); err != nil {
		t.Fatal(err)
	}
	db.Close()
	transcript := filepath.Join(dir, "session.jsonl")
	data := fmt.Sprintf("{\"type\":\"user\",\"sessionId\":\"skipped-recovery\",\"timestamp\":%q,\"message\":{\"content\":%q}}\n{\"type\":\"assistant\",\"sessionId\":\"skipped-recovery\",\"timestamp\":%q,\"message\":{\"id\":\"m\",\"model\":\"claude-fable-5-1\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"Read\"}],\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n", base.Format(time.RFC3339Nano), text, base.Add(time.Second).Format(time.RFC3339Nano))
	if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: old.SessionID, Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: transcript}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	usage, err := store.PendingToolUsage(ctx, 10)
	if err != nil || len(usage) != 1 || usage[0].TurnID != old.ID {
		t.Fatalf("linked fixture: %+v, %v", usage, err)
	}
	if err := store.AcknowledgeToolUsage(ctx, usage); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeTurns(ctx, []string{old.ID}); err != nil {
		t.Fatal(err)
	}
	on, off := true, false
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &off}
	identity, _ := endpointconfig.ComputeIdentity(config)
	cache := endpointconfig.NewCache(endpointconfig.DefaultCachePathForDB(dbPath))
	if err := cache.Apply(endpointconfig.FetchResult{Response: &endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	restored := 0
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch struct {
			Turns []sqlite.TurnRecord `json:"turns"`
		}
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, turn := range batch.Turns {
			if turn.ID != old.ID || turn.Prompt.Text == nil || *turn.Prompt.Text != text {
				t.Errorf("wrong restored turn: %+v", turn)
			}
			restored++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer cloud.Close()
	opts := Options{DBPath: dbPath, CloudURL: cloud.URL, InstallationID: "ins_test", InstallToken: "fixture", AllowHistoricalTurnRecovery: true}
	for range 2 {
		if err := Flush(ctx, opts); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if restored != 1 {
		t.Fatalf("restored uploads=%d, want exactly one", restored)
	}
}
