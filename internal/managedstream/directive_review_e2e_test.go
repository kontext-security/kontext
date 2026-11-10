package managedstream

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/payloadcapture"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestDirectiveAuthorityE2E(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "endpoint.json")
	dbPath := filepath.Join(dir, "guard.db")
	cache := endpointconfig.NewCacheForDB(path, dbPath)
	on, off := true, false
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &off}
	var mu sync.Mutex
	status := 200
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if status != 200 {
			w.WriteHeader(status)
			return
		}
		identity, _ := endpointconfig.ComputeIdentity(config)
		w.Header().Set("ETag", `"`+identity+`"`)
		json.NewEncoder(w).Encode(endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity})
	}))
	defer cloud.Close()
	client, err := endpointconfig.NewClient(cloud.URL, cloud.Client())
	if err != nil {
		t.Fatal(err)
	}
	refresher := endpointconfig.Refresher{Cache: cache, Client: client, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", TokenSource: func(context.Context) (string, error) { return "fixture", nil }}
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
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
	var phases []map[string]string
	prompt := func(phase, want string) {
		t.Helper()
		s := cache.Current()
		host.SetPayloadCaptureConfiguration(payloadcapture.RuntimeConfiguration{ConfiguredMode: s.Configured.PayloadCaptureMode, EffectiveMode: s.Config.PayloadCaptureMode, Confirmed: s.Confirmed, ConfigIdentity: s.ConfigIdentity, WorkTypeClassification: s.Config.WorkTypeClassificationEnabled()})
		if _, err := host.ProcessHookEvent(ctx, risk.HookEvent{Agent: "claude", SessionID: phase, HookEventName: "UserPromptSubmit", ToolInput: map[string]any{"prompt": "explain this configuration fixture"}}); err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if err := job(ctx); err != nil {
				t.Fatal(err)
			}
		}
		jobs = nil
		turns, err := store.PendingTurns(ctx, 20)
		if err != nil {
			t.Fatal(err)
		}
		for _, turn := range turns {
			if turn.SessionID == phase {
				if turn.Prompt.Mode != want {
					t.Fatalf("%s: %s, want %s", phase, turn.Prompt.Mode, want)
				}
				phases = append(phases, map[string]string{"phase": phase, "promptMode": turn.Prompt.Mode})
				return
			}
		}
		t.Fatal("missing turn")
	}
	if err := refresher.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	prompt("confirmed", sqlite.TurnPromptExcerpt)
	mu.Lock()
	status = 503
	mu.Unlock()
	if err := refresher.Refresh(ctx); err == nil {
		t.Fatal("expected outage")
	}
	prompt("transient-outage", sqlite.TurnPromptExcerpt)
	// A valid stricter response must take effect despite a disk write failure.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	strict := config
	strict.WorkTypeClassification = &off
	identity, _ := endpointconfig.ComputeIdentity(strict)
	if err := cache.Apply(endpointconfig.FetchResult{Response: &endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: strict, ConfigIdentity: identity}}, time.Now()); err == nil {
		t.Fatal("expected cache write failure")
	}
	prompt("stricter-policy-write-failed", sqlite.TurnPromptSkipped)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	status = 200
	mu.Unlock()
	if err := refresher.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	oldCache, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	status = 401
	mu.Unlock()
	if err := refresher.Refresh(ctx); err == nil {
		t.Fatal("expected rejected authority")
	}
	prompt("revoked-authority", sqlite.TurnPromptSkipped)
	// Simulate a cache file surviving failed deletion. The independent journal
	// must reject it even after the original file becomes writable again.
	if err := os.WriteFile(path, oldCache, 0600); err != nil {
		t.Fatal(err)
	}
	restart := endpointconfig.NewCacheForDB(path, dbPath)
	if err := restart.Load(); err != nil && !errors.Is(err, endpointconfig.ErrCacheInvalidated) {
		t.Fatal(err)
	}
	if restart.Current().Config.WorkTypeClassificationEnabled() {
		t.Fatal("revoked directive survived restart")
	}
	mu.Lock()
	status = 200
	mu.Unlock()
	if err := refresher.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	restored := endpointconfig.NewCacheForDB(path, dbPath)
	if err := restored.Load(); err != nil {
		t.Fatal(err)
	}
	if !restored.Current().Config.WorkTypeClassificationEnabled() {
		t.Fatal("fresh authorization did not clear durable rejection")
	}
	if path := os.Getenv("KONTEXT_RECOVERY_E2E_ARTIFACT"); path != "" {
		body, _ := json.MarshalIndent(phases, "", "  ")
		if err := os.WriteFile(path+".authority.json", body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
