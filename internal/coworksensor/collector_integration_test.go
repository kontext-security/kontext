//go:build integration

package coworksensor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/managedstream"
)

func TestTranscriptObservationReachesUploaderWithoutDecision(t *testing.T) {
	cfg := testConfig(t)
	cfg.Interval = 20 * time.Millisecond
	payloads := make(chan managedstream.Payload, 100)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-install-token" {
			w.WriteHeader(401)
			return
		}
		var p managedstream.Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		payloads <- p
		w.WriteHeader(201)
		io.WriteString(w, `{"quarantined":[],"altered":[]}`)
	}))
	defer api.Close()
	cfg.CloudURL = api.URL
	cfg.AllowHTTPLoopback = true
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg, "collector-test", io.Discard) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	socket := filepath.Join(cfg.RuntimeDir, "observations.sock")
	for {
		if _, err := os.Stat(socket); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("sensor exited: %v", err)
		case <-ctx.Done():
			t.Fatal("sensor not ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
	client := observationClient(socket)
	defer client.CloseIdleConnections()
	pairs := transcriptPairs{session: collectorSession}
	_, err := pairs.line([]byte(transcriptFixture("assistant", `[{"type":"tool_use","id":"toolu_observed","name":"mcp__workspace__bash","input":{"command":"printf harmless"}}]`)))
	if err != nil {
		t.Fatal(err)
	}
	items, err := pairs.line([]byte(transcriptFixture("user", `[{"type":"tool_result","tool_use_id":"toolu_observed","content":"PRIVATE OUTPUT"}]`)))
	if err != nil || len(items) != 1 {
		t.Fatal("pair not observed", err)
	}
	id, err := postObservation(ctx, client, items[0])
	if err != nil {
		t.Fatal(err)
	}
	id2, err := postObservation(ctx, client, items[0])
	if err != nil || id != id2 {
		t.Fatal("retry not idempotent", err)
	}
	for {
		select {
		case p := <-payloads:
			for _, a := range p.Actions {
				if a["id"] != id {
					continue
				}
				if a["decision_result"] != nil || a["canonical_event_type"] != "request.observed" || a["adapter_event_name"] != "CoworkTranscriptToolResult" {
					t.Fatalf("fabricated authority: %+v", a)
				}
				b, _ := json.Marshal(a)
				if !strings.Contains(string(b), "cowork.vm_mounted_transcript") || strings.Contains(string(b), "PRIVATE OUTPUT") || a["tool_use_id"] != "toolu_observed" {
					t.Fatalf("wrong evidence: %s", b)
				}
				if len(p.Actions) != 1 || len(p.Receipts) != 1 {
					t.Fatalf("duplicate action/receipt: %d/%d", len(p.Actions), len(p.Receipts))
				}
				return
			}
		case <-ctx.Done():
			t.Fatal("observation did not reach uploader")
		}
	}
}
