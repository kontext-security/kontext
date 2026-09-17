package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

func TestAuthorityFlushCadenceAndLastSent(t *testing.T) {
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	_, dbPath := testStore(t)
	data, err := os.ReadFile("../../pkg/agentauthority/testdata/contract/authority-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var report agentauthority.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	enabled, reject := true, false
	var payload Payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if reject {
			w.WriteHeader(500)
		} else {
			w.WriteHeader(202)
		}
	}))
	defer server.Close()
	opts := Options{DBPath: dbPath, StatePath: filepath.Join(t.TempDir(), "state.json"), CloudURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", InstallToken: "test", Now: func() time.Time { return now }, AuthorityFact: func() (agentauthority.Report, bool) { return report, enabled }, AgentsFact: func() (agentinventory.Inventory, bool) {
		return agentinventory.Inventory{Agents: []agentinventory.Agent{}, ReportedAt: now.Format(time.RFC3339)}, true
	}}
	flush := func(want bool) {
		t.Helper()
		payload = Payload{}
		if err := Flush(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		if payload.Device == nil || (payload.Device.Authority != nil) != want {
			t.Fatalf("authority present=%t, want %t", payload.Device != nil && payload.Device.Authority != nil, want)
		}
	}
	flush(true)
	first := report
	now = now.Add(time.Minute)
	report.ScannedAt = now.Format(time.RFC3339)
	flush(false)
	state, err := LoadState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.LastReport.Authority, &first) {
		t.Fatal("unsent scan replaced last sent report")
	}
	now = now.Add(59 * time.Minute)
	flush(true)
	now = now.Add(time.Minute)
	report.Hash = "changed"
	flush(true)
	now = now.Add(time.Minute)
	enabled = false
	report.Hash = "off"
	flush(false)
	now = now.Add(time.Minute)
	enabled = true
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "off")
	flush(false)
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	now = now.Add(time.Minute)
	reject = true
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("failed post accepted")
	}
	state, err = LoadState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastReport.Authority != nil {
		t.Fatal("failed post advanced last sent report")
	}
	now = now.Add(time.Minute)
	reject = false
	flush(true)
}

func TestAuthorityReportDoesNotDiscardMinimumLedgerBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "tool-1")
	report := agentauthority.Report{Hash: "large", Coverage: agentauthority.Coverage{Errors: []string{strings.Repeat("x", MaxPayloadBytes)}}}
	var got Payload
	server := capturePayloadServer(t, &got)
	defer server.Close()
	opts := Options{DBPath: dbPath, StatePath: filepath.Join(t.TempDir(), "state.json"), CloudURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", InstallToken: "test-install-token", BatchLimit: 1, AuthorityFact: func() (agentauthority.Report, bool) { return report, true }}
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if len(got.Actions) == 0 {
		t.Fatal("authority displaced the ledger action")
	}
	if got.Device.Authority != nil {
		t.Fatal("oversized report sent with minimum batch")
	}
	state, err := LoadState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastReport.Authority != nil || state.LastAuthorityAt != "" {
		t.Fatal("omitted authority marked sent")
	}
}

func TestAuthoritySwitchRecovery(t *testing.T) {
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	_, dbPath := testStore(t)
	now := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	report := agentauthority.Report{Hash: "unchanged"}
	available := make(chan struct{}, 1)
	var payload Payload
	server := capturePayloadServer(t, &payload)
	defer server.Close()
	opts := Options{DBPath: dbPath, StatePath: filepath.Join(t.TempDir(), "state.json"), CloudURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", InstallToken: "test-install-token", Now: func() time.Time { return now }, AuthorityAvailable: available, AuthorityFact: func() (agentauthority.Report, bool) { return report, true }}
	flush := func(wantReport, wantOff bool) {
		t.Helper()
		now = now.Add(time.Minute)
		payload = Payload{}
		if err := Flush(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
		gotReport := payload.Device != nil && payload.Device.Authority != nil
		gotOff := payload.Device != nil && payload.Device.AuthorityScan != nil && !*payload.Device.AuthorityScan
		if gotReport != wantReport || gotOff != wantOff {
			t.Fatalf("payload = %+v; want report=%t off=%t", payload.Device, wantReport, wantOff)
		}
	}
	flush(true, false)
	flush(false, false)
	// Policy refresh observed off -> on; the unchanged hash must resend immediately.
	available <- struct{}{}
	flush(true, false)
	flush(false, false)
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "off")
	flush(false, true)
	flush(false, true)
	state, err := LoadState(opts.StatePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.LastReport.Authority != nil || state.LastAuthorityAt != "" {
		t.Fatal("accepted local clear retained last authority")
	}
	t.Setenv("KONTEXT_AUTHORITY_SCAN", "")
	flush(true, false)
}
