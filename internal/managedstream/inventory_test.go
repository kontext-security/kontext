package managedstream

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const testInstallation = "ins_inventory_fixture"

func openTestStore(t *testing.T) (*InventoryStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory-state.json")
	return OpenInventoryStore(path, testInstallation), path
}

func result(id, status string, reasons ...string) agentauthority.SourceResult {
	return agentauthority.SourceResult{ID: id, Status: status, Reasons: append([]string{}, reasons...), StartedAt: "2026-11-08T12:00:00Z", FinishedAt: "2026-11-08T12:00:01Z"}
}

func presenceScan(status string, ids ...string) agentinventory.Inventory {
	inv := agentinventory.Inventory{Agents: []agentinventory.Agent{}, ReportedAt: "2026-11-08T12:00:00Z"}
	for _, id := range ids {
		inv.Agents = append(inv.Agents, agentinventory.Agent{ID: id, ConfigPath: "~/." + id, Wired: agentinventory.WiredNo, Installed: agentinventory.InstalledYes, Configured: true})
	}
	inv.Sources = []agentauthority.SourceResult{result("cursor/presence", status), result("codex/presence", status)}
	return inv
}

func mcpScan(status string, names ...string) agentauthority.Report {
	a := agentauthority.Agent{ID: "cursor", MCPServers: []agentauthority.MCPServer{}, Plugins: []agentauthority.Plugin{}, Permissions: agentauthority.Permissions{Allow: []agentauthority.Grant{}}}
	for _, name := range names {
		command := "npx"
		a.MCPServers = append(a.MCPServers, agentauthority.MCPServer{Name: name, Command: &command, Args: []string{}, Source: "~/.cursor/mcp.json", Scope: "user"})
	}
	r := agentauthority.Report{SchemaVersion: "authority/v1", ScannedAt: "2026-11-08T12:00:00Z", Agents: []agentauthority.Agent{a}, Credentials: []agentauthority.Credential{}, Coverage: agentauthority.Coverage{UnknownFormat: []string{}, Errors: []string{}}}
	r.Seal()
	r.Sources = []agentauthority.SourceResult{result("cursor/mcp", status)}
	return r
}

func pendingOf(t *testing.T, store *InventoryStore, id string) pendingSource {
	t.Helper()
	entry, ok := store.pendingFor(id)
	if !ok {
		t.Fatalf("no pending %s", id)
	}
	return entry
}

func mcpNames(claims sourceClaims) []string {
	names := []string{}
	for _, server := range claims.MCPServers {
		names = append(names, server.Name)
	}
	slices.Sort(names)
	return names
}

func TestEachScanTakesANewPersistedRevision(t *testing.T) {
	store, path := openTestStore(t)
	for want := int64(1); want <= 2; want++ {
		if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
			t.Fatal(err)
		}
		if got := pendingOf(t, store, "cursor/presence").Result.Revision; got != want {
			t.Fatalf("revision = %d, want %d", got, want)
		}
	}
	reopened := OpenInventoryStore(path, testInstallation)
	if err := reopened.RecordAuthority(mcpScan(agentauthority.StatusComplete, "a")); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, reopened, "cursor/mcp").Result.Revision; got != 3 {
		t.Fatalf("revision after restart = %d", got)
	}
	// Results survive the restart too.
	if got := pendingOf(t, reopened, "codex/presence").Result.Revision; got != 2 {
		t.Fatalf("pending after restart = %d", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("state dir = %v, %v", entries, err)
	}
}

func TestAnotherInstallationStartsOver(t *testing.T) {
	store, path := openTestStore(t)
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	other := OpenInventoryStore(path, "ins_other_generation")
	if _, ok := other.pendingFor("cursor/presence"); ok {
		t.Fatal("pending result crossed installations")
	}
}

func TestCorruptStateStartsOverAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory-state.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := OpenInventoryStore(path, testInstallation)
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/presence").Result.Revision; got != 1 {
		t.Fatalf("revision = %d", got)
	}
}

func TestPendingMerge(t *testing.T) {
	first := func(store *InventoryStore) {
		t.Helper()
		if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete, "a", "b")); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		name, status string
		newer        []string
		reasons      []string
		wantStatus   string
		wantNames    []string
	}{
		{"complete replaces", agentauthority.StatusComplete, []string{"a"}, nil, agentauthority.StatusComplete, []string{"a"}},
		{"complete empty replaces", agentauthority.StatusComplete, nil, nil, agentauthority.StatusComplete, []string{}},
		{"partial merges", agentauthority.StatusPartial, []string{"a", "c"}, []string{agentauthority.ReasonWalkLimit}, agentauthority.StatusPartial, []string{"a", "b", "c"}},
		{"failed keeps claims as partial", agentauthority.StatusFailed, nil, []string{agentauthority.ReasonDeadline}, agentauthority.StatusPartial, []string{"a", "b"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := openTestStore(t)
			first(store)
			scan := mcpScan(tt.status, tt.newer...)
			scan.Sources[0].Reasons = append([]string{}, tt.reasons...)
			if err := store.RecordAuthority(scan); err != nil {
				t.Fatal(err)
			}
			got := pendingOf(t, store, "cursor/mcp")
			if got.Result.Status != tt.wantStatus || got.Result.Revision != 2 || !slices.Equal(mcpNames(got.Claims), tt.wantNames) {
				t.Fatalf("pending = %+v names %v", got.Result, mcpNames(got.Claims))
			}
			if tt.reasons != nil && !slices.Equal(got.Result.Reasons, tt.reasons) {
				t.Fatalf("reasons = %v", got.Result.Reasons)
			}
		})
	}
}

func TestFailedWithNothingPendingStaysFailed(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	scan := mcpScan(agentauthority.StatusFailed)
	scan.Sources[0].Reasons = []string{agentauthority.ReasonMalformed}
	if err := store.RecordAuthority(scan); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/mcp"); got.Result.Status != agentauthority.StatusFailed {
		t.Fatalf("status = %s", got.Result.Status)
	}
}

func TestSourceNotReachedIsLeftAlone(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusPartial, "a")); err != nil {
		t.Fatal(err)
	}
	before := pendingOf(t, store, "cursor/mcp")
	omitted := mcpScan(agentauthority.StatusComplete)
	omitted.Sources = []agentauthority.SourceResult{result("codex/mcp", agentauthority.StatusComplete)}
	if err := store.RecordAuthority(omitted); err != nil {
		t.Fatal(err)
	}
	after := pendingOf(t, store, "cursor/mcp")
	if after.Result.Revision != before.Result.Revision || !slices.Equal(mcpNames(after.Claims), []string{"a"}) {
		t.Fatalf("after = %+v", after)
	}
}

func TestPresenceRowSurvivesPartialMerge(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete, "cursor")); err != nil {
		t.Fatal(err)
	}
	failed := presenceScan(agentauthority.StatusFailed)
	if err := store.RecordAgents(failed); err != nil {
		t.Fatal(err)
	}
	got := pendingOf(t, store, "cursor/presence")
	if got.Claims.Agent == nil || got.Result.Status != agentauthority.StatusPartial {
		t.Fatalf("pending = %+v", got)
	}
	if empty := pendingOf(t, store, "codex/presence"); empty.Result.Status != agentauthority.StatusFailed {
		t.Fatalf("nothing pending should stay failed: %+v", empty.Result)
	}
}

func TestPermissionsMergeKeepsOlderObservations(t *testing.T) {
	mode := "plan"
	older := sourceClaims{Permissions: &agentauthority.Permissions{DefaultMode: &mode, Allow: []agentauthority.Grant{{Pattern: "Bash(rm *)", Risk: "delete"}}, DenyCount: 3}}
	newer := sourceClaims{Permissions: &agentauthority.Permissions{Allow: []agentauthority.Grant{{Pattern: "Bash", Risk: "any_shell"}}}}
	got := mergeClaims(older, newer).Permissions
	if got.DefaultMode == nil || *got.DefaultMode != "plan" || got.DenyCount != 3 || len(got.Allow) != 2 {
		t.Fatalf("permissions = %+v", got)
	}
	if kept := mergeClaims(older, sourceClaims{}).Permissions; kept == nil || kept.DenyCount != 3 {
		t.Fatalf("kept = %+v", kept)
	}
}

func TestPendingClaimsAreBounded(t *testing.T) {
	store, _ := openTestStore(t)
	for scan := 0; scan < 3; scan++ {
		names := []string{}
		for i := 0; i < 60; i++ {
			names = append(names, fmt.Sprintf("s%d-%d", scan, i))
		}
		if err := store.RecordAuthority(mcpScan(agentauthority.StatusPartial, names...)); err != nil {
			t.Fatal(err)
		}
	}
	got := pendingOf(t, store, "cursor/mcp").Claims.MCPServers
	if len(got) != maxPendingClaims {
		t.Fatalf("claims = %d", len(got))
	}
	// The newest scan's observations are the ones kept.
	for i := 0; i < 60; i++ {
		if got[i].Name != fmt.Sprintf("s2-%d", i) {
			t.Fatalf("claim %d = %s", i, got[i].Name)
		}
	}
}

func ackBody(acks ...InventoryAck) []InventoryAck { return acks }

func TestAcknowledgement(t *testing.T) {
	id := "cursor/presence"
	for _, tt := range []struct {
		name         string
		outcome      string
		applied      int64
		wantPending  bool
		wantRevision int64
	}{
		{"applied clears", "applied", 1, false, 0},
		{"duplicate clears", "duplicate", 1, false, 0},
		{"stale resends past the server", "stale", 41, true, 42},
		{"conflict resends past the server", "conflict", 41, true, 42},
		{"rejected drops", "rejected", 0, false, 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store, path := openTestStore(t)
			if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
				t.Fatal(err)
			}
			store.acknowledge(ackBody(InventoryAck{ID: id, Revision: 1, Outcome: tt.outcome, AppliedRevision: tt.applied}), nil, time.Now())
			entry, ok := store.pendingFor(id)
			if ok != tt.wantPending {
				t.Fatalf("pending = %t", ok)
			}
			if ok && entry.Result.Revision != tt.wantRevision {
				t.Fatalf("revision = %d, want %d", entry.Result.Revision, tt.wantRevision)
			}
			if tt.outcome == "stale" || tt.outcome == "conflict" {
				// The counter stays past the server across a restart.
				reopened := OpenInventoryStore(path, testInstallation)
				if err := reopened.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
					t.Fatal(err)
				}
				if got := pendingOf(t, reopened, id).Result.Revision; got <= 42 {
					t.Fatalf("next scan revision = %d", got)
				}
			}
		})
	}
}

func TestAckForASupersededRevisionKeepsTheNewerResult(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	store.acknowledge(ackBody(InventoryAck{ID: "cursor/presence", Revision: 1, Outcome: "applied", AppliedRevision: 1}), nil, time.Now())
	if got := pendingOf(t, store, "cursor/presence").Result.Revision; got != 2 {
		t.Fatalf("revision = %d", got)
	}
}

func payloadWith(store *InventoryStore, inv *agentinventory.Inventory, report *agentauthority.Report) Payload {
	opts := Options{Inventory: store}
	if inv != nil {
		opts.AgentsFact = func() (agentinventory.Inventory, bool) { return *inv, true }
	}
	if report != nil {
		opts.AuthorityFact = func() (agentauthority.Report, bool) { return *report, true }
	}
	payload := newPayload(opts, nil, nil, nil, nil, nil, time.Now())
	addAuthority(&payload, opts, State{}, time.Now())
	addInventory(&payload, opts)
	return payload
}

func TestSerializedInventoryShape(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusPartial, "cursor")
	scan.Sources = []agentauthority.SourceResult{result("cursor/presence", agentauthority.StatusPartial, agentauthority.ReasonPermissionDenied)}
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, &scan, nil)
	data, err := json.Marshal(payload.Device.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"schema":"inventory-sources-v1","sources":[{"id":"cursor/presence","revision":1,"status":"partial","reasons":["permission_denied"],"started_at":"2026-11-08T12:00:00Z","finished_at":"2026-11-08T12:00:01Z"}]}`
	if string(data) != want {
		t.Fatalf("wire = %s", data)
	}
}

// An upload with nothing pending still says so, or the server would read this
// CLI's agents as an older CLI's and refresh every timestamp.
func TestNothingPendingIsAnEmptyList(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	payload := payloadWith(store, &scan, nil)
	data, err := json.Marshal(payload.Device.Inventory)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"schema":"inventory-sources-v1","sources":[]}` {
		t.Fatalf("wire = %s", data)
	}
}

func TestNoStoreMeansNoInventoryField(t *testing.T) {
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	payload := payloadWith(nil, &scan, nil)
	if payload.Device.Inventory != nil {
		t.Fatalf("inventory = %+v", payload.Device.Inventory)
	}
}

func TestRetriedUploadKeepsItsTimestamps(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	report := mcpScan(agentauthority.StatusComplete, "a")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(report); err != nil {
		t.Fatal(err)
	}
	first := payloadWith(store, &scan, &report)
	time.Sleep(2 * time.Millisecond)
	second := payloadWith(store, &scan, &report)
	if a, b := marshalJSON(t, first.Device.Inventory), marshalJSON(t, second.Device.Inventory); a != b {
		t.Fatalf("inventory changed on retry:\n%s\n%s", a, b)
	}
	if first.Device.AgentsReportedAt != second.Device.AgentsReportedAt || first.Device.Authority.ScannedAt != second.Device.Authority.ScannedAt {
		t.Fatal("observation timestamps moved on retry")
	}
}

func marshalJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRetainedClaimsTravelInAgentsAndAuthority(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete, "cursor")); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete, "a", "b")); err != nil {
		t.Fatal(err)
	}
	failedScan := presenceScan(agentauthority.StatusFailed)
	failedReport := mcpScan(agentauthority.StatusPartial, "a")
	failedReport.Sources[0].Reasons = []string{agentauthority.ReasonWalkLimit}
	if err := store.RecordAgents(failedScan); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(failedReport); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, &failedScan, &failedReport)
	if agents := *payload.Device.Agents; len(agents) != 1 || agents[0].ID != "cursor" {
		t.Fatalf("agents = %+v", agents)
	}
	if len(failedScan.Agents) != 0 {
		t.Fatal("overlay changed the cached scan")
	}
	got := payload.Device.Authority.Agents[0].MCPServers
	if len(got) != 2 || len(failedReport.Agents[0].MCPServers) != 1 {
		t.Fatalf("servers = %+v, cached = %+v", got, failedReport.Agents[0].MCPServers)
	}
	want, err := payload.Device.Authority.ContentHash()
	if err != nil || payload.Device.Authority.Hash != want {
		t.Fatalf("hash = %s, want %s (%v)", payload.Device.Authority.Hash, want, err)
	}
}

func TestRetainedClaimsForAgentMissingFromTheReport(t *testing.T) {
	store, _ := openTestStore(t)
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete, "a")); err != nil {
		t.Fatal(err)
	}
	failed := mcpScan(agentauthority.StatusFailed)
	failed.Agents = []agentauthority.Agent{}
	failed.Sources[0].Reasons = []string{agentauthority.ReasonDeadline}
	failed.Seal()
	if err := store.RecordAuthority(failed); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, nil, &failed)
	agents := payload.Device.Authority.Agents
	if len(agents) != 1 || agents[0].ID != "cursor" || len(agents[0].MCPServers) != 1 || agents[0].Plugins == nil || agents[0].Permissions.Allow == nil {
		t.Fatalf("agents = %+v", agents)
	}
}

// A source's claims must travel with its result, or a complete withdraws them.
func TestSourcesTravelOnlyWithTheirClaims(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	report := mcpScan(agentauthority.StatusComplete, "a")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(report); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, &scan, nil)
	for _, source := range payload.Device.Inventory.Sources {
		if !strings.HasSuffix(source.ID, "/presence") {
			t.Fatalf("authority source without a report: %s", source.ID)
		}
	}
	payload = payloadWith(store, nil, &report)
	for _, source := range payload.Device.Inventory.Sources {
		if strings.HasSuffix(source.ID, "/presence") {
			t.Fatalf("presence source without agents: %s", source.ID)
		}
	}
}

func TestPendingAuthorityIsResentEvenWhenUnchanged(t *testing.T) {
	store, _ := openTestStore(t)
	report := mcpScan(agentauthority.StatusComplete, "a")
	if err := store.RecordAuthority(report); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	opts := Options{Inventory: store, AuthorityFact: func() (agentauthority.Report, bool) { return report, true }}
	state := State{LastReport: Report{Authority: &report}, LastAuthorityAt: now.Format(time.RFC3339Nano)}
	payload := Payload{}
	addAuthority(&payload, opts, state, now)
	if payload.Device == nil || payload.Device.Authority == nil {
		t.Fatal("a pending source went out without its claims")
	}
	store.acknowledge(ackBody(InventoryAck{ID: "cursor/mcp", Revision: 1, Outcome: "applied", AppliedRevision: 1}), nil, now)
	payload = Payload{}
	addAuthority(&payload, opts, state, now)
	if payload.Device != nil && payload.Device.Authority != nil {
		t.Fatal("acknowledged authority was resent before its hour")
	}
}

func TestDroppingAuthorityDropsItsSources(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	report := mcpScan(agentauthority.StatusComplete, "a")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(report); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, &scan, &report)
	dropAuthority(&payload)
	if payload.Device.Authority != nil {
		t.Fatal("authority kept")
	}
	for _, source := range payload.Device.Inventory.Sources {
		if !strings.HasSuffix(source.ID, "/presence") {
			t.Fatalf("source kept: %s", source.ID)
		}
	}
}

// Retained claims can push the report past its bound. A source that lost claims
// to that bound must not be uploaded as complete.
func TestSealedOverflowLowersACompleteSource(t *testing.T) {
	store, path := openTestStore(t)
	long := strings.Repeat("x", 120)
	huge := func(agent string, n int) agentauthority.Agent {
		a := agentauthority.Agent{ID: agent, MCPServers: []agentauthority.MCPServer{}, Plugins: []agentauthority.Plugin{}, Permissions: agentauthority.Permissions{Allow: []agentauthority.Grant{}}}
		for i := 0; i < n; i++ {
			a.MCPServers = append(a.MCPServers, agentauthority.MCPServer{Name: fmt.Sprintf("%s%d", long, i), Args: []string{strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60), strings.Repeat("d", 60)}, Source: "~/x", Scope: "user"})
		}
		return a
	}
	base := agentauthority.Report{SchemaVersion: "authority/v1", ScannedAt: "2026-11-08T12:00:00Z", Credentials: []agentauthority.Credential{}, Coverage: agentauthority.Coverage{UnknownFormat: []string{}, Errors: []string{}}}
	older := base
	older.Agents = []agentauthority.Agent{huge("kiro", 64), huge("amp", 64)}
	older.Sources = []agentauthority.SourceResult{result("kiro/mcp", agentauthority.StatusPartial), result("amp/mcp", agentauthority.StatusPartial)}
	if err := store.RecordAuthority(older); err != nil {
		t.Fatal(err)
	}
	newer := base
	newer.Agents = []agentauthority.Agent{huge("cursor", 64), huge("codex", 40)}
	newer.Sources = []agentauthority.SourceResult{result("cursor/mcp", agentauthority.StatusComplete), result("codex/mcp", agentauthority.StatusComplete)}
	if err := store.RecordAuthority(newer); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, nil, &newer)
	trimmed := 0
	for _, source := range payload.Device.Inventory.Sources {
		if slices.Contains(source.Reasons, agentauthority.ReasonSizeLimit) {
			trimmed++
			if source.Status == agentauthority.StatusComplete {
				t.Fatalf("trimmed source stayed complete: %+v", source)
			}
		}
	}
	if !payload.Device.Authority.Truncated || trimmed == 0 {
		t.Fatalf("truncated=%t trimmed=%d", payload.Device.Authority.Truncated, trimmed)
	}
	if got := pendingOf(t, store, "cursor/mcp").Result.Status; got != agentauthority.StatusComplete {
		t.Fatalf("the send-time bound changed the pending result: %s", got)
	}

	var acks []InventoryAck
	for _, source := range payload.Device.Inventory.Sources {
		if slices.Contains(source.Reasons, agentauthority.ReasonSizeLimit) {
			acks = append(acks, InventoryAck{ID: source.ID, Revision: source.Revision, Outcome: "applied", AppliedRevision: source.Revision})
		}
	}
	if err := store.acknowledge(acks, payload.Device.Inventory.Sources, time.Now()); err != nil {
		t.Fatal(err)
	}
	health, _ := LoadInventoryHealth(path)
	if _, overstated := health.AppliedRevisions[agentauthority.StatusComplete]; overstated || health.AppliedRevisions[agentauthority.StatusPartial] == 0 {
		t.Fatalf("doctor would report the wrong status: %+v", health.AppliedRevisions)
	}
}

type ingestFixture struct {
	responses chan func(http.ResponseWriter, []byte)
	bodies    chan []byte
	server    *httptest.Server
}

func flushOptions(t *testing.T, store *InventoryStore, inv agentinventory.Inventory) (Options, *ingestFixture) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")
	db, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	fixture := &ingestFixture{responses: make(chan func(http.ResponseWriter, []byte), 8), bodies: make(chan []byte, 8)}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&body)
		fixture.bodies <- body
		(<-fixture.responses)(w, body)
	}))
	t.Cleanup(fixture.server.Close)
	clock := time.Date(2026, 11, 8, 13, 0, 0, 0, time.UTC)
	return Options{
		DBPath: dbPath, StatePath: filepath.Join(dir, "stream-state.json"), CloudURL: fixture.server.URL,
		InstallationID: testInstallation, InstallToken: "test-token", HTTPClient: fixture.server.Client(),
		HeartbeatInterval: time.Second, Inventory: store,
		AgentsFact: func() (agentinventory.Inventory, bool) { return inv, true },
		Now:        func() time.Time { clock = clock.Add(time.Minute); return clock },
	}, fixture
}

func sentSources(t *testing.T, body []byte) []agentauthority.SourceResult {
	t.Helper()
	var payload struct {
		Device struct {
			Inventory *Inventory `json:"inventory"`
		} `json:"device"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Device.Inventory == nil {
		t.Fatalf("no inventory in %s", body)
	}
	return payload.Device.Inventory.Sources
}

func acknowledgeAll(t *testing.T, outcome string) func(http.ResponseWriter, []byte) {
	return func(w http.ResponseWriter, body []byte) {
		acks := []InventoryAck{}
		for _, source := range sentSources(t, body) {
			acks = append(acks, InventoryAck{ID: source.ID, Revision: source.Revision, Outcome: outcome, AppliedRevision: source.Revision})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"inventory_sources": acks})
	}
}

// Through the real flush: an outage keeps the results, a response without the
// field acknowledges nothing, and an applied response clears them.
func TestFlushKeepsResultsUntilAcknowledged(t *testing.T) {
	store, statePath := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	opts, fixture := flushOptions(t, store, scan)

	fixture.responses <- func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusBadGateway) }
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("outage reported as success")
	}
	first := sentSources(t, <-fixture.bodies)
	if len(first) != 2 {
		t.Fatalf("sources = %+v", first)
	}

	fixture.responses <- func(w http.ResponseWriter, _ []byte) { _, _ = w.Write([]byte(`{}`)) }
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	second := sentSources(t, <-fixture.bodies)
	if marshalJSON(t, first) != marshalJSON(t, second) {
		t.Fatalf("retry changed results:\n%v\n%v", first, second)
	}
	if _, ok := store.pendingFor("cursor/presence"); !ok {
		t.Fatal("a response without the field cleared pending results")
	}

	fixture.responses <- acknowledgeAll(t, "applied")
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	<-fixture.bodies
	if _, ok := store.pendingFor("cursor/presence"); ok {
		t.Fatal("applied result still pending")
	}
	health, ok := LoadInventoryHealth(statePath)
	if !ok || health.LastUploadAt == "" || health.AppliedRevisions[agentauthority.StatusComplete] != 1 || health.LastAttemptAt == "" || health.LastCompleteAt == "" {
		t.Fatalf("health = %+v, %t", health, ok)
	}
}

func TestFlushRecoversFromALostCounter(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	opts, fixture := flushOptions(t, store, scan)
	fixture.responses <- func(w http.ResponseWriter, body []byte) {
		acks := []InventoryAck{}
		for _, source := range sentSources(t, body) {
			acks = append(acks, InventoryAck{ID: source.ID, Revision: source.Revision, Outcome: "stale", AppliedRevision: 50})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"inventory_sources": acks})
	}
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	<-fixture.bodies
	fixture.responses <- acknowledgeAll(t, "applied")
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	for _, source := range sentSources(t, <-fixture.bodies) {
		if source.Revision != 51 {
			t.Fatalf("resent revision = %d", source.Revision)
		}
	}
	if len(store.snapshot()) != 0 {
		t.Fatal("recovery did not finish")
	}
}

// The fact is read before the pending snapshot, so a scan finishing between the
// two must not pair a complete result with the older scan's claims.
func TestCompleteResultTravelsWithItsOwnClaims(t *testing.T) {
	store, _ := openTestStore(t)
	older := mcpScan(agentauthority.StatusComplete, "a")
	newer := mcpScan(agentauthority.StatusComplete, "a", "b")
	if err := store.RecordAuthority(newer); err != nil {
		t.Fatal(err)
	}
	olderAgents := presenceScan(agentauthority.StatusComplete, "codex")
	newerAgents := presenceScan(agentauthority.StatusComplete, "cursor")
	if err := store.RecordAgents(newerAgents); err != nil {
		t.Fatal(err)
	}
	payload := payloadWith(store, &olderAgents, &older)
	if got := payload.Device.Authority.Agents[0].MCPServers; len(got) != 2 {
		t.Fatalf("servers = %+v", got)
	}
	want, err := payload.Device.Authority.ContentHash()
	if err != nil || payload.Device.Authority.Hash != want {
		t.Fatalf("hash = %s, want %s (%v)", payload.Device.Authority.Hash, want, err)
	}
	agents := *payload.Device.Agents
	if len(agents) != 1 || agents[0].ID != "cursor" {
		t.Fatalf("agents = %+v", agents)
	}
	if len(older.Agents[0].MCPServers) != 1 || olderAgents.Agents[0].ID != "codex" {
		t.Fatal("overlay changed the cached scans")
	}
}

func TestSnapshotEmptiesAClaimTheFactStillHas(t *testing.T) {
	store, _ := openTestStore(t)
	older := mcpScan(agentauthority.StatusComplete, "a")
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete)); err != nil {
		t.Fatal(err)
	}
	got := payloadWith(store, nil, &older).Device.Authority.Agents[0].MCPServers
	if got == nil || len(got) != 0 {
		t.Fatalf("servers = %#v", got)
	}
}

// Failure case 1: an inherited claim must not look freshly observed.
func TestMergeKeepsTheOlderFinishedAt(t *testing.T) {
	store, _ := openTestStore(t)
	first := mcpScan(agentauthority.StatusComplete, "a", "b")
	first.Sources[0].FinishedAt = "2026-11-08T11:00:00Z"
	if err := store.RecordAuthority(first); err != nil {
		t.Fatal(err)
	}
	second := mcpScan(agentauthority.StatusPartial, "a")
	second.Sources[0].Reasons = []string{agentauthority.ReasonWalkLimit}
	second.Sources[0].FinishedAt = "2026-11-08T12:00:00Z"
	if err := store.RecordAuthority(second); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/mcp").Result.FinishedAt; got != "2026-11-08T11:00:00Z" {
		t.Fatalf("finished_at = %s", got)
	}
	third := mcpScan(agentauthority.StatusComplete, "a")
	third.Sources[0].FinishedAt = "2026-11-08T13:00:00Z"
	if err := store.RecordAuthority(third); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/mcp").Result.FinishedAt; got != "2026-11-08T13:00:00Z" {
		t.Fatalf("a complete result is fresh: %s", got)
	}
}

func TestMergeWithNothingInheritedKeepsItsOwnFinishedAt(t *testing.T) {
	store, _ := openTestStore(t)
	empty := mcpScan(agentauthority.StatusFailed)
	empty.Sources[0].FinishedAt = "2026-11-08T11:00:00Z"
	if err := store.RecordAuthority(empty); err != nil {
		t.Fatal(err)
	}
	next := mcpScan(agentauthority.StatusPartial, "a")
	next.Sources[0].FinishedAt = "2026-11-08T12:00:00Z"
	if err := store.RecordAuthority(next); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/mcp").Result.FinishedAt; got != "2026-11-08T12:00:00Z" {
		t.Fatalf("finished_at = %s", got)
	}
}

// After an opt-out the server has cleared these claims, and it rejects anything
// dated before that as stale, so a resumed scan must not inherit them.
func TestDiscardAuthorityKeepsCounterAndPresence(t *testing.T) {
	store, path := openTestStore(t)
	first := mcpScan(agentauthority.StatusComplete, "a", "b")
	first.Sources[0].FinishedAt = "2026-11-08T11:00:00Z"
	if err := store.RecordAuthority(first); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete, "cursor")); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardAuthority(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.pendingFor("cursor/mcp"); ok {
		t.Fatal("authority result survived the opt-out")
	}
	if _, ok := store.pendingFor("cursor/presence"); !ok {
		t.Fatal("presence belongs to no opt-out")
	}
	reopened := OpenInventoryStore(path, testInstallation)
	if _, ok := reopened.pendingFor("cursor/mcp"); ok {
		t.Fatal("discard was not persisted")
	}
	resumed := mcpScan(agentauthority.StatusPartial, "a")
	resumed.Sources[0].Reasons = []string{agentauthority.ReasonWalkLimit}
	resumed.Sources[0].FinishedAt = "2026-11-08T13:00:00Z"
	if err := reopened.RecordAuthority(resumed); err != nil {
		t.Fatal(err)
	}
	got := pendingOf(t, reopened, "cursor/mcp")
	if got.Result.Revision != 3 || got.Result.FinishedAt != "2026-11-08T13:00:00Z" || !slices.Equal(mcpNames(got.Claims), []string{"a"}) {
		t.Fatalf("resumed = %+v names %v", got.Result, mcpNames(got.Claims))
	}
}

// A revision above the applied one cannot be an ordering problem: the server
// refused the result for predating an opt-out this endpoint never saw.
func TestStaleAboveAppliedRevisionDropsTheResult(t *testing.T) {
	store, _ := openTestStore(t)
	scan := presenceScan(agentauthority.StatusPartial, "cursor")
	if err := store.RecordAgents(scan); err != nil {
		t.Fatal(err)
	}
	if err := store.acknowledge(ackBody(InventoryAck{ID: "cursor/presence", Revision: 1, Outcome: "stale", AppliedRevision: 0}), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.pendingFor("cursor/presence"); ok {
		t.Fatal("a result older than the clear point would retry forever")
	}
	if _, ok := store.pendingFor("codex/presence"); !ok {
		t.Fatal("a verdict on one source touched another")
	}
	if err := store.RecordAgents(presenceScan(agentauthority.StatusPartial)); err != nil {
		t.Fatal(err)
	}
	got := pendingOf(t, store, "cursor/presence")
	if got.Result.Revision != 2 || got.Claims.Agent != nil {
		t.Fatalf("next scan inherited the dropped result: %+v", got)
	}
}

func TestStaleAboveAppliedKeepsANewerResult(t *testing.T) {
	store, _ := openTestStore(t)
	for range 2 {
		if err := store.RecordAgents(presenceScan(agentauthority.StatusComplete)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.acknowledge(ackBody(InventoryAck{ID: "cursor/presence", Revision: 1, Outcome: "stale", AppliedRevision: 0}), nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := pendingOf(t, store, "cursor/presence").Result.Revision; got != 2 {
		t.Fatalf("revision = %d", got)
	}
}
