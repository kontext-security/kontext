package managedstream

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const hookSource = "claude_code/hooks"

func hookScan(status string, scopes map[string]string, hooks ...string) (agentauthority.HookAgent, agentauthority.SourceResult) {
	agent := agentauthority.HookAgent{ID: "claude_code", KontextHooks: agentauthority.KontextHookSet{State: "missing", MissingEvents: []string{}}, Scopes: []agentauthority.HookScope{}, Hooks: []agentauthority.HookRecord{}}
	ids := make([]string, 0, len(scopes))
	for id := range scopes {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		agent.Scopes = append(agent.Scopes, agentauthority.HookScope{ID: id, Kind: "user", Status: scopes[id], Reasons: []string{}, CheckedAt: "2026-11-08T12:00:01Z"})
	}
	// Each hook is "scope:name".
	for _, hook := range hooks {
		scope, name, _ := strings.Cut(hook, ":")
		agent.Hooks = append(agent.Hooks, agentauthority.HookRecord{ID: "hk_" + name, ScopeID: scope, Event: "PreToolUse", Type: "command", Origin: "user", ContentFP: "fp_" + name, Match: "anchor",
			Enablement: agentauthority.HookEnablement{State: "enabled", Reasons: []string{}}, Evidence: agentauthority.HookEvidence{Level: "discovered", DiscoveredAt: "2026-11-08T12:00:01Z"}})
	}
	return agent, result(hookSource, status)
}

func hookIDs(agent *agentauthority.HookAgent) []string {
	ids := []string{}
	for _, r := range agent.Hooks {
		ids = append(ids, r.ID)
	}
	slices.Sort(ids)
	return ids
}

func heartbeatWith(store *InventoryStore, hooksOn bool) Payload {
	opts := Options{Inventory: store, CLIVersion: "test", HookInventoryEnabled: func() bool { return hooksOn }, HookKeyTag: func() string { return "tag" }}
	payload := newPayload(opts, nil, nil, nil, nil, nil, time.Now())
	addInventory(&payload, opts)
	return payload
}

// The deployment's switch decides: off sends neither the block nor its
// source, and the result waits; on sends both, even in a heartbeat without
// agents or authority.
func TestHookInventoryFollowsTheSwitch(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:one")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	if off := heartbeatWith(store, false); off.Device.HookInventory != nil || off.Device.Inventory != nil {
		t.Fatalf("switch off sent %+v %+v", off.Device.HookInventory, off.Device.Inventory)
	}
	on := heartbeatWith(store, true)
	if on.Device.HookInventory == nil || on.Device.Inventory == nil {
		t.Fatalf("switch on sent nothing: %+v", on.Device)
	}
	block := on.Device.HookInventory
	if block.Schema != "hook-inventory-v1" || block.IDScheme != 1 || len(block.Agents) != 1 || block.Agents[0].Hooks[0].ID != "hk_one" {
		t.Fatalf("block %+v", block)
	}
	if sources := on.Device.Inventory.Sources; len(sources) != 1 || sources[0].ID != hookSource || sources[0].Status != agentauthority.StatusComplete {
		t.Fatalf("sources %+v", sources)
	}
	data, _ := json.Marshal(on.Device)
	if !strings.Contains(string(data), `"hook_inventory":{"schema":"hook-inventory-v1","id_scheme":1,`) {
		t.Fatalf("wire %s", data)
	}
}

// An authority opt-out leaves hook results alone, and the hook switch going
// off leaves authority results alone.
func TestHookAndAuthorityDiscardsAreSeparate(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:one")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete, "github")); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardAuthority(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.pendingFor(hookSource); !ok {
		t.Fatal("authority opt-out dropped the hook result")
	}
	if err := store.RecordAuthority(mcpScan(agentauthority.StatusComplete, "github")); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardHooks(); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.pendingFor(hookSource); ok {
		t.Fatal("hook result kept after the switch went off")
	}
	if _, ok := store.pendingFor("cursor/mcp"); !ok {
		t.Fatal("hook switch dropped the authority result")
	}
	if !store.hasPendingAuthority() {
		t.Fatal("hasPendingAuthority counts hook sources only")
	}
}

// A scan that cannot read a scope keeps what an unacknowledged scan read
// there completely; a scope it reads completely replaces the older one.
func TestHookMergeKeepsCompleteScopes(t *testing.T) {
	store, _ := openTestStore(t)
	older, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete", "sc_b": "complete"}, "sc_a:a1", "sc_b:b1")
	if err := store.RecordHooks(older, res, "tag"); err != nil {
		t.Fatal(err)
	}
	newer, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_a": "failed", "sc_b": "complete"}, "sc_b:b2")
	if err := store.RecordHooks(newer, res, "tag"); err != nil {
		t.Fatal(err)
	}
	merged := pendingOf(t, store, hookSource)
	if got := hookIDs(merged.Claims.Hooks); !slices.Equal(got, []string{"hk_a1", "hk_b2"}) {
		t.Fatalf("hooks %v", got)
	}
	for _, scope := range merged.Claims.Hooks.Scopes {
		if scope.Status != agentauthority.StatusComplete {
			t.Fatalf("scope %+v", scope)
		}
	}
	if merged.Result.Status != agentauthority.StatusPartial || merged.Result.FinishedAt != "2026-11-08T12:00:01Z" {
		t.Fatalf("result %+v", merged.Result)
	}
	// A failed source with nothing in it keeps the older scan whole.
	failed := agentauthority.HookAgent{ID: "claude_code", Scopes: []agentauthority.HookScope{}, Hooks: []agentauthority.HookRecord{}}
	if err := store.RecordHooks(failed, result(hookSource, agentauthority.StatusFailed, agentauthority.ReasonMalformed), "tag"); err != nil {
		t.Fatal(err)
	}
	if got := hookIDs(pendingOf(t, store, hookSource).Claims.Hooks); !slices.Equal(got, []string{"hk_a1", "hk_b2"}) {
		t.Fatalf("after failure %v", got)
	}
}

// A block over the budget loses hooks from its end, says it is truncated,
// and its source goes out partial, so the cloud withdraws nothing.
func TestHookBlockStaysInsideTheBudget(t *testing.T) {
	store, _ := openTestStore(t)
	hooks := []string{}
	for i := range agentauthority.MaxHookRecords {
		hooks = append(hooks, "sc_a:"+strconv.Itoa(i))
	}
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, hooks...)
	long := strings.Repeat("x", 240)
	for i := range agent.Hooks {
		agent.Hooks[i].Summary = &long
	}
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	payload := heartbeatWith(store, true)
	data, _ := json.Marshal(payload.Device.HookInventory)
	block := payload.Device.HookInventory
	if len(data) > hookBlockBudget || !block.Agents[0].Truncated || len(block.Agents[0].Hooks) == 0 || len(block.Agents[0].Hooks) >= agentauthority.MaxHookRecords {
		t.Fatalf("%d bytes, truncated=%v, %d hooks", len(data), block.Agents[0].Truncated, len(block.Agents[0].Hooks))
	}
	source := payload.Device.Inventory.Sources[0]
	if source.Status != agentauthority.StatusPartial || !slices.Contains(source.Reasons, agentauthority.ReasonSizeLimit) {
		t.Fatalf("source %+v", source)
	}
	// The scope that lost records goes partial, so a cut record isn't
	// withdrawn from it.
	if scope := block.Agents[0].Scopes[0]; scope.Status != agentauthority.StatusPartial || !slices.Contains(scope.Reasons, agentauthority.ReasonSizeLimit) {
		t.Fatalf("trimmed scope %+v", scope)
	}
	// The stored result is untouched: a later upload may fit.
	if pending := pendingOf(t, store, hookSource); len(pending.Claims.Hooks.Hooks) != agentauthority.MaxHookRecords || pending.Claims.Hooks.Truncated || pending.Claims.Hooks.Scopes[0].Status != agentauthority.StatusComplete {
		t.Fatal("trimming changed the stored scan")
	}
}

// Through the real flush: the hook source is acknowledged like any other.
func TestFlushAcknowledgesHookSource(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:one")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	scan := presenceScan(agentauthority.StatusComplete, "cursor")
	opts, fixture := flushOptions(t, store, scan)
	opts.HookInventoryEnabled = func() bool { return true }
	opts.HookKeyTag = func() string { return "tag" }
	fixture.responses <- acknowledgeAll(t, "applied")
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	body := <-fixture.bodies
	if !strings.Contains(string(body), `"hook_inventory"`) || !slices.ContainsFunc(sentSources(t, body), func(r agentauthority.SourceResult) bool { return r.ID == hookSource }) {
		t.Fatalf("body %s", body)
	}
	if _, ok := store.pendingFor(hookSource); ok {
		t.Fatal("applied hook source still pending")
	}
}

// Hook ids are keyed per workspace: a result recorded under another key, or
// while no key is known, never travels, and a newer partial scan under a new
// key inherits nothing from the old one.
func TestHookResultsTravelOnlyUnderTheirKey(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:old")
	if err := store.RecordHooks(agent, res, "acme"); err != nil {
		t.Fatal(err)
	}
	send := func(tag string) Payload {
		opts := Options{Inventory: store, CLIVersion: "test", HookInventoryEnabled: func() bool { return true }, HookKeyTag: func() string { return tag }}
		payload := newPayload(opts, nil, nil, nil, nil, nil, time.Now())
		addInventory(&payload, opts)
		return payload
	}
	for _, tag := range []string{"", "other"} {
		if p := send(tag); p.Device.HookInventory != nil || p.Device.Inventory != nil {
			t.Fatalf("tag %q sent %+v", tag, p.Device.HookInventory)
		}
	}
	if p := send("acme"); p.Device.HookInventory == nil {
		t.Fatal("own key's result not sent")
	}
	newer, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_b": "complete"}, "sc_b:new")
	if err := store.RecordHooks(newer, res, "other"); err != nil {
		t.Fatal(err)
	}
	if got := hookIDs(pendingOf(t, store, hookSource).Claims.Hooks); !slices.Equal(got, []string{"hk_new"}) {
		t.Fatalf("merged across keys: %v", got)
	}
}

// A flush that can't name the current key sends no hook result.
func TestHookResultsNeedAKeyTagCallback(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:one")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	opts := Options{Inventory: store, CLIVersion: "test", HookInventoryEnabled: func() bool { return true }}
	payload := newPayload(opts, nil, nil, nil, nil, nil, time.Now())
	addInventory(&payload, opts)
	if payload.Device.HookInventory != nil || payload.Device.Inventory != nil {
		t.Fatalf("sent without a key tag: %+v", payload.Device.HookInventory)
	}
}

// A partial scope that holds new records keeps them beside the older
// complete scan's, and stays partial, so nothing is withdrawn there.
func TestHookMergeKeepsNewRecordsInAPartialScope(t *testing.T) {
	store, _ := openTestStore(t)
	older, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:a")
	if err := store.RecordHooks(older, res, "tag"); err != nil {
		t.Fatal(err)
	}
	newer, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_a": "partial"}, "sc_a:b")
	if err := store.RecordHooks(newer, res, "tag"); err != nil {
		t.Fatal(err)
	}
	merged := pendingOf(t, store, hookSource).Claims.Hooks
	if got := hookIDs(merged); !slices.Equal(got, []string{"hk_a", "hk_b"}) {
		t.Fatalf("hooks %v", got)
	}
	if merged.Scopes[0].Status != "partial" {
		t.Fatalf("scope %+v", merged.Scopes[0])
	}
	// More incomplete scans before an upload keep every older record.
	third, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_a": "partial"}, "sc_a:c")
	if err := store.RecordHooks(third, res, "tag"); err != nil {
		t.Fatal(err)
	}
	failed, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_a": "failed"})
	if err := store.RecordHooks(failed, res, "tag"); err != nil {
		t.Fatal(err)
	}
	merged = pendingOf(t, store, hookSource).Claims.Hooks
	if got := hookIDs(merged); !slices.Equal(got, []string{"hk_a", "hk_b", "hk_c"}) {
		t.Fatalf("hooks after more partial scans %v", got)
	}
	if merged.Scopes[0].Status != "failed" {
		t.Fatalf("scope %+v", merged.Scopes[0])
	}
}

// A purge whose write failed writes again next time, even though memory
// already dropped the results.
func TestDiscardHooksWritesAgainAfterAFailedWrite(t *testing.T) {
	store, path := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:a")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	// A non-empty directory where the file goes refuses the write, for root
	// too.
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(path, "busy"), 0o700); err != nil {
		t.Fatal(err)
	}
	if store.DiscardHooks() == nil {
		t.Fatal("DiscardHooks() wrote over a directory")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.DiscardHooks(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "hk_a") {
		t.Fatalf("purged hook still on disk: %s", data)
	}
}

// A result an older build stored travels only once this build has rescanned:
// its summaries may hold what the current redaction drops.
func TestHookResultsFromAnOlderRedactorStayHome(t *testing.T) {
	store, _ := openTestStore(t)
	agent, res := hookScan(agentauthority.StatusComplete, map[string]string{"sc_a": "complete"}, "sc_a:a")
	if err := store.RecordHooks(agent, res, "tag"); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	entry := store.file.Pending[hookSource]
	entry.Claims.Redactor = hookRedactor - 1
	store.file.Pending[hookSource] = entry
	store.mu.Unlock()
	if block := heartbeatWith(store, true).Device.HookInventory; block != nil && len(block.Agents) > 0 {
		t.Fatalf("older redactor's result sent: %+v", block)
	}
	// A partial rescan doesn't merge it in either.
	newer, res := hookScan(agentauthority.StatusPartial, map[string]string{"sc_a": "partial"}, "sc_a:b")
	if err := store.RecordHooks(newer, res, "tag"); err != nil {
		t.Fatal(err)
	}
	if got := hookIDs(pendingOf(t, store, hookSource).Claims.Hooks); !slices.Equal(got, []string{"hk_b"}) {
		t.Fatalf("hooks %v", got)
	}
}
