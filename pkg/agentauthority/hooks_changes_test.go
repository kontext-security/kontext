package agentauthority

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func changeKinds(changes []HookChange) []string {
	out := []string{}
	for _, c := range changes {
		id := c.HookID
		if id == "" {
			id = c.ScopeID
		}
		out = append(out, c.Kind+":"+id)
	}
	return out
}

type changeScan struct {
	status    string
	truncated bool
	scopes    map[string]string
	hooks     []HookRecord
}

func (c changeScan) agent() (HookAgent, SourceResult) {
	agent := HookAgent{ID: "claude_code", Truncated: c.truncated, Hooks: c.hooks}
	for id, status := range c.scopes {
		scope := HookScope{ID: id, Kind: HookScopeUser, Status: status, Reasons: []string{}}
		if status != StatusComplete {
			scope.Reasons = []string{ReasonReadError}
		}
		agent.Scopes = append(agent.Scopes, scope)
	}
	slices.SortFunc(agent.Scopes, func(a, b HookScope) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	return agent, SourceResult{ID: HookSourceID("claude_code"), Status: c.status, FinishedAt: "2026-11-22T10:00:00Z"}
}

func hookIn(scope, id, fp, state string) HookRecord {
	return HookRecord{ID: id, ScopeID: scope, Event: "Stop", ContentFP: fp, Enablement: HookEnablement{State: state}}
}

// Each scan is compared with the baseline the scans before it left.
func TestHookChanges(t *testing.T) {
	complete := StatusComplete
	steps := []struct {
		name string
		scan changeScan
		want []string
	}{
		{"the first scan sets the baseline", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("a", "h1", "f1", hookEnabled), hookIn("b", "h2", "f2", hookEnabled)}}, []string{}},
		{"an unchanged scan reports nothing", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("a", "h1", "f1", hookEnabled), hookIn("b", "h2", "f2", hookEnabled)}}, []string{}},
		{"new content and a new state are changes, a new id an addition", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("a", "h1", "f9", hookEnabled), hookIn("b", "h2", "f2", hookDisabled), hookIn("b", "h3", "f3", hookEnabled)}}, []string{"changed:h1", "changed:h2", "added:h3"}},
		{"an unreadable scope is a failed check and removes nothing", changeScan{StatusPartial, false, map[string]string{"a": StatusFailed, "b": complete}, []HookRecord{hookIn("b", "h2", "f2", hookDisabled), hookIn("b", "h3", "f3", hookEnabled)}}, []string{"check_failed:a"}},
		{"a scope that stays unreadable is reported once", changeScan{StatusPartial, false, map[string]string{"a": StatusFailed, "b": complete}, []HookRecord{hookIn("b", "h2", "f2", hookDisabled), hookIn("b", "h3", "f3", hookEnabled)}}, []string{}},
		{"a failed source with no scope to blame is a source check failure, and removes nothing", changeScan{StatusFailed, false, map[string]string{}, nil}, []string{"check_failed:" + HookChangeSourceScope}},
		{"a recovered scope reports only what changed meanwhile", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("a", "h1", "f9", hookEnabled), hookIn("b", "h2", "f2", hookDisabled)}}, []string{"removed:h3"}},
		{"a hook gone from a complete scope is removed", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("b", "h2", "f2", hookDisabled)}}, []string{"removed:h1"}},
		{"a truncated scan withdraws no unlisted scope, and says it lost sight", changeScan{StatusPartial, true, map[string]string{"a": complete}, nil}, []string{"check_failed:" + HookChangeSourceScope}},
		{"an unlisted scope's hooks go with a complete scan", changeScan{complete, false, map[string]string{"a": complete}, nil}, []string{"removed:h2"}},
		{"a scope failing again after recovering is reported again", changeScan{StatusPartial, false, map[string]string{"a": StatusFailed}, nil}, []string{"check_failed:a"}},
	}
	var base *HookBaseline
	for _, step := range steps {
		agent, source := step.scan.agent()
		changes, next := HookChanges(base, agent, source)
		if got := changeKinds(changes); !slices.Equal(got, step.want) {
			t.Fatalf("%s: got %v, want %v", step.name, got, step.want)
		}
		for _, c := range changes {
			if c.At != source.FinishedAt || c.ScopeID == "" {
				t.Fatalf("%s: %+v", step.name, c)
			}
		}
		base = next
	}
}

// A change made between two scans shows on the next scan.
func TestHookChangeShowsOnTheNextScan(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	agent, source := h.scan()
	_, base := HookChanges(nil, agent, source)
	if base == nil {
		t.Fatal("a complete first scan sets no baseline")
	}

	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"Stop":         hooksOf("Stop", "", command("echo stop"))["Stop"],
		"SessionStart": hooksOf("SessionStart", "", command("echo hello"))["SessionStart"],
	}})
	agent, source = h.scan()
	changes, base := HookChanges(base, agent, source)
	if len(changes) != 1 || changes[0].Kind != HookChangeAdded || changes[0].Event != "SessionStart" {
		t.Fatalf("%+v", changes)
	}

	// Unparsed settings fail the scope's check and keep its hooks.
	h.write(filepath.Join(h.base, "settings.json"), []byte(`{"hooks": [`))
	agent, source = h.scan()
	changes, base = HookChanges(base, agent, source)
	if got := changeKinds(changes); len(got) != 1 || changes[0].Kind != HookChangeCheckFailed || !slices.Equal(changes[0].Reasons, []string{ReasonMalformed}) {
		t.Fatalf("%+v", changes)
	}
	if len(base.Hooks) != 2 {
		t.Fatalf("baseline lost hooks of an unread scope: %+v", base.Hooks)
	}

	// Removing the file is a complete read with no hooks.
	if err := os.Remove(filepath.Join(h.base, "settings.json")); err != nil {
		t.Fatal(err)
	}
	agent, source = h.scan()
	changes, _ = HookChanges(base, agent, source)
	if got := changeKinds(changes); len(got) != 2 || changes[0].Kind != HookChangeRemoved || changes[1].Kind != HookChangeRemoved {
		t.Fatalf("%+v", changes)
	}
}

// A failed first scan sets no baseline, so the next readable scan is still
// the first and reports nothing.
func TestFailedFirstScanSetsNoBaseline(t *testing.T) {
	agent, source := changeScan{StatusFailed, false, map[string]string{"a": StatusFailed}, nil}.agent()
	changes, base := HookChanges(nil, agent, source)
	if len(changes) != 0 || base != nil {
		t.Fatalf("%+v %+v", changes, base)
	}
}

// A failed source still reports the scopes it names as unreadable, once.
func TestFailedSourceReportsItsUnreadScopes(t *testing.T) {
	agent, source := changeScan{StatusComplete, false, map[string]string{"a": StatusComplete}, []HookRecord{hookIn("a", "h1", "f1", hookEnabled)}}.agent()
	_, base := HookChanges(nil, agent, source)
	agent, source = changeScan{StatusFailed, false, map[string]string{"a": StatusFailed}, nil}.agent()
	changes, base := HookChanges(base, agent, source)
	if got := changeKinds(changes); !slices.Equal(got, []string{"check_failed:a"}) || len(base.Hooks) != 1 {
		t.Fatalf("%v %+v", got, base)
	}
	if changes, _ := HookChanges(base, agent, source); len(changes) != 0 {
		t.Fatalf("reported twice: %+v", changes)
	}
}

// Changes name only known events.
func TestHookChangesNameKnownEventsOnly(t *testing.T) {
	agent, source := changeScan{StatusComplete, false, map[string]string{"a": StatusComplete}, nil}.agent()
	_, base := HookChanges(nil, agent, source)
	odd := hookIn("a", "h1", "f1", hookEnabled)
	odd.Event = "FAKEhunter2Event"
	agent.Hooks = []HookRecord{odd, hookIn("a", "h2", "f2", hookEnabled)}
	changes, _ := HookChanges(base, agent, source)
	if len(changes) != 2 || changes[0].Event != HookEventOther || changes[1].Event != "Stop" {
		t.Fatalf("%+v", changes)
	}
}

// Hooks carried over from unread scopes are bounded; what the scan read
// itself is kept.
func TestBaselineIsBounded(t *testing.T) {
	base := &HookBaseline{Hooks: map[string]HookBaselineEntry{}, Scopes: map[string]string{}}
	for i := range maxBaselineHooks {
		base.Hooks[fmt.Sprintf("old%05d", i)] = HookBaselineEntry{ScopeID: "gone", Event: "Stop"}
	}
	for i := range maxBaselineScopes {
		base.Scopes[fmt.Sprintf("gone%05d", i)] = StatusFailed
	}
	agent, source := changeScan{StatusPartial, false, map[string]string{"a": StatusComplete}, []HookRecord{hookIn("a", "new", "f1", hookEnabled)}}.agent()
	_, next := HookChanges(base, agent, source)
	if len(next.Hooks) != maxBaselineHooks || len(next.Scopes) != maxBaselineScopes {
		t.Fatalf("%d hooks, %d scopes", len(next.Hooks), len(next.Scopes))
	}
	if _, ok := next.Hooks["new"]; !ok {
		t.Fatal("dropped a hook the scan read")
	}
	if _, ok := next.Scopes["a"]; !ok {
		t.Fatal("dropped a scope the scan listed")
	}
}

// A scan that loses sight of hooks with no scope to say why, such as an
// unreadable plugin registry, reports one source-level check failure.
func TestUnexplainedPartialScanIsACheckFailure(t *testing.T) {
	agent, source := changeScan{StatusComplete, false, map[string]string{"a": StatusComplete}, []HookRecord{hookIn("a", "h1", "f1", hookEnabled)}}.agent()
	_, base := HookChanges(nil, agent, source)
	agent, source = changeScan{StatusPartial, false, map[string]string{}, nil}.agent()
	source.Reasons = []string{ReasonMalformed}
	changes, next := HookChanges(base, agent, source)
	if got := changeKinds(changes); !slices.Equal(got, []string{"check_failed:" + HookChangeSourceScope}) || !slices.Equal(changes[0].Reasons, []string{ReasonMalformed}) {
		t.Fatalf("%v %+v", got, changes)
	}
	if len(next.Hooks) != 1 {
		t.Fatalf("the unseen hook was dropped: %+v", next.Hooks)
	}
	if again, _ := HookChanges(next, agent, source); len(again) != 0 {
		t.Fatalf("reported twice: %+v", again)
	}
	// A scope failing meanwhile doesn't end the outage, so it isn't
	// reported again once that scope recovers.
	failed, failedSource := changeScan{StatusPartial, false, map[string]string{"a": StatusFailed}, nil}.agent()
	_, during := HookChanges(next, failed, failedSource)
	if during.Source == "" {
		t.Fatal("the outage was forgotten while a scope failed")
	}
	if after, _ := HookChanges(during, agent, source); slices.Contains(changeKinds(after), "check_failed:"+HookChangeSourceScope) {
		t.Fatalf("one outage reported twice: %+v", after)
	}
}

// The baseline keeps only known event names, as the changes do.
func TestBaselineKeepsKnownEventsOnly(t *testing.T) {
	odd := hookIn("a", "h1", "f1", hookEnabled)
	odd.Event = "FAKEhunter2Event"
	agent, source := changeScan{StatusComplete, false, map[string]string{"a": StatusComplete}, []HookRecord{odd}}.agent()
	_, base := HookChanges(nil, agent, source)
	if e := base.Hooks["h1"].Event; e != HookEventOther {
		t.Fatalf("baseline event %q", e)
	}
}
