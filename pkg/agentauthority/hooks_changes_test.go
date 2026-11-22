package agentauthority

import (
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
		{"a failed source establishes nothing", changeScan{StatusFailed, false, map[string]string{}, nil}, []string{}},
		{"a recovered scope reports only what changed meanwhile", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("a", "h1", "f9", hookEnabled), hookIn("b", "h2", "f2", hookDisabled)}}, []string{"removed:h3"}},
		{"a hook gone from a complete scope is removed", changeScan{complete, false, map[string]string{"a": complete, "b": complete}, []HookRecord{hookIn("b", "h2", "f2", hookDisabled)}}, []string{"removed:h1"}},
		{"a truncated scan withdraws no unlisted scope", changeScan{StatusPartial, true, map[string]string{"a": complete}, nil}, []string{}},
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
		base = &next
	}
}

// A change made between two scans shows on the next scan, so within two
// poll cycles of the edit.
func TestHookChangeShowsOnTheNextScan(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	agent, source := h.scan()
	_, base := HookChanges(nil, agent, source)

	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"Stop":         hooksOf("Stop", "", command("echo stop"))["Stop"],
		"SessionStart": hooksOf("SessionStart", "", command("echo hello"))["SessionStart"],
	}})
	agent, source = h.scan()
	changes, base := HookChanges(&base, agent, source)
	if len(changes) != 1 || changes[0].Kind != HookChangeAdded || changes[0].Event != "SessionStart" {
		t.Fatalf("%+v", changes)
	}

	// Unparsed settings fail the scope's check and keep its hooks.
	h.write(filepath.Join(h.base, "settings.json"), []byte(`{"hooks": [`))
	agent, source = h.scan()
	changes, base = HookChanges(&base, agent, source)
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
	changes, _ = HookChanges(&base, agent, source)
	if got := changeKinds(changes); len(got) != 2 || changes[0].Kind != HookChangeRemoved || changes[1].Kind != HookChangeRemoved {
		t.Fatalf("%+v", changes)
	}
}
