package agentauthority

import (
	"slices"
	"strings"
)

// Hook change kinds: what one scan established against the scan before it.
const (
	HookChangeAdded       = "added"
	HookChangeChanged     = "changed"
	HookChangeRemoved     = "removed"
	HookChangeCheckFailed = "check_failed"
)

// HookChange is one transition between two scans of an agent's hooks. Hook
// changes name the hook, check failures the scope; neither carries content.
type HookChange struct {
	Kind    string   `json:"kind"`
	HookID  string   `json:"hook_id,omitempty"`
	ScopeID string   `json:"scope_id"`
	Event   string   `json:"event,omitempty"`
	Reasons []string `json:"reasons,omitempty"`
	At      string   `json:"at"`
}

// HookBaseline is what change detection keeps of the last scan: each hook's
// scope, event, content and enablement, and each scope's status. It holds
// opaque ids and fingerprints only.
type HookBaseline struct {
	Hooks  map[string]HookBaselineEntry `json:"hooks"`
	Scopes map[string]string            `json:"scopes"`
}

type HookBaselineEntry struct {
	ScopeID   string `json:"scope_id"`
	Event     string `json:"event"`
	ContentFP string `json:"content_fp"`
	State     string `json:"state"`
}

// HookChanges compares a scan with the baseline left by the scans before it
// and returns the transitions and the next baseline. It follows the cloud's
// withdrawal rule (ADR-0011): a hook is removed only when its scope was read
// completely without it, or when the scope is gone from a complete,
// untruncated scan. A scope that can't be read keeps its hooks in the
// baseline, so recovering it reports only what changed meanwhile.
//
// Changes are deduplicated: a scope that stays unreadable is reported once,
// when it stops reading, and a hook is reported only when its content or
// enablement state moves. A nil baseline is the first scan, which sets the
// baseline and reports nothing.
func HookChanges(base *HookBaseline, agent HookAgent, source SourceResult) ([]HookChange, HookBaseline) {
	next := HookBaseline{Hooks: map[string]HookBaselineEntry{}, Scopes: map[string]string{}}
	if source.Status == StatusFailed {
		// A failed scan establishes nothing.
		if base != nil {
			next = cloneBaseline(*base)
		}
		return nil, next
	}
	at := source.FinishedAt
	listed := make(map[string]HookScope, len(agent.Scopes))
	for _, scope := range agent.Scopes {
		listed[scope.ID] = scope
	}
	authoritative := source.Status == StatusComplete && !agent.Truncated
	reported := make(map[string]bool, len(agent.Hooks))
	for _, r := range agent.Hooks {
		reported[r.ID] = true
		next.Hooks[r.ID] = HookBaselineEntry{ScopeID: r.ScopeID, Event: r.Event, ContentFP: r.ContentFP, State: r.Enablement.State}
	}
	for _, scope := range agent.Scopes {
		next.Scopes[scope.ID] = scope.Status
	}
	if base == nil {
		return nil, next
	}

	var changes []HookChange
	for _, scope := range agent.Scopes {
		// A scope reports a failed check when it stops reading completely,
		// or first appears unreadable; never again while it stays so.
		if scope.Status == StatusComplete {
			continue
		}
		if before, seen := base.Scopes[scope.ID]; !seen || before == StatusComplete {
			changes = append(changes, HookChange{Kind: HookChangeCheckFailed, ScopeID: scope.ID, Reasons: slices.Clone(scope.Reasons), At: at})
		}
	}
	for _, r := range agent.Hooks {
		before, seen := base.Hooks[r.ID]
		switch {
		case !seen:
			changes = append(changes, HookChange{Kind: HookChangeAdded, HookID: r.ID, ScopeID: r.ScopeID, Event: r.Event, At: at})
		case before.ContentFP != r.ContentFP || before.State != r.Enablement.State:
			changes = append(changes, HookChange{Kind: HookChangeChanged, HookID: r.ID, ScopeID: r.ScopeID, Event: r.Event, At: at})
		}
	}
	for id, before := range base.Hooks {
		if reported[id] {
			continue
		}
		scope, ok := listed[before.ScopeID]
		withdrawn := ok && scope.Status == StatusComplete || !ok && authoritative
		if withdrawn {
			changes = append(changes, HookChange{Kind: HookChangeRemoved, HookID: id, ScopeID: before.ScopeID, Event: before.Event, At: at})
			continue
		}
		// Not established gone: kept until its scope is read again.
		next.Hooks[id] = before
	}
	for id, status := range base.Scopes {
		if _, ok := listed[id]; !ok && !authoritative {
			next.Scopes[id] = status
		}
	}
	slices.SortStableFunc(changes, func(a, b HookChange) int {
		if c := strings.Compare(changeRank(a.Kind), changeRank(b.Kind)); c != 0 {
			return c
		}
		if c := strings.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return strings.Compare(a.HookID, b.HookID)
	})
	return changes, next
}

// changeRank orders a scan's changes: check failures first, since they say
// what the rest can't cover, then removals, changes and additions.
func changeRank(kind string) string {
	switch kind {
	case HookChangeCheckFailed:
		return "0"
	case HookChangeRemoved:
		return "1"
	case HookChangeChanged:
		return "2"
	}
	return "3"
}

func cloneBaseline(b HookBaseline) HookBaseline {
	out := HookBaseline{Hooks: make(map[string]HookBaselineEntry, len(b.Hooks)), Scopes: make(map[string]string, len(b.Scopes))}
	for k, v := range b.Hooks {
		out.Hooks[k] = v
	}
	for k, v := range b.Scopes {
		out.Scopes[k] = v
	}
	return out
}
