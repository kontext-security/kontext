package agentauthority

import (
	"maps"
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

// maxBaselineHooks and maxBaselineScopes bound what a baseline keeps. Past
// them, entries carried over from scopes this scan couldn't read go first;
// a hook dropped that way is reported as added if it comes back.
const (
	maxBaselineHooks  = 4096
	maxBaselineScopes = 1024
)

// HookEventOther stands for an event name change detection doesn't know. A
// change record is logged and kept on disk, so it carries a known name or
// this, never a string read from a settings file.
const HookEventOther = "other"

// knownHookEvents are the Claude Code hook events a change may name.
var knownHookEvents = map[string]bool{
	"PreToolUse": true, "PostToolUse": true, "PostToolUseFailure": true,
	"PermissionRequest": true, "PermissionDenied": true, "UserPromptSubmit": true,
	"Notification": true, "Stop": true, "StopFailure": true,
	"SubagentStart": true, "SubagentStop": true, "SessionStart": true,
	"SessionEnd": true, "PreCompact": true, "PostCompact": true,
	"TeammateIdle": true, "TaskCompleted": true, "TaskCreated": true,
	"ConfigChange": true, "InstructionsLoaded": true, "WorktreeCreate": true,
	"WorktreeRemove": true, "Elicitation": true, "ElicitationResult": true,
	"Setup": true, "CwdChanged": true, "FileChanged": true,
}

func changeEvent(event string) string {
	if knownHookEvents[event] {
		return event
	}
	return HookEventOther
}

// HookBaseline is what change detection keeps of the last scan: each hook's
// scope, event, content and enablement, and each scope's status. It holds
// opaque ids and fingerprints only.
type HookBaseline struct {
	Hooks  map[string]HookBaselineEntry `json:"hooks"`
	Scopes map[string]string            `json:"scopes"`
	// Source is the source's status when no listed scope explained an
	// incomplete scan, such as an unreadable plugin registry.
	Source string `json:"source,omitempty"`
}

// HookChangeSourceScope is the scope a check failure names when the source
// itself couldn't be read in full and no scope it lists says why.
const HookChangeSourceScope = "source"

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
// baseline and reports nothing; a nil result means no baseline yet.
func HookChanges(base *HookBaseline, agent HookAgent, source SourceResult) ([]HookChange, *HookBaseline) {
	at := source.FinishedAt
	if source.Status == StatusFailed {
		// A failed scan establishes no hook. Before any baseline it sets
		// none, so the first readable scan still reports nothing.
		if base == nil {
			return nil, nil
		}
		next := cloneBaseline(*base)
		// Scopes it names as unreadable are still reported, once.
		changes := checkFailures(base, agent.Scopes, at)
		listed := map[string]HookScope{}
		for _, scope := range agent.Scopes {
			listed[scope.ID] = scope
			if scope.Status != StatusComplete {
				next.Scopes[scope.ID] = scope.Status
			}
		}
		changes = append(changes, sourceFailure(base, &next, agent, source)...)
		boundBaseline(&next, nil, listed)
		sortChanges(changes)
		return changes, &next
	}
	next := HookBaseline{Hooks: map[string]HookBaselineEntry{}, Scopes: map[string]string{}}
	listed := make(map[string]HookScope, len(agent.Scopes))
	for _, scope := range agent.Scopes {
		listed[scope.ID] = scope
	}
	authoritative := source.Status == StatusComplete && !agent.Truncated
	reported := make(map[string]bool, len(agent.Hooks))
	for _, r := range agent.Hooks {
		reported[r.ID] = true
		// Only a known event name is kept on disk.
		next.Hooks[r.ID] = HookBaselineEntry{ScopeID: r.ScopeID, Event: changeEvent(r.Event), ContentFP: r.ContentFP, State: r.Enablement.State}
	}
	for _, scope := range agent.Scopes {
		next.Scopes[scope.ID] = scope.Status
	}
	if base == nil {
		sourceFailure(nil, &next, agent, source)
		boundBaseline(&next, reported, listed)
		return nil, &next
	}

	changes := checkFailures(base, agent.Scopes, at)
	changes = append(changes, sourceFailure(base, &next, agent, source)...)
	for _, r := range agent.Hooks {
		before, seen := base.Hooks[r.ID]
		switch {
		case !seen:
			changes = append(changes, HookChange{Kind: HookChangeAdded, HookID: r.ID, ScopeID: r.ScopeID, Event: changeEvent(r.Event), At: at})
		case before.ContentFP != r.ContentFP || before.State != r.Enablement.State:
			changes = append(changes, HookChange{Kind: HookChangeChanged, HookID: r.ID, ScopeID: r.ScopeID, Event: changeEvent(r.Event), At: at})
		}
	}
	for id, before := range base.Hooks {
		if reported[id] {
			continue
		}
		scope, ok := listed[before.ScopeID]
		withdrawn := ok && scope.Status == StatusComplete || !ok && authoritative
		if withdrawn {
			changes = append(changes, HookChange{Kind: HookChangeRemoved, HookID: id, ScopeID: before.ScopeID, Event: changeEvent(before.Event), At: at})
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
	boundBaseline(&next, reported, listed)
	sortChanges(changes)
	return changes, &next
}

// checkFailures reports each scope that stops reading completely, or first
// appears unreadable; never again while it stays so.
func checkFailures(base *HookBaseline, scopes []HookScope, at string) []HookChange {
	var changes []HookChange
	for _, scope := range scopes {
		if scope.Status == StatusComplete {
			continue
		}
		if before, seen := base.Scopes[scope.ID]; !seen || before == StatusComplete {
			changes = append(changes, HookChange{Kind: HookChangeCheckFailed, ScopeID: scope.ID, Reasons: slices.Clone(scope.Reasons), At: at})
		}
	}
	return changes
}

// sourceFailure reports a scan that couldn't read the whole source when no
// scope it lists says why, such as an unreadable plugin registry: otherwise
// the hooks it lost sight of would vanish from view without a word. It is
// reported once per outage, and sets next.Source.
func sourceFailure(base, next *HookBaseline, agent HookAgent, source SourceResult) []HookChange {
	explained := slices.ContainsFunc(agent.Scopes, func(scope HookScope) bool { return scope.Status != StatusComplete })
	if source.Status == StatusComplete || explained {
		next.Source = ""
		return nil
	}
	next.Source = source.Status
	if base == nil || base.Source != "" {
		return nil
	}
	return []HookChange{{Kind: HookChangeCheckFailed, ScopeID: HookChangeSourceScope, Reasons: slices.Clone(source.Reasons), At: source.FinishedAt}}
}

// boundBaseline drops carried-over entries, those this scan didn't report
// or list, past the bounds, in id order so the result is the same each time.
// What this scan read itself is already bounded by the scan.
func boundBaseline(b *HookBaseline, reported map[string]bool, listed map[string]HookScope) {
	if extra := len(b.Hooks) - maxBaselineHooks; extra > 0 {
		for _, id := range slices.Sorted(maps.Keys(b.Hooks)) {
			if extra == 0 {
				break
			}
			if !reported[id] {
				delete(b.Hooks, id)
				extra--
			}
		}
	}
	if extra := len(b.Scopes) - maxBaselineScopes; extra > 0 {
		for _, id := range slices.Sorted(maps.Keys(b.Scopes)) {
			if extra == 0 {
				break
			}
			if _, ok := listed[id]; !ok {
				delete(b.Scopes, id)
				extra--
			}
		}
	}
}

func sortChanges(changes []HookChange) {
	slices.SortStableFunc(changes, func(a, b HookChange) int {
		if c := strings.Compare(changeRank(a.Kind), changeRank(b.Kind)); c != 0 {
			return c
		}
		if c := strings.Compare(a.ScopeID, b.ScopeID); c != 0 {
			return c
		}
		return strings.Compare(a.HookID, b.HookID)
	})
}

// CloneHookChanges copies changes and their reasons.
func CloneHookChanges(changes []HookChange) []HookChange {
	out := slices.Clone(changes)
	for i := range out {
		out[i].Reasons = slices.Clone(out[i].Reasons)
	}
	return out
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
	out := HookBaseline{Hooks: make(map[string]HookBaselineEntry, len(b.Hooks)), Scopes: make(map[string]string, len(b.Scopes)), Source: b.Source}
	for k, v := range b.Hooks {
		out.Hooks[k] = v
	}
	for k, v := range b.Scopes {
		out.Scopes[k] = v
	}
	return out
}
