package modelusage

import (
	"slices"
	"sort"
	"time"
)

// Prompt is where one of a transcript's turns begins: a prompt the agent
// received from its user, or one the harness submitted on the user's behalf
// (a queued prompt, a background task notification). Only the session and the
// time are kept, never the text.
type Prompt struct {
	SessionID string
	Timestamp time.Time
}

// Turn is a turn the daemon minted when a prompt hook reached it.
type Turn struct {
	ID        string
	StartedAt time.Time
}

// PromptHookSkew is how far before its transcript line a prompt hook may be
// received and still belong to it. Both clocks are the same machine's; a
// Claude prompt line is written within a few hundred milliseconds of its hook
// in either order, and Codex records task_started before the hook fires.
const PromptHookSkew = time.Second

// AssignTurns sets each record's TurnID from the minted turns of one session.
// The prompts partition time: prompt k owns minted turns started within
// [t_k - PromptHookSkew, t_k+1 - PromptHookSkew) and takes the earliest of
// them, so a minted turn never moves back to an earlier prompt whose own hook
// was missed. A record belongs to the last prompt at or before its timestamp
// and carries that prompt's turn; a record before the first prompt, or in a
// turn no hook was minted for (hook not installed, daemon down, session
// resumed from before the install), carries none rather than inheriting the
// previous label.
func AssignTurns(records []Record, prompts []time.Time, turns []Turn) {
	prompts = slices.Clone(prompts)
	slices.SortFunc(prompts, func(a, b time.Time) int { return a.Compare(b) })
	prompts = slices.CompactFunc(prompts, time.Time.Equal)
	turns = slices.Clone(turns)
	slices.SortStableFunc(turns, func(a, b Turn) int { return a.StartedAt.Compare(b.StartedAt) })
	matched := make([]string, len(prompts))
	for k, start := range prompts {
		from := start.Add(-PromptHookSkew)
		i := sort.Search(len(turns), func(i int) bool { return !turns[i].StartedAt.Before(from) })
		if i == len(turns) {
			continue
		}
		if k+1 < len(prompts) && !turns[i].StartedAt.Before(prompts[k+1].Add(-PromptHookSkew)) {
			continue
		}
		matched[k] = turns[i].ID
	}
	for i := range records {
		records[i].TurnID = ""
		at, err := time.Parse(time.RFC3339Nano, records[i].Timestamp)
		if err != nil {
			continue
		}
		// The last prompt at or before the record.
		k := sort.Search(len(prompts), func(k int) bool { return prompts[k].After(at) }) - 1
		if k >= 0 {
			records[i].TurnID = matched[k]
		}
	}
}
