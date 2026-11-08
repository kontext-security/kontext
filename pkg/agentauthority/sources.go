package agentauthority

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"
)

// A source is one agent's asset family; each scan states an outcome for it.
const (
	StatusComplete = "complete"
	StatusPartial  = "partial"
	StatusFailed   = "failed"
)

// The closed reason list. Parser text and paths never appear in a reason.
const (
	ReasonPermissionDenied  = "permission_denied"
	ReasonMalformed         = "malformed"
	ReasonDeadline          = "deadline"
	ReasonWalkLimit         = "walk_limit"
	ReasonSizeLimit         = "size_limit"
	ReasonChangedDuringRead = "changed_during_read"
	ReasonUnsupportedFormat = "unsupported_format"
	ReasonReadError         = "read_error"
)

// HostCredentials is the source of credential files, which no agent owns.
const HostCredentials = "host/credentials"

const timeLayout = time.RFC3339Nano

var (
	errTooLarge          = fmt.Errorf("%w: file too large", os.ErrPermission)
	errDataless          = fmt.Errorf("%w: file content not on disk", os.ErrPermission)
	errUnsupportedFormat = errors.New("unsupported format")
)

// SourceResult is one source's outcome for one scan. Revision is assigned when
// the scan is recorded for upload.
type SourceResult struct {
	ID         string   `json:"id"`
	Revision   int64    `json:"revision"`
	Status     string   `json:"status"`
	Reasons    []string `json:"reasons"`
	StartedAt  string   `json:"started_at"`
	FinishedAt string   `json:"finished_at"`
}

// SourceHealth latches one source's failures for one scan: a later successful
// read cannot clear them.
type SourceHealth struct {
	id         string
	started    time.Time
	enumerated bool
	reasons    map[string]bool
}

func NewSourceHealth(id string, started time.Time) *SourceHealth {
	return &SourceHealth{id: id, started: started, reasons: map[string]bool{}}
}

// Read records one successful required read; a file that is absent counts.
func (h *SourceHealth) Read() { h.enumerated = true }

func (h *SourceHealth) Fail(reason string) { h.reasons[reason] = true }

// Result is complete only when no required read failed. Limits are partial by
// definition; the other reasons are failed when nothing could be enumerated.
func (h *SourceHealth) Result(finished time.Time) SourceResult {
	reasons := make([]string, 0, len(h.reasons))
	status := StatusComplete
	if len(h.reasons) > 0 {
		status = StatusFailed
		if h.enumerated {
			status = StatusPartial
		}
	}
	for reason := range h.reasons {
		reasons = append(reasons, reason)
		if reason == ReasonWalkLimit || reason == ReasonSizeLimit || reason == ReasonChangedDuringRead {
			status = StatusPartial
		}
	}
	slices.Sort(reasons)
	return SourceResult{ID: h.id, Status: status, Reasons: reasons, StartedAt: h.started.UTC().Format(timeLayout), FinishedAt: finished.UTC().Format(timeLayout)}
}

// ReasonFor names a failed read. A missing file is not a failure; callers
// decide that before asking.
func ReasonFor(err error) string {
	switch {
	case errors.Is(err, errTooLarge):
		return ReasonSizeLimit
	case errors.Is(err, errDataless), isEvictedErr(err):
		return ReasonReadError
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return ReasonDeadline
	case errors.Is(err, os.ErrPermission):
		return ReasonPermissionDenied
	default:
		return ReasonReadError
	}
}

// use makes these families the sources every following read counts for.
func (g *guard) use(agent string, families ...string) {
	now := time.Now()
	for _, h := range g.active {
		g.finished[h.id] = now
	}
	g.active = g.active[:0]
	if g.sources == nil {
		g.sources, g.finished = map[string]*SourceHealth{}, map[string]time.Time{}
	}
	for _, family := range families {
		id := agent + "/" + family
		h := g.sources[id]
		if h == nil {
			h = NewSourceHealth(id, now)
			g.sources[id] = h
			g.order = append(g.order, id)
		}
		g.active = append(g.active, h)
	}
}

func (g *guard) fail(reason string) {
	for _, h := range g.active {
		h.Fail(reason)
	}
}

func (g *guard) readOK() {
	for _, h := range g.active {
		h.Read()
	}
}

// noteAccess counts a finished access. Parsed reads count once parsing succeeds.
func (g *guard) noteAccess(err error, mode string) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		g.readOK()
	case err != nil:
		g.fail(ReasonFor(err))
	case mode != "read" && mode != "cursor":
		g.readOK()
	}
}

func (g *guard) noteParse(err error) {
	switch {
	case err == nil:
		g.readOK()
	case errors.Is(err, errUnsupportedFormat):
		g.fail(ReasonUnsupportedFormat)
	default:
		g.fail(ReasonMalformed)
	}
}

func (g *guard) results() []SourceResult {
	results := make([]SourceResult, 0, len(g.order))
	for _, id := range g.order {
		results = append(results, g.sources[id].Result(g.finished[id]))
	}
	return results
}

// failSources states that nothing in the report can be relied on.
func (r *Report) failSources(reason string) {
	for i := range r.Sources {
		r.Sources[i].Status = StatusFailed
		r.Sources[i].Reasons = []string{reason}
	}
}

func (r *Report) claimCounts() map[string]int {
	counts := map[string]int{HostCredentials: len(r.Credentials)}
	for _, a := range r.Agents {
		counts[a.ID+"/mcp"] = len(a.MCPServers)
		counts[a.ID+"/plugins"] = len(a.Plugins)
		counts[a.ID+"/connectors"] = len(a.Connectors)
		counts[a.ID+"/permissions"] = a.Permissions.claims()
	}
	return counts
}

// Seal applies the report's redaction and size bounds and returns the sources
// that lost claims to them.
func (r *Report) Seal() []string {
	before := r.claimCounts()
	r.finish()
	after := r.claimCounts()
	var trimmed []string
	for id, count := range before {
		if after[id] < count {
			trimmed = append(trimmed, id)
		}
	}
	slices.Sort(trimmed)
	return trimmed
}

func (p Permissions) observed() bool {
	return p.DefaultMode != nil || len(p.Allow) > 0 || p.DenyCount > 0 || p.Sandbox != (Sandbox{}) || p.Codex != nil
}

func (p Permissions) claims() int {
	count := len(p.Allow)
	for _, set := range []bool{p.DefaultMode != nil, p.DenyCount > 0, p.Sandbox != (Sandbox{}), p.Codex != nil} {
		if set {
			count++
		}
	}
	return count
}

func (a Agent) hasClaims() bool {
	return len(a.MCPServers) > 0 || len(a.Plugins) > 0 || len(a.Connectors) > 0 || a.Permissions.observed()
}
