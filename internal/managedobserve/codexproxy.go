package managedobserve

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/hookruntime"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

// codexRouting follows the endpoint's switches with the Codex route, away
// from the refresher: while a confirmed configuration has both tool output
// compaction and the Codex proxy on, Codex's model traffic goes through the
// proxy; once one has either off, the route goes, and the proxy job after it,
// once Codex has drained. An unconfirmed configuration changes nothing, so an
// unreachable API never churns the person's Codex config. Where the route
// stands goes to the Kontext API (see codexReports).
type codexRouting struct {
	router     *codexroute.Router
	diagnostic diagnostic.Logger
	// switched carries why the latest confirmed configuration has the route
	// off, or "" when it has it on; only the latest counts.
	switched chan string
	reports  *codexReports
}

// newCodexRouting returns the daemon's Codex routing, which reports with
// send, or nil (which does nothing) for a daemon whose home is not a
// person's.
func newCodexRouting(dbPath, socketPath string, diag diagnostic.Logger, send func(context.Context, codexReport) error) *codexRouting {
	home, err := os.UserHomeDir()
	if err != nil || os.Getuid() == 0 {
		return nil
	}
	// The proxy job runs a copy of this very binary, made from the file as it
	// is now: by the time it is made, an update or a downgrade may have put
	// another build at the path.
	var binary *os.File
	if runtime.GOOS == "darwin" {
		executable, err := os.Executable()
		if err != nil {
			return nil
		}
		if binary, err = os.Open(executable); err != nil {
			return nil
		}
	}
	router := codexroute.New(codexroute.Options{Home: home, Binary: binary, StateDir: codexroute.StateDir(dbPath), Socket: socketPath})
	return &codexRouting{
		router:     router,
		diagnostic: diag,
		switched:   make(chan string, 1),
		reports:    &codexReports{send: send, route: router, diagnostic: diag, now: time.Now},
	}
}

func (c *codexRouting) follow(snapshot endpointconfig.Snapshot) {
	if c == nil || !snapshot.Confirmed {
		return
	}
	// With both switches off, compaction's is the reason: the Codex proxy
	// has no use without it.
	off := ""
	switch {
	case !snapshot.Config.ToolOutputCompactionEnabled():
		off = codexroute.ReasonCompactionOff
	case !snapshot.Config.CodexProxyEnabled():
		off = codexroute.ReasonCodexProxyOff
	}
	select {
	case <-c.switched:
	default:
	}
	c.switched <- off
}

func (c *codexRouting) run(ctx context.Context) {
	if c == nil {
		return
	}
	// This daemon holds a route it finds from the start, its configuration
	// confirmed or not: without renewals, the proxy job takes the route away.
	// Where the route stands goes to the log whatever the debug setting,
	// since routing edits ~/.codex/config.toml: once at the start, and at
	// each change.
	last, lastRenewal := "", ""
	renew := func() {
		failure := ""
		if err := c.router.Renew(ctx); err != nil {
			failure = err.Error()
		}
		if failure != "" && failure != lastRenewal {
			diagnostic.LogAlways(c.diagnostic, "codex proxy: route not renewed: %s\n", failure)
		}
		lastRenewal = failure
	}
	renew()
	ticker := time.NewTicker(codexroute.LeaseRenewal)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case off := <-c.switched:
			now, state := c.apply(ctx, off)
			if now != last {
				diagnostic.LogAlways(c.diagnostic, "codex proxy: %s\n", now)
				last = now
			}
			c.reports.update(ctx, state)
		case <-ticker.C:
			renew()
			c.reports.tick(ctx)
		}
	}
}

// apply routes Codex, or unroutes it for off, drains the job when Codex is
// not routed to it, and describes where that left it: for the log, and as
// the state to report. After a failure, that is where Codex goes: a failed
// Enable or Disable may leave the line in place.
func (c *codexRouting) apply(ctx context.Context, off string) (string, routeState) {
	var result string
	var state routeState
	if off == "" {
		status, err := c.router.Enable(ctx)
		if err != nil && !status.Routed {
			status.Port, status.Routed = c.router.InPlace()
		}
		if status.Routed {
			if err != nil {
				return fmt.Sprintf("routed through 127.0.0.1:%d, but %v", status.Port, err), routeState{state: codexRouted}
			}
			return fmt.Sprintf("routed through 127.0.0.1:%d", status.Port), routeState{state: codexRouted}
		}
		state = routeState{codexNotRouted, status.Reason}
		if err != nil {
			result = fmt.Sprintf("not routed: %v", err)
		} else {
			result = "not routed: " + status.Skipped
		}
	} else {
		state = routeState{codexNotRouted, off}
		if err := c.router.Disable(ctx); err != nil {
			result = fmt.Sprintf("route not removed: %v", err)
			if _, inPlace := c.router.InPlace(); inPlace {
				return result, routeState{state: codexRouted}
			}
		} else {
			result = "not routed: switch off (" + off + ")"
		}
	}
	if drained, err := c.router.Drain(ctx); err != nil {
		result += fmt.Sprintf("; drain: %v", err)
	} else if !drained {
		result += "; job kept for running Codex sessions"
	}
	return result, state
}

// decideSlack is how long before the proxy's deadline the daemon stops, for
// the answer to travel back.
const decideSlack = 150 * time.Millisecond

// codexProxyAnswer answers the Codex proxy's questions about the model
// requests it carries: it decides each new printed part, all at once, within
// the budget the proxy waits for.
func codexProxyAnswer(compactor *tooloutput.Compactor) func(context.Context, json.RawMessage) json.RawMessage {
	return func(ctx context.Context, question json.RawMessage) json.RawMessage {
		var request codexproxy.DecideRequest
		if json.Unmarshal(question, &request) != nil {
			return nil
		}
		// Hooks name a Codex session by its root thread, prefixed; the proxy
		// sees the session and the thread, which differ for a subagent.
		session, thread := hookruntime.CodexSessionID(request.SessionID), hookruntime.CodexSessionID(request.ThreadID)
		if session == "" {
			session = thread
		}
		if session == "" {
			return nil
		}
		response := codexproxy.DecideResponse{Texts: make([]*string, len(request.Parts))}
		// Give up before the proxy stops waiting: a later answer would be
		// counted for a part the model never saw shortened.
		budget := codexproxy.DecideBudget
		if !request.Deadline.IsZero() {
			budget = min(budget, time.Until(request.Deadline)-decideSlack)
		}
		if len(request.Parts) > 0 && budget > 0 {
			ctx, cancel := context.WithTimeout(ctx, budget)
			defer cancel()
			conversation := request.Conversation()
			var wg sync.WaitGroup
			for i, part := range request.Parts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					text, ok := compactor.CompactProxied(ctx, tooloutput.ProxyOutput{
						SessionID: session, CallID: part.CallID, Part: part.Part, ToolName: part.ToolName, ToolInput: part.ToolInput,
						Model: request.Model, CWD: request.CWD, Text: part.Text, Conversation: conversation, Whole: request.Start == 0,
					})
					if ok {
						response.Texts[i] = &text
					}
				}()
			}
			wg.Wait()
		}
		answer, err := json.Marshal(response)
		if err != nil {
			return nil
		}
		return answer
	}
}
