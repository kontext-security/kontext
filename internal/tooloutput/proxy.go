package tooloutput

import (
	"context"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/modelusage"
)

// ProxyOutput is a printed part of a Codex code mode result that the Codex
// proxy found in a model request, with what the request shows around it.
type ProxyOutput struct {
	SessionID string
	// CallID is the code mode call's id, and Part the index of the printed
	// part in its result (the first, Codex's own summary, is never one).
	CallID   string
	Part     int
	ToolName string
	// ToolInput is the string the model wrote for the call: the script.
	ToolInput string
	Model     string
	// CWD resolves relative paths in the call's input.
	CWD  string
	Text string
	// Conversation is the request's input up to and including the result,
	// and Whole reports that it starts where the request's input does.
	Conversation modelusage.Conversation
	Whole        bool
}

// CompactProxied decides a printed part for the proxy: it returns the text
// the model should see instead, or false to leave the part as it is. A part is
// decided once, and asking again gets the same answer. As on the hook path,
// the switch must be on, the part over 2048 bytes and the call must not read
// saved outputs back; every failure keeps the part. The full part is saved
// where the agent can read it back, before the model is told where.
func (c *Compactor) CompactProxied(ctx context.Context, out ProxyOutput) (string, bool) {
	name := proxyName(out.CallID, out.Part)
	if !c.on() || out.Part < 1 || len(out.Text) <= minOutputBytes || !safeSegment(out.SessionID) || !safeSegment(name) {
		return "", false
	}
	c.mu.Lock()
	state := c.session(out.SessionID)
	decided, seen := state.decided[name]
	if !seen {
		// Taken up: an ask while this one runs keeps the part.
		state.decided[name] = nil
	}
	c.mu.Unlock()
	if seen {
		if decided == nil {
			return "", false
		}
		return *decided, true
	}
	if c.namesSaveDir(out.ToolInput, out.CWD) {
		return "", false
	}
	select {
	case c.live <- struct{}{}:
		defer func() { <-c.live }()
	default:
		c.diagnostic.Printf("tool output compaction: too many calls in flight; output left as is\n")
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, apiWait)
	defer cancel()

	saved := filepath.Join(c.dir, out.SessionID, name+".txt")
	body, fits := encode(c.proxyRequest(out, saved))
	if !fits {
		return "", false
	}
	response, err := c.client.Compact(ctx, body)
	if err != nil {
		c.diagnostic.Printf("%v; output left as is\n", err)
		return "", false
	}
	part := output{kind: KindText, text: out.Text}
	if response.Decision != DecisionReplace || !part.acceptable(*response.Text) {
		return "", false
	}
	if err := writePrivate(c.dir, saved, []byte(out.Text)); err != nil {
		c.diagnostic.Printf("tool output compaction: %v; output left as is\n", err)
		return "", false
	}
	c.remember(out.SessionID, record{EventID: response.EventID, ToolUseID: out.CallID, Part: out.Part, Kind: KindText, At: c.now()})
	text := *response.Text
	c.mu.Lock()
	c.session(out.SessionID).decided[name] = &text
	c.mu.Unlock()
	return text, true
}

func (c *Compactor) proxyRequest(out ProxyOutput, saved string) Request {
	withheld := func(input any) bool { return c.namesSaveDir(input, out.CWD) }
	// The request's input is what the model sees, so its latest prompt beats
	// the one the hooks last reported.
	goal := proxyGoal(out.Conversation.Messages)
	if goal == "" {
		goal = c.goal(out.SessionID)
	}
	var model *string
	if out.Model != "" {
		model = &out.Model
	}
	return Request{
		Mode:      ModeLive,
		Agent:     "codex",
		SessionID: out.SessionID,
		ToolUseID: out.CallID,
		ToolName:  out.ToolName,
		ToolInput: out.ToolInput,
		Model:     model,
		Output:    Output{Kind: KindText, Text: out.Text, RecoveryPath: saved},
		Context:   conversationContext(out.Conversation, out.Whole, goal, out.CallID, out.ToolName, out.ToolInput, withheld),
		Delivery:  DeliveryProxy,
		Part:      out.Part,
	}
}

// codexInjected open the user messages Codex writes itself, besides those
// modelusage already leaves out: instructions, and the note an interrupted
// turn leaves.
var codexInjected = []string{"<user_instructions>", "# AGENTS.md instructions", "<turn_aborted>"}

// proxyGoal is the latest user message that is not one Codex injected.
func proxyGoal(messages []modelusage.Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		text := strings.TrimLeft(messages[i].Text, " \t\r\n")
		if messages[i].Role == "user" && !slices.ContainsFunc(codexInjected, func(prefix string) bool { return strings.HasPrefix(text, prefix) }) {
			return messages[i].Text
		}
	}
	return ""
}

// name is what the record and its output are saved as: the call's id, with
// the part's index after it for a printed part the proxy changed.
func (r record) name() string {
	if r.Part == 0 {
		return r.ToolUseID
	}
	return proxyName(r.ToolUseID, r.Part)
}

func proxyName(callID string, part int) string {
	return callID + "-" + strconv.Itoa(part)
}
