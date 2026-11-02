package codexproxy

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/internal/modelusage"
)

// DecideBudget bounds the daemon's work on one request's parts. The proxy
// waits a little longer, for the answer to arrive, before it sends the
// request on with the parts it has.
const DecideBudget = 1500 * time.Millisecond

// DecideWait is how long the proxy waits for the daemon's decisions.
const DecideWait = DecideBudget + 250*time.Millisecond

// maxQuestionBytes keeps a question well within the daemon's 10 MiB frames;
// the oldest context goes first.
const maxQuestionBytes = 8 << 20

// Decider decides the new printed parts of a model request. The daemon
// answers it over its socket; every error keeps the parts as they are.
type Decider interface {
	Decide(ctx context.Context, request DecideRequest) (DecideResponse, error)
}

// DecideRequest asks about the new printed parts of one model request. One
// without parts only tells the daemon the proxy carries the session, so the
// hook path leaves the session's code mode outputs alone.
type DecideRequest struct {
	// SessionID and ThreadID are the ids Codex sent with the request.
	SessionID string `json:"sessionId"`
	ThreadID  string `json:"threadId,omitempty"`
	Model     string `json:"model,omitempty"`
	CWD       string `json:"cwd,omitempty"`
	// Messages is the request's input as the model sees it, from Start on.
	Messages []Message `json:"messages,omitempty"`
	Start    int       `json:"start,omitempty"`
	Parts    []Part    `json:"parts,omitempty"`
	// Deadline is when the proxy stops waiting: an answer after it would
	// never reach the model, so the daemon gives up before.
	Deadline time.Time `json:"deadline,omitzero"`
}

// Part is a printed part of a code mode result, as the model would read it:
// a printed exec_command result is its "output" field alone.
type Part struct {
	CallID   string `json:"callId"`
	Part     int    `json:"part"`
	ToolName string `json:"toolName"`
	// ToolInput is the script as the model wrote it.
	ToolInput string `json:"toolInput"`
	Text      string `json:"text"`
}

// DecideResponse answers the parts in order: the text the model should see
// instead, or null to keep the part.
type DecideResponse struct {
	Texts []*string `json:"texts"`
}

// SocketDecider asks the daemon over its socket.
type SocketDecider struct {
	Client localruntime.Client
}

func (d SocketDecider) Decide(ctx context.Context, request DecideRequest) (DecideResponse, error) {
	question, err := json.Marshal(request)
	for err == nil && len(question) > maxQuestionBytes && len(request.Messages) > 0 {
		request.Messages, request.Start = request.Messages[len(request.Messages)/2:], request.Start+len(request.Messages)/2
		if len(request.Messages) == 1 {
			request.Messages, request.Start = nil, request.Start+1
		}
		question, err = json.Marshal(request)
	}
	if err != nil {
		return DecideResponse{}, err
	}
	if len(question) > maxQuestionBytes {
		return DecideResponse{}, errors.New("codex proxy: parts too large to ask about")
	}
	answer, err := d.Client.CodexProxy(ctx, question)
	if err != nil || len(answer) == 0 {
		return DecideResponse{}, err
	}
	var response DecideResponse
	err = json.Unmarshal(answer, &response)
	return response, err
}

// Message is a modelusage.Message on the wire.
type Message struct {
	Role      string          `json:"role"`
	Text      string          `json:"text,omitempty"`
	CallID    string          `json:"callId,omitempty"`
	CallName  string          `json:"callName,omitempty"`
	CallInput json.RawMessage `json:"callInput,omitempty"`
	ToolUseID string          `json:"toolUseId,omitempty"`
	Response  string          `json:"response,omitempty"`
	Prompt    bool            `json:"prompt,omitempty"`
}

// wireMessages puts messages on the wire with each call's input as the
// string the model wrote: a function call's arguments too, unparsed.
func wireMessages(messages []modelusage.Message) []Message {
	wire := make([]Message, len(messages))
	for i, message := range messages {
		wire[i] = Message{Role: message.Role, Text: message.Text, ToolUseID: message.ToolUseID, Response: message.Response, Prompt: message.Prompt}
		if call := message.ToolCall; call != nil {
			input := call.Input
			var text string
			if json.Unmarshal(input, &text) != nil {
				input, _ = json.Marshal(string(call.Input))
			}
			wire[i].CallID, wire[i].CallName, wire[i].CallInput = call.ID, call.Name, input
		}
	}
	return wire
}

// Conversation is the request's messages as modelusage reads them.
func (r DecideRequest) Conversation() modelusage.Conversation {
	messages := make([]modelusage.Message, len(r.Messages))
	for i, message := range r.Messages {
		messages[i] = modelusage.Message{Role: message.Role, Text: message.Text, ToolUseID: message.ToolUseID, Response: message.Response, Prompt: message.Prompt}
		if message.CallID != "" {
			messages[i].ToolCall = &modelusage.ToolCall{ID: message.CallID, Name: message.CallName, Input: message.CallInput}
		}
	}
	return modelusage.Conversation{Messages: messages, Model: r.Model}
}
