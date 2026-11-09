package localruntime

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
)

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func NewClient(socketPath string) Client {
	return Client{SocketPath: socketPath, Timeout: 10 * time.Second}
}

func (c Client) Process(ctx context.Context, event hook.Event) (hook.Result, error) {
	req, err := EvaluateRequestFromEvent(event)
	if err != nil {
		return hook.Result{}, err
	}
	var result EvaluateResult
	if err := c.roundTrip(ctx, req, &result); err != nil {
		return hook.Result{}, err
	}
	return ResultFromEvaluateResult(result), nil
}

// ProcessHoldable is Process for a hook that can wait while a fresh daemon
// holds the call until its policy arrives. It declares HoldCapability. When
// the daemon answers with a hold frame first, the deadline moves to the end
// of the hold, at most maxHold away, plus the client's Timeout again for
// the decision itself. held reports whether a hold frame arrived, so the
// caller does not retry a call that already spent its hold. Cancelling ctx
// ends the call at once, so ctx must not carry the decision budget: that is
// Timeout, which a hold is meant to outlast.
func (c Client) ProcessHoldable(ctx context.Context, event hook.Event, maxHold time.Duration) (result hook.Result, held bool, err error) {
	req, err := EvaluateRequestFromEvent(event)
	if err != nil {
		return hook.Result{}, false, err
	}
	req.Capabilities = append(req.Capabilities, HoldCapability)
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return hook.Result{}, false, err
	}
	defer conn.Close()
	failed := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hook.Result{}, false, failed(err)
	}
	// A cancelled caller cuts the connection's deadline to now, which ends
	// any read, including one waiting through a hold. Registered only after
	// the first deadline is set, so that deadline can't overwrite a cancel;
	// a context already cancelled by now runs the cut at once.
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if err := WriteMessage(conn, req); err != nil {
		return hook.Result{}, false, failed(err)
	}
	var answer EvaluateResult
	if err := ReadMessage(conn, &answer); err != nil {
		return hook.Result{}, false, failed(err)
	}
	if answer.Type == HoldResultType {
		held = true
		hold := min(time.Duration(answer.HoldMs)*time.Millisecond, maxHold)
		hold = max(hold, 0)
		if err := conn.SetDeadline(time.Now().Add(hold + timeout)); err != nil {
			return hook.Result{}, held, failed(err)
		}
		// A cancel that landed before the new deadline was set would be lost.
		if err := ctx.Err(); err != nil {
			return hook.Result{}, held, err
		}
		answer = EvaluateResult{}
		if err := ReadMessage(conn, &answer); err != nil {
			return hook.Result{}, held, failed(err)
		}
		if answer.Type == HoldResultType {
			return hook.Result{}, held, errors.New("local runtime: a second hold frame")
		}
	}
	return ResultFromEvaluateResult(answer), held, nil
}

// CompactToolOutput asks the runtime to compact a PostToolUse event's tool
// output. A nil map leaves the output unchanged.
func (c Client) CompactToolOutput(ctx context.Context, event hook.Event) (map[string]any, error) {
	req, err := EvaluateRequestFromEvent(event)
	if err != nil {
		return nil, err
	}
	req.Type = CompactRequestType
	var result CompactResult
	if err := c.roundTrip(ctx, req, &result); err != nil {
		return nil, err
	}
	return rawMap(result.UpdatedToolOutput)
}

// CodexProxy sends the Codex proxy's question about a model request and
// returns the daemon's answer, nil when it has none. The context's deadline
// bounds the whole exchange, not only the dial.
func (c Client) CodexProxy(ctx context.Context, question json.RawMessage) (json.RawMessage, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if at, ok := ctx.Deadline(); ok && at.Before(deadline) {
		deadline = at
	}
	dialer := net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := WriteMessage(conn, EvaluateRequest{Type: CodexProxyRequestType, CodexProxy: question}); err != nil {
		return nil, err
	}
	var result CodexProxyResult
	if err := ReadMessage(conn, &result); err != nil {
		return nil, err
	}
	return result.Answer, nil
}

func (c Client) roundTrip(ctx context.Context, req EvaluateRequest, result any) error {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := WriteMessage(conn, req); err != nil {
		return err
	}
	return ReadMessage(conn, result)
}
