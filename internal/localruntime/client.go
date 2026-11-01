package localruntime

import (
	"context"
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
