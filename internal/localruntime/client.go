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
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		return hook.Result{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hook.Result{}, err
	}

	req, err := EvaluateRequestFromEvent(event)
	if err != nil {
		return hook.Result{}, err
	}
	if err := WriteMessage(conn, req); err != nil {
		return hook.Result{}, err
	}

	var result EvaluateResult
	if err := ReadMessage(conn, &result); err != nil {
		return hook.Result{}, err
	}
	return ResultFromEvaluateResult(result), nil
}
