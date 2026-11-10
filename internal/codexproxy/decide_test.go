package codexproxy

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/localruntime"
)

// fakeDaemon serves the daemon's socket framing and answers each question
// with answer, or never answers when answer is nil.
func fakeDaemon(t *testing.T, answer func(DecideRequest) DecideResponse) string {
	t.Helper()
	socket := filepath.Join(hermetic.SocketDir(t), "kontext.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var request localruntime.EvaluateRequest
				if err := localruntime.ReadMessage(conn, &request); err != nil || request.Type != localruntime.CodexProxyRequestType {
					t.Errorf("request %+v, %v", request, err)
					return
				}
				var question DecideRequest
				if err := json.Unmarshal(request.CodexProxy, &question); err != nil {
					t.Errorf("question: %v", err)
					return
				}
				if answer == nil {
					time.Sleep(time.Second)
					return
				}
				data, _ := json.Marshal(answer(question))
				_ = localruntime.WriteMessage(conn, localruntime.CodexProxyResult{Type: "codex_proxy_result", Answer: data})
			}()
		}
	}()
	return socket
}

func TestSocketDeciderAsksTheDaemon(t *testing.T) {
	socket := fakeDaemon(t, func(question DecideRequest) DecideResponse {
		texts := make([]*string, len(question.Parts))
		for i, part := range question.Parts {
			texts[i] = headTail(part)
		}
		return DecideResponse{Texts: texts}
	})
	decider := SocketDecider{Client: localruntime.NewClient(socket)}
	part := Part{CallID: "call_1", Part: 1, ToolName: "exec", Text: seq(1, 3000)}
	response, err := decider.Decide(context.Background(), DecideRequest{SessionID: "s1", Parts: []Part{part}})
	if err != nil || len(response.Texts) != 1 || response.Texts[0] == nil || *response.Texts[0] != *headTail(part) {
		t.Fatalf("Decide = %+v, %v", response, err)
	}
}

func TestSocketDeciderStopsAtTheDeadline(t *testing.T) {
	decider := SocketDecider{Client: localruntime.NewClient(fakeDaemon(t, nil))}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := decider.Decide(ctx, DecideRequest{SessionID: "s1"}); err == nil {
		t.Fatal("a daemon that never answered gave an answer")
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("Decide waited %s past a 100ms deadline", waited)
	}
}

func TestSocketDeciderWithoutADaemon(t *testing.T) {
	decider := SocketDecider{Client: localruntime.NewClient(filepath.Join(t.TempDir(), "missing.sock"))}
	if _, err := decider.Decide(context.Background(), DecideRequest{SessionID: "s1"}); err == nil {
		t.Fatal("Decide without a daemon succeeded")
	}
}
