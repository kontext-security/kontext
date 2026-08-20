package hookcmd

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

type stubAgent struct {
	decodeErr         error
	event             hook.HookName
	encodeErr         error
	allowUpdatedInput map[string]any
	blockingDecision  hook.Decision
	blockingReason    string
}

func (s *stubAgent) Name() string { return "stub" }

func (s *stubAgent) DecodeHookInput(input []byte) (hook.Event, error) {
	if s.decodeErr != nil {
		return hook.Event{}, s.decodeErr
	}
	event := s.event
	if event == "" {
		event = hook.HookPreToolUse
	}
	return hook.Event{HookName: event}, nil
}

func (s *stubAgent) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	if s.encodeErr != nil {
		return nil, s.encodeErr
	}
	if result.Blocking() {
		s.blockingDecision = result.Decision
		s.blockingReason = result.ClaudeReason()
		return []byte(strings.ToUpper(string(result.Decision))), nil
	}
	s.allowUpdatedInput = result.UpdatedInput
	return []byte("ALLOW"), nil
}

func TestRunAllowsAndWritesOutput(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	stub := &stubAgent{}
	updatedInput := map[string]any{"command": "echo ok"}
	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, stub, func(event hook.Event) (hook.Result, error) {
		if event.HookName != hook.HookPreToolUse {
			t.Fatalf("event.HookName = %q, want %q", event.HookName, hook.HookPreToolUse)
		}
		return hook.Result{Decision: hook.DecisionAllow, Reason: "ok", UpdatedInput: updatedInput}, nil
	})

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if got := stdout.String(); got != "ALLOW" {
		t.Fatalf("stdout = %q, want %q", got, "ALLOW")
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
	if stub.allowUpdatedInput["command"] != "echo ok" {
		t.Fatalf("updated input = %#v, want command", stub.allowUpdatedInput)
	}
}

func TestRunPreservesDenyDecision(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	stub := &stubAgent{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, stub, func(hook.Event) (hook.Result, error) {
		return hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "blocked",
		}, nil
	})

	if code != 0 {
		t.Fatalf("run() exit code = %d, want 0", code)
	}
	if stdout.String() != "DENY" {
		t.Fatalf("stdout = %q, want agent deny output", stdout.String())
	}
	if stub.blockingDecision != hook.DecisionDeny {
		t.Fatalf("blocking decision = %q, want deny", stub.blockingDecision)
	}
	if stub.blockingReason != "blocked" {
		t.Fatalf("blocking reason = %q, want raw reason", stub.blockingReason)
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunReturnsErrorWhenEncodingFails(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), stdout, stderr, &stubAgent{encodeErr: errors.New("encode failed")}, func(hook.Event) (hook.Result, error) {
		return hook.Result{Decision: hook.DecisionAllow, Reason: "ok"}, nil
	})

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "failed to encode hook output") {
		t.Fatalf("stderr = %q, want encode failure", stderr.String())
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
}

func TestRunReturnsErrorWhenWriteFails(t *testing.T) {
	t.Parallel()

	stderr := &bytes.Buffer{}

	code := run(strings.NewReader(`{"hook_event_name":"PreToolUse"}`), errWriter{}, stderr, &stubAgent{}, func(hook.Event) (hook.Result, error) {
		return hook.Result{Decision: hook.DecisionAllow, Reason: "ok"}, nil
	})

	if code != 2 {
		t.Fatalf("run() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "failed to write hook output") {
		t.Fatalf("stderr = %q, want write failure", stderr.String())
	}
}

func TestRunWithExpectedEventRejectsMismatch(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := runWithExpectedEvent(strings.NewReader(`{"hook_event_name":"PostToolUse"}`), stdout, stderr, &stubAgent{event: hook.HookPostToolUse}, hook.HookPreToolUse, func(hook.Event) (hook.Result, error) {
		t.Fatal("evaluate should not be called")
		return hook.Result{}, nil
	})

	if code != 2 {
		t.Fatalf("runWithExpectedEvent() exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "does not match stdin event") {
		t.Fatalf("stderr = %q, want mismatch error", stderr.String())
	}
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) {
	return 0, io.ErrClosedPipe
}
