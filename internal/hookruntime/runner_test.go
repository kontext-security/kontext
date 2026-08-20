package hookruntime

import (
	"bytes"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestRunWritesStructuredDenyResult(t *testing.T) {
	t.Parallel()

	codec := stubCodec{
		event: hook.Event{HookName: hook.HookPreToolUse},
		out:   []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}`),
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := Run(
		bytes.NewBufferString(`{"hook_event_name":"PreToolUse"}`),
		stdout,
		stderr,
		codec,
		func(hook.Event) (hook.Result, error) {
			return hook.Result{Decision: hook.DecisionDeny, Reason: "blocked by policy"}, nil
		},
	)

	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
	if stdout.String() != string(codec.out) {
		t.Fatalf("stdout = %q, want encoded output", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRunWritesStructuredUnsupportedDecisionResult(t *testing.T) {
	t.Parallel()

	codec := stubCodec{
		event: hook.Event{HookName: hook.HookPreToolUse},
		out:   []byte(`{"hookSpecificOutput":{"permissionDecision":"deny"}}`),
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := Run(
		bytes.NewBufferString(`{"hook_event_name":"PreToolUse"}`),
		stdout,
		stderr,
		codec,
		func(hook.Event) (hook.Result, error) {
			return hook.Result{Decision: hook.Decision("ask"), Reason: "approval required"}, nil
		},
	)

	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
	if stdout.String() != string(codec.out) {
		t.Fatalf("stdout = %q, want encoded output", stdout.String())
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

type stubCodec struct {
	event hook.Event
	out   []byte
}

func (s stubCodec) DecodeHookEvent([]byte) (hook.Event, error) {
	return s.event, nil
}

func (s stubCodec) EncodeHookResult(hook.Event, hook.Result) ([]byte, error) {
	return s.out, nil
}
