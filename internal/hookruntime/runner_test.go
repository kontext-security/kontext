package hookruntime

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
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
	event     hook.Event
	out       []byte
	decodeErr error
}

func (s stubCodec) DecodeHookEvent([]byte) (hook.Event, error) {
	if s.decodeErr != nil {
		return hook.Event{}, s.decodeErr
	}
	return s.event, nil
}

func (s stubCodec) EncodeHookResult(hook.Event, hook.Result) ([]byte, error) {
	return s.out, nil
}

// A skipped event is not a failure. Some agent runtimes read a non-zero hook
// exit as "block the tool call", so an event the adapter recognizes but does not
// translate must exit 0 and emit no decision.
func TestRunSucceedsSilentlyOnSkippedEvent(t *testing.T) {
	t.Parallel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	code := Run(
		bytes.NewBufferString(`{"hook_event_name":"PostCompaction"}`),
		stdout,
		stderr,
		stubCodec{decodeErr: fmt.Errorf("devin: event PostCompaction: %w", hook.ErrSkipEvent)},
		func(hook.Event) (hook.Result, error) {
			t.Fatal("evaluate called for a skipped event")
			return hook.Result{}, nil
		},
	)

	if code != 0 {
		t.Fatalf("Run() exit code = %d, want 0", code)
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want no decision written", stdout.String())
	}
}

func TestRunFailsOnDecodeErrorThatIsNotASkip(t *testing.T) {
	t.Parallel()

	code := Run(
		bytes.NewBufferString(`{`),
		&bytes.Buffer{},
		&bytes.Buffer{},
		stubCodec{decodeErr: errors.New("malformed")},
		func(hook.Event) (hook.Result, error) { return hook.Result{}, nil },
	)

	if code != 2 {
		t.Fatalf("Run() exit code = %d, want 2", code)
	}
}
