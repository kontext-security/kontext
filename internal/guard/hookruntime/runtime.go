package hookruntime

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type Mode string

const (
	ModeObserve Mode = "observe"
	ModeEnforce Mode = "enforce"
	// ModeRemote defers the posture to the policy distribution: a decision the
	// runtime marked enforce (Mode on the result) passes through unchanged,
	// everything else gets observe semantics. Neither the hook edge nor the
	// daemon start-up pins the posture; the fetched deployment does.
	ModeRemote Mode = "remote"
)

type Adapter interface {
	Decode(io.Reader) (hook.Event, error)
	Encode(io.Writer, hook.Event, hook.Result) error
	MalformedHookName() hook.HookName
}

type Processor interface {
	Process(ctx context.Context, event hook.Event) (hook.Result, error)
}

func Run(ctx context.Context, adapter Adapter, processor Processor, mode Mode, stdin io.Reader, stdout, stderr io.Writer) error {
	event, err := adapter.Decode(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "kontext: malformed hook input: %v\n", err)
		malformed := hook.Event{HookName: adapter.MalformedHookName()}
		return adapter.Encode(stdout, malformed, effectiveResult(malformed, hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "malformed hook input",
			Mode:     string(mode),
		}, mode))
	}

	result, err := processor.Process(ctx, event)
	if err != nil {
		if event.HookName.CanBlock() && mode == ModeEnforce {
			return adapter.Encode(stdout, event, hook.Result{
				Decision: hook.DecisionDeny,
				Reason:   "Kontext daemon unavailable",
				Mode:     string(mode),
			})
		}
		fmt.Fprintf(stderr, "kontext: async hook ingestion failed: %v\n", err)
		return adapter.Encode(stdout, event, effectiveResult(event, hook.Result{
			Decision: hook.DecisionAllow,
			Reason:   "telemetry allowed",
			Mode:     string(mode),
		}, mode))
	}

	return adapter.Encode(stdout, event, effectiveResult(event, normalizeResult(result), mode))
}

func ParseMode(value string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(value))) {
	case "", ModeObserve:
		return ModeObserve, nil
	case ModeEnforce:
		return ModeEnforce, nil
	case ModeRemote:
		return ModeRemote, nil
	default:
		return "", fmt.Errorf("unknown hook mode %q; use observe, enforce, or remote", value)
	}
}

func normalizeResult(result hook.Result) hook.Result {
	if result.Decision == hook.DecisionAllow || result.Decision == hook.DecisionDeny {
		return result
	}
	result.Decision = hook.DecisionDeny
	return result
}

func effectiveResult(event hook.Event, result hook.Result, mode Mode) hook.Result {
	if mode == ModeRemote {
		// The runtime stamped enforce only on decisions the policy
		// distribution made authoritative; everything else is observe.
		if result.Mode == string(ModeEnforce) {
			if !event.HookName.CanBlock() {
				result.Decision = hook.DecisionAllow
			}
			return result
		}
		mode = ModeObserve
	}
	result.Mode = string(mode)
	if mode == ModeObserve {
		result.Reason = formatObserveReason(result.Decision, result.Reason)
		result.Decision = hook.DecisionAllow
		return result
	}
	if !event.HookName.CanBlock() {
		result.Decision = hook.DecisionAllow
	}
	return result
}

func formatObserveReason(decision hook.Decision, reason string) string {
	if reason == "" {
		reason = "no reason provided"
	}
	return fmt.Sprintf("Kontext observe mode: would %s; %s", decision, reason)
}
