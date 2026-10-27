//go:build nostepsafetymodel

package stepsafety

import (
	"context"
	"testing"
)

func TestBuildWithoutModelIsUnavailable(t *testing.T) {
	evaluator := New(context.Background(), Config{Enabled: true})
	if evaluator == nil {
		t.Fatal("enabled config returned no evaluator")
	}
	health := evaluator.Health(context.Background())
	if health.Status != "unavailable" || health.ErrorCode != ErrorUnavailable {
		t.Fatalf("health = %+v, want unavailable", health)
	}
	result := evaluator.Evaluate(context.Background(), Input{ToolName: "send_email", UserRequest: "what is on my calendar"})
	if result.ShadowDecision != DecisionUnavailable || result.UnsafeProbability != nil || result.Enforced {
		t.Fatalf("result = %+v, want unavailable, unscored and not enforced", result)
	}
	if result.ErrorCode != ErrorUnavailable {
		t.Fatalf("error code = %q, want %q", result.ErrorCode, ErrorUnavailable)
	}
}
