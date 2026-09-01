package sqlite

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
)

func TestStepSafetyTelemetryContainsNoRawContext(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	probability := 0.91
	stored, err := store.SaveStepSafetyVerdict(context.Background(), StepSafetyRecord{
		ActionID:          "act-1",
		SessionID:         "session-1",
		ToolUseID:         "tool-1",
		ToolName:          "Write [REDACTED]",
		UnsafeProbability: &probability,
		ShadowDecision:    stepsafety.DecisionUnsafe,
		Threshold:         stepsafety.Threshold,
		ModelVersion:      stepsafety.ModelVersion,
		LatencyMS:         12.5,
	})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"secret argument", "user request", "interaction_history", "tool_arguments", "available_tool_schemas"} {
		if strings.Contains(string(blob), forbidden) {
			t.Fatalf("telemetry leaked %q: %s", forbidden, blob)
		}
	}
	rows, err := store.StepSafetyVerdictsForSession(context.Background(), "session-1")
	if err != nil || len(rows) != 1 || rows[0].UnsafeProbability == nil {
		t.Fatalf("stored rows = %+v, err = %v", rows, err)
	}
}

func TestStepSafetyFeedback(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	_, err = store.SaveStepSafetyVerdict(context.Background(), StepSafetyRecord{
		ActionID:       "act-1",
		SessionID:      "session-1",
		ToolName:       "Read",
		ShadowDecision: stepsafety.DecisionSafe,
		Threshold:      stepsafety.Threshold,
		ModelVersion:   stepsafety.ModelVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := store.SetStepSafetyFeedback(context.Background(), "act-1", riskclassifier.FeedbackShouldBlock)
	if err != nil {
		t.Fatal(err)
	}
	if updated.UserFeedback != riskclassifier.FeedbackShouldBlock || updated.FeedbackAt == nil {
		t.Fatalf("updated = %+v", updated)
	}
}
