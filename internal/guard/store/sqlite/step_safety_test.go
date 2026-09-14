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
		HistoryOmitted:    true,
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
	if err != nil || len(rows) != 1 || rows[0].UnsafeProbability == nil || !rows[0].HistoryOmitted {
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

func TestStepSafetyHistoryCoverageMigratesExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate the previous pilot schema, including a historical verdict.
	_, err = store.SaveStepSafetyVerdict(context.Background(), StepSafetyRecord{ActionID: "old", SessionID: "s", ToolName: "Bash", ModelVersion: "previous-pilot", ShadowDecision: stepsafety.DecisionUnavailable})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`alter table step_safety_verdicts drop column history_omitted`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, err := reopened.StepSafetyVerdictForAction(context.Background(), "old")
	if err != nil || record.HistoryOmitted {
		t.Fatalf("migration failed: %+v / %v", record, err)
	}
}
