package sqlite

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

func TestCedarClassification(t *testing.T) {
	shell := func(facts ...string) cedareval.ShellProjectionV2 {
		return cedareval.ShellProjectionV2{Program: "databricks", Facts: facts}
	}
	tests := []struct {
		name     string
		evidence *risk.CedarEvidence
		want     *cedareval.ToolClassificationV2
	}{
		{"none", nil, nil},
		{"mcp tool", &risk.CedarEvidence{Tool: &cedareval.ToolClassificationV2{Provider: "databricks", Product: "sql", Access: "delete"}}, &cedareval.ToolClassificationV2{Provider: "databricks", Product: "sql", Access: "delete"}},
		{"catalogued read", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{shell("databricks/route=catalogued", "databricks/product=compute")}}, &cedareval.ToolClassificationV2{Provider: "databricks", Product: "compute", Access: "read"}},
		{"delete beats admin", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{shell("databricks/route=catalogued", "databricks/product=sql", "databricks/write=true", "databricks/delete=true", "databricks/admin=true")}}, &cedareval.ToolClassificationV2{Provider: "databricks", Product: "sql", Access: "delete"}},
		{"admin beats write", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{shell("databricks/route=catalogued", "databricks/product=workspace", "databricks/write=true", "databricks/admin=true")}}, &cedareval.ToolClassificationV2{Provider: "databricks", Product: "workspace", Access: "admin"}},
		{"strictest projection wins", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{
			shell("databricks/route=catalogued", "databricks/product=compute"),
			shell("databricks/route=catalogued", "databricks/product=sql", "databricks/write=true", "databricks/delete=true"),
		}}, &cedareval.ToolClassificationV2{Provider: "databricks", Product: "sql", Access: "delete"}},
		{"unrecognized route has no tier", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{shell("databricks/command=api/post", "databricks/route=unrecognized")}}, &cedareval.ToolClassificationV2{Provider: "databricks"}},
		{"other shell", &risk.CedarEvidence{Shell: []cedareval.ShellProjectionV2{{Program: "git", Facts: []string{"github/write=true"}}}}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := cedarClassification(test.evidence)
			if (got == nil) != (test.want == nil) || got != nil && *got != *test.want {
				t.Fatalf("cedarClassification() = %+v, want %+v", got, test.want)
			}
		})
	}
}

// The ledger row and the exported decision fact name the provider the Cedar
// request classified the call as, which the normalizer leaves empty for
// catalogued MCP providers (ENG-758 F4).
func TestSaveDecisionRecordsTheCedarProvider(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	evidence := enforcedDenyCedarEvidence()
	evidence.ToolID = "databricks-mcp/execute_sql"
	evidence.Tool = &cedareval.ToolClassificationV2{Provider: "databricks", Product: "sql", Access: "delete"}
	_, err = store.SaveDecision(context.Background(), risk.HookEvent{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "mcp__claude_ai_Warehouse__execute_sql", ToolUseID: "tool-1"}, risk.RiskDecision{
		Decision:  risk.DecisionDeny,
		RiskEvent: risk.RiskEvent{Decision: risk.DecisionDeny, OperationClass: "unknown", ResourceClass: "unknown"},
		Cedar:     evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	var provider, operationClass, resourceClass, factJSON, riskEventJSON string
	if err := store.db.QueryRowContext(context.Background(), `select provider, operation_class, resource_class, decision_fact_json, risk_event_json from authorization_actions where session_id = 's1' and canonical_event_type = 'request.decided'`).Scan(&provider, &operationClass, &resourceClass, &factJSON, &riskEventJSON); err != nil {
		t.Fatal(err)
	}
	var fact struct {
		TargetProvider *string `json:"target_provider"`
	}
	if err := json.Unmarshal([]byte(factJSON), &fact); err != nil {
		t.Fatal(err)
	}
	var event risk.RiskEvent
	if err := json.Unmarshal([]byte(riskEventJSON), &event); err != nil {
		t.Fatal(err)
	}
	if provider != "databricks" || operationClass != "delete" || resourceClass != "sql" || fact.TargetProvider == nil || *fact.TargetProvider != "databricks" ||
		event.Provider != "databricks" || event.OperationClass != "delete" || event.ResourceClass != "sql" {
		t.Fatalf("row = provider %q access %q product %q, fact target_provider %v, risk event %+v", provider, operationClass, resourceClass, fact.TargetProvider, event)
	}
}
