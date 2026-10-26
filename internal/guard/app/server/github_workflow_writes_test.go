package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

func TestGitHubWorkflowWritePolicyDecisions(t *testing.T) {
	useMCPHome(t)
	const policy = `@id("default-permit") permit(principal, action, resource);
@id("protect-releases-and-workflows") forbid(principal, action, resource) when {
 context has tool && context.tool.provider == "github" && ["actions", "releases"].contains(context.tool.product) && ["write", "delete", "admin"].contains(context.tool.access)
};`
	for _, tc := range []struct {
		tool    string
		input   map[string]any
		blocked bool
	}{
		{"mcp__github__create_or_update_file", map[string]any{"path": ".github/workflows/build.yml"}, true},
		{"mcp__github__delete_file", map[string]any{"path": ".github/workflows/build.yml"}, true},
		{"mcp__github__delete_file", map[string]any{"path": "README.md"}, false},
		{"mcp__github__create_or_update_file", map[string]any{"path": "%2egithub/workflows/build.yml"}, true},
		{"mcp__github__create_or_update_file", map[string]any{"owner": "acme", "repo": "./sandbox", "path": ".github/workflows/build.yml"}, true},
		{"mcp__github__create_or_update_file", map[string]any{"owner": "acme", "repo": "sandbox/.", "path": ".github/workflows/build.yml"}, true},
		{"mcp__github__create_or_update_file", map[string]any{"owner": "acme", "repo": "sandbox/contents/.github/workflows/build.yml?x=", "path": "README.md"}, true},
		{"mcp__github__delete_file", map[string]any{"path": ".github%2fworkflows/build.yml"}, false},
		{"mcp__github__create_or_update_file", map[string]any{"path": "%2egithub/workflows/build.yml?x=/%2e%2e/%2e%2e/README.md"}, true},
		{"mcp__github__create_or_update_file", map[string]any{"path": "%2egithub/workflows/build.yml#x=/%2e%2e/%2e%2e/README.md"}, true},
		{"mcp__github__push_files", map[string]any{"files": []any{map[string]any{"path": ".github"}}}, true},
		{"mcp__github__push_files", map[string]any{"files": []any{map[string]any{"path": ".github/workflows"}}}, true},
		{"mcp__github__push_files", map[string]any{"files": []any{map[string]any{"path": "%2egithub/workflows/build.yml"}}}, false},
		{"mcp__github__create_or_update_file", map[string]any{"path": "./.github/workflows/build.yaml"}, true},
		{"mcp__github__create_or_update_file", map[string]any{"path": ".github/workflows/nested/build.yml"}, true},
		{"mcp__github__push_files", map[string]any{"files": []any{map[string]any{"path": "README.md"}, map[string]any{"path": ".github/workflows/build.yml"}}}, true},
		{"mcp__github__push_files", map[string]any{"files": []any{map[string]any{"path": "README.md"}}}, false},
		{"mcp__github__create_or_update_file", map[string]any{"path": ".github/workflows-old/build.yml"}, false},
		{"mcp__github__create_or_update_file", map[string]any{"path": "README.md"}, false},
		{"mcp__github__get_file_contents", map[string]any{"path": ".github/workflows/build.yml"}, false},
		{"mcp__other__create_or_update_file", map[string]any{"path": ".github/workflows/build.yml", "resource_id": "foreign-provider"}, false},
		{"Bash", map[string]any{"command": "git push origin main"}, false},
	} {
		for _, mode := range []cedareval.RolloutMode{cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce} {
			t.Run(tc.tool+"/"+string(mode)+"/"+func() string { b, _ := json.Marshal(tc.input); return string(b) }(), func(t *testing.T) {
				deployment := cedarTestDeployment(t, mode, policy)
				provider := newCedarPolicyProvider(staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
				decision, err := provider.DecideHook(context.Background(), cedarHookEvent(tc.tool, tc.input))
				if err != nil {
					t.Fatal(err)
				}
				if decision.Cedar == nil || decision.Cedar.EngineErrorCount != 0 {
					t.Fatalf("evaluation failed: %#v", decision.Cedar)
				}
				blocked := decision.Cedar.Mapping.DerivedCedarAction == cedareval.DerivedCedarActionDeny
				want := risk.DecisionAllow
				if tc.blocked && mode == cedareval.RolloutModeEnforce {
					want = risk.DecisionDeny
				}
				receipt, _ := json.Marshal(map[string]any{"tool": tc.tool, "input": tc.input, "mode": mode, "expected_block": tc.blocked, "actual_block": blocked, "effective": decision.Decision, "policies": decision.Cedar.Mapping.DeterminingPolicyIDs})
				t.Log(string(receipt))
				if blocked != tc.blocked || decision.Decision != want {
					t.Fatalf("got %s/block=%t, want %s/block=%t", decision.Decision, blocked, want, tc.blocked)
				}
			})
		}
	}
}

func TestWorkflowKeepsExistingCodePolicy(t *testing.T) {
	useMCPHome(t)
	const policy = `@id("default-permit") permit(principal, action, resource);
 @id("code-write") forbid(principal, action, resource) when { context has tool && context.tool.provider == "github" && context.tool.product == "code" && context.tool.access != "read" };`
	for _, input := range []map[string]any{
		{"files": []any{map[string]any{"path": "src/main.go"}}},
		{"files": []any{map[string]any{"path": "src/main.go"}, map[string]any{"path": ".github/workflows/pad.yml"}}},
	} {
		for _, mode := range []cedareval.RolloutMode{cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce} {
			deployment := cedarTestDeployment(t, mode, policy)
			provider := newCedarPolicyProvider(staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
			decision, err := provider.DecideHook(context.Background(), cedarHookEvent("mcp__github__push_files", input))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Cedar == nil || decision.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionDeny {
				t.Fatalf("code write escaped existing policy: %#v", decision)
			}
		}
	}
}
