package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

func TestGitHubAdministrationPolicyDecisions(t *testing.T) {
	useMCPHome(t)
	const policy = `@id("default-permit") permit(principal, action, resource);
@id("protect-repository-settings") forbid(principal, action, resource) when {
 context has shell && context.shell.facts.containsAny([
 "github/operation=edit-organization", "github/operation=edit-teams", "github/operation=edit-account-keys"])
};`
	for _, tc := range []struct {
		command string
		blocked bool
	}{
		{`gh api -X PUT orgs/acme/memberships/outside-user -f role=admin`, true},
		{`gh api -X DELETE orgs/acme/members/outside-user`, true},
		{`gh api -X PATCH orgs/acme -F members_can_create_public_repositories=true`, true},
		{`gh api -X PUT orgs/acme/teams/owners/memberships/user -f role=maintainer`, true},
		{`gh api -X POST orgs/acme/teams -f name=agents`, true},
		{`gh api -X DELETE teams/123`, true},
		{`gh api -X PUT orgs/acme/actions/permissions -F enabled_repositories=all`, true},
		{`curl -X DELETE https://api.github.com/orgs/acme/teams/owners`, true},
		{`gh ssh-key add attacker.pub --title laptop`, true},
		{`gh ssh-key delete 123 --yes`, true},
		{`gh gpg-key add attacker.asc`, true},
		{`gh gpg-key delete 123 --yes`, true},
		{`gh api -X POST user/keys -f key=ssh-rsa`, true},
		{`curl -X DELETE https://api.github.com/user/gpg_keys/123`, true},
		{`gh api orgs/acme/memberships/user`, false},
		{`gh api orgs/acme/teams`, false},
		{`gh ssh-key list`, false},
		{`gh gpg-key list`, false},
		{`gh pr list`, false},
	} {
		for _, mode := range []cedareval.RolloutMode{cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce} {
			t.Run(tc.command+"/"+string(mode), func(t *testing.T) {
				deployment := cedarTestDeployment(t, mode, policy)
				provider := newCedarPolicyProvider(staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
				decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": tc.command}))
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
				receipt, _ := json.Marshal(map[string]any{"command": tc.command, "mode": mode, "expected_block": tc.blocked, "actual_block": blocked, "effective": decision.Decision, "policies": decision.Cedar.Mapping.DeterminingPolicyIDs})
				t.Log(string(receipt))
				if blocked != tc.blocked || decision.Decision != want {
					t.Fatalf("decision = %s/block=%t, want %s/block=%t", decision.Decision, blocked, want, tc.blocked)
				}
			})
		}
	}
}
