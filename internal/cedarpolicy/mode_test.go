package cedarpolicy

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
)

func TestDeploymentClaimsEnforce(t *testing.T) {
	enforce := &Deployment{RolloutMode: cedareval.RolloutModeEnforce}
	observe := &Deployment{RolloutMode: cedareval.RolloutModeObserve}

	cases := map[string]struct {
		snapshot Snapshot
		want     bool
	}{
		"empty snapshot":              {Snapshot{}, false},
		"active enforce":              {Snapshot{Deployment: enforce, State: StateSuccess}, true},
		"active observe":              {Snapshot{Deployment: observe, State: StateSuccess}, false},
		"last-known-good enforce":     {Snapshot{LastKnownGood: enforce, State: StateUnavailable}, true},
		"expired enforce holds":       {Snapshot{Deployment: enforce, State: StateSuccess, Status: CacheStatus{Expired: true}}, true},
		"disabled relinquishes":       {Snapshot{LastKnownGood: enforce, State: StateDisabled}, false},
		"no active policy relinquish": {Snapshot{LastKnownGood: enforce, State: StateNoActivePolicy}, false},
		"active observe over LKG":     {Snapshot{Deployment: observe, LastKnownGood: enforce, State: StateSuccess}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := DeploymentClaimsEnforce(tc.snapshot); got != tc.want {
				t.Fatalf("DeploymentClaimsEnforce = %v, want %v", got, tc.want)
			}
		})
	}
}
