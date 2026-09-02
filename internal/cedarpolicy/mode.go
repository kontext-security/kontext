package cedarpolicy

import (
	"encoding/json"
	"io"
	"os"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// DeploymentClaimsEnforce reports whether the cached policy distribution asks
// this endpoint to enforce: an active (or last-known-good) deployment exists
// and its rollout mode is enforce. This is the remote-managed counterpart of
// the static cutover gate, with deliberately different unknown-state
// semantics: a remote-managed endpoint without a trustworthy deployment stays
// in observe, because the organization's intent is unknown until a deployment
// has been fetched. Expiry and staleness do not relinquish enforcement — once
// an enforce deployment is cached, only an explicit disabled/no-active-policy
// state or an observe deployment hands authority back.
func DeploymentClaimsEnforce(snapshot Snapshot) bool {
	if snapshot.State == StateDisabled || snapshot.State == StateNoActivePolicy {
		return false
	}
	deployment := snapshot.Deployment
	if deployment == nil {
		deployment = snapshot.LastKnownGood
	}
	if deployment != nil {
		return deployment.RolloutMode == cedareval.RolloutModeEnforce
	}
	legacy := snapshot.LegacyDeployment
	if legacy == nil {
		legacy = snapshot.LegacyLastKnownGood
	}
	return legacy != nil && legacy.RolloutMode == cedareval.RolloutModeEnforce
}

// PersistedDeploymentClaimsEnforce reads only the rollout claim from a cache.
// It keeps outage behavior stable across compatible cache and catalog upgrades,
// even when the cached policy itself can no longer be evaluated.
func PersistedDeploymentClaimsEnforce(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxResponseBytes+1))
	if err != nil || len(data) > MaxResponseBytes {
		return false
	}
	var cached cacheFile
	if err := json.Unmarshal(data, &cached); err != nil || (cached.Version != 1 && cached.Version != cacheFileVersion) {
		return false
	}
	return DeploymentClaimsEnforce(Snapshot{
		State:         cached.State,
		Deployment:    cached.Deployment,
		LastKnownGood: cached.LastGood,
	})
}
