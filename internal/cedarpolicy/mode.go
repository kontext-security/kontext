package cedarpolicy

import "github.com/kontext-security/kontext-cli/internal/cedareval"

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
	return deployment != nil && deployment.RolloutMode == cedareval.RolloutModeEnforce
}
