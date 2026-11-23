package managedstream

import "slices"

// HookActionsSchema names the reconciler's report (ADR-0012). The cloud's
// contract is hookActionsReportSchema in packages/shared, and both pin
// testdata/hook-actions-v1.json.
const HookActionsSchema = "hook-actions-v1"

// The statuses of one agent and scope after a reconciler pass.
const (
	// HookInPlace: Kontext's entries were already there.
	HookInPlace = "in_place"
	// HookRestored: the reconciler wrote them and read them back.
	HookRestored = "restored"
	// HookMissing: they are absent and this pass did not write them.
	HookMissing = "missing"
	// HookAdminOff: a local opt-out in the managed config wins.
	HookAdminOff = "admin_off"
	// HookNotOurs: the file is one Kontext must not rewrite.
	HookNotOurs = "not_ours"
	// HookUnrestorable: a write or the read-back failed.
	HookUnrestorable = "unrestorable"
	// HookNeedsPrivileged: a machine-wide file needs root; the package has
	// to be pushed again.
	HookNeedsPrivileged = "needs_privileged"
)

// HookActions is device.hook_actions: what the reconciler found for the
// desired state, generation and repair nonce it acted on.
type HookActions struct {
	Schema      string             `json:"schema"`
	Desired     string             `json:"desired"`
	Generation  int64              `json:"generation"`
	RepairNonce *string            `json:"repair_nonce"`
	FinishedAt  string             `json:"finished_at"`
	Results     []HookActionResult `json:"results"`
}

type HookActionResult struct {
	Agent     string `json:"agent"`
	ScopeKind string `json:"scope_kind"`
	ScopeID   string `json:"scope_id,omitempty"`
	Status    string `json:"status"`
}

// Same reports whether two reports say the same thing, whenever they finished.
func (h HookActions) Same(other HookActions) bool {
	return h.Schema == other.Schema && h.Desired == other.Desired && h.Generation == other.Generation &&
		(h.RepairNonce == nil) == (other.RepairNonce == nil) &&
		(h.RepairNonce == nil || *h.RepairNonce == *other.RepairNonce) &&
		slices.Equal(h.Results, other.Results)
}

// addHookActions puts the reconciler's pending report on the payload; the
// payload remembers how to mark it sent once the cloud accepts it.
func addHookActions(payload *Payload, opts Options) {
	if opts.HookActions == nil {
		return
	}
	report, sent := opts.HookActions()
	if report == nil {
		return
	}
	if payload.Device == nil {
		payload.Device = &Device{}
	}
	payload.Device.HookActions = report
	payload.hookActionsSent = sent
}

// ackHookActions marks the report a post carried as sent.
func ackHookActions(payload Payload) {
	if payload.hookActionsSent != nil {
		payload.hookActionsSent()
	}
}
