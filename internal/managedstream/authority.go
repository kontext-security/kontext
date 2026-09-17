package managedstream

import (
	"os"
	"strings"
	"time"
)

func AuthorityScanLocallyEnabled() bool {
	return !strings.EqualFold(strings.TrimSpace(os.Getenv("KONTEXT_AUTHORITY_SCAN")), "off")
}

func addAuthority(payload *Payload, opts Options, state State, now time.Time) {
	if opts.AuthorityFact == nil || !AuthorityScanLocallyEnabled() {
		return
	}
	report, ok := opts.AuthorityFact()
	if !ok {
		return
	}
	previous := state.LastReport.Authority
	if previous != nil && previous.Hash == report.Hash && !heartbeatDue(state.LastAuthorityAt, time.Hour, now) {
		return
	}
	if payload.Device == nil {
		payload.Device = &Device{}
	}
	payload.Device.Authority = &report
}

func recordReport(state *State, payload Payload, now time.Time) {
	if payload.Device == nil {
		return
	}
	if payload.Device.Agents != nil {
		state.LastReport.Agents = payload.Device.Agents
		state.LastReport.AgentsReportedAt = payload.Device.AgentsReportedAt
	}
	if payload.Device.Authority != nil {
		state.LastReport.Authority = payload.Device.Authority
		state.LastAuthorityAt = now.Format(time.RFC3339Nano)
	}
}
