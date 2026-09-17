package managedobserve

import (
	"context"
	"os"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// Discovery owns locations;
// the public authority package knows nothing about internal discovery types.
func scanAuthority(ctx context.Context, scanner *agentauthority.Scanner, home string, inv agentinventory.Inventory) agentauthority.Report {
	locations := make([]agentauthority.AgentLocation, 0, len(inv.Agents))
	for _, agent := range inv.Agents {
		locations = append(locations, agentauthority.AgentLocation{ID: agent.ID, ConfigPath: agent.ConfigPath})
	}
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return scanner.Scan(scanCtx, home, agentauthority.ProbeEnvironment(), locations, time.Now())
}

type authorityHolder struct {
	scanner   agentauthority.Scanner
	mu        sync.RWMutex
	report    agentauthority.Report
	present   bool
	enabled   func() bool
	available <-chan struct{}
	resend    <-chan struct{}
}

func (h *authorityHolder) Fact() (agentauthority.Report, bool) {
	if h == nil {
		return agentauthority.Report{}, false
	}
	if !managedstream.AuthorityScanLocallyEnabled() || h.enabled == nil || !h.enabled() {
		h.mu.Lock()
		h.report, h.present = agentauthority.Report{}, false
		h.mu.Unlock()
		return agentauthority.Report{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.report, h.present
}

func (h *authorityHolder) refresh(ctx context.Context, inv agentinventory.Inventory) {
	if !managedstream.AuthorityScanLocallyEnabled() || !h.enabled() {
		h.mu.Lock()
		h.report, h.present = agentauthority.Report{}, false
		h.mu.Unlock()
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	if h.scanner.BeginRead != nil {
		defer h.scanner.BeginRead()()
	}
	report := scanAuthority(ctx, &h.scanner, home, inv)
	if ctx.Err() != nil {
		return
	}
	h.mu.Lock()
	h.report, h.present = report, true
	h.mu.Unlock()
}

func (h *authorityHolder) run(ctx context.Context, inv *agentInventoryHolder, ready chan<- struct{}) {
	first, _ := inv.Fact()
	h.refresh(ctx, first)
	close(ready)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-h.available:
			current, _ := inv.Fact()
			h.refresh(ctx, current)
		case <-ticker.C:
			current, _ := inv.Fact()
			h.refresh(ctx, current)
		}
	}
}
