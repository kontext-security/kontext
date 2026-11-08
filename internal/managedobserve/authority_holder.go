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
	locations := agentinventory.AuthorityLocations(home, os.Getenv, inv)
	scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return scanner.Scan(scanCtx, home, agentauthority.ProbeEnvironment(), locations, time.Now())
}

type authorityHolder struct {
	scanner agentauthority.Scanner
	mu      sync.RWMutex
	report  agentauthority.Report
	present bool
	enabled func() bool
	// known reports whether the server has ever answered the scan flag.
	known     func() bool
	available <-chan struct{}
	resend    <-chan struct{}
	// record takes each finished scan for upload; nil in tests.
	record  func(agentauthority.Report)
	discard func()
}

func (h *authorityHolder) scanEnabled() bool {
	return managedstream.AuthorityScanLocallyEnabled() && h.enabled != nil && h.enabled()
}

// clear forgets the report and, once an opt-out is certain, the results waiting
// for upload. Before the server has answered, disabled only means no policy yet.
func (h *authorityHolder) clear() {
	h.mu.Lock()
	h.report, h.present = agentauthority.Report{}, false
	h.mu.Unlock()
	if h.discard != nil && (!managedstream.AuthorityScanLocallyEnabled() || h.known == nil || h.known()) {
		h.discard()
	}
}

func (h *authorityHolder) Fact() (agentauthority.Report, bool) {
	if h == nil {
		return agentauthority.Report{}, false
	}
	if !h.scanEnabled() {
		h.clear()
		return agentauthority.Report{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.report, h.present
}

func (h *authorityHolder) refresh(ctx context.Context, inv agentinventory.Inventory) {
	if !h.scanEnabled() {
		h.clear()
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
	if !h.scanEnabled() {
		h.clear()
		return
	}
	h.mu.Lock()
	h.report, h.present = report, true
	h.mu.Unlock()
	if h.record != nil {
		h.record(report)
	}
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
