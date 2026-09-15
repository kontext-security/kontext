package managedobserve

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/codexmanaged"
)

// AgentWiring shares the daemon's hook facts with the one-shot setup scan.
// The scanner itself must not import managedobserve (managedstream uses it).
func AgentWiring() map[string]func() agentinventory.Wired {
	paths, err := codexmanaged.DefaultInstallationPaths()
	return agentWiring(paths, err)
}

// AgentWiringWithCodexPaths lets callers inspecting a staged installation keep
// system hook discovery inside that installation instead of reading host policy.
func AgentWiringWithCodexPaths(paths codexmanaged.InstallationPaths) map[string]func() agentinventory.Wired {
	return agentWiring(paths, nil)
}

func agentWiring(paths codexmanaged.InstallationPaths, pathsErr error) map[string]func() agentinventory.Wired {
	claude := func() agentinventory.Wired {
		fact, ok := managedObserveHooksFact()
		if !ok {
			return agentinventory.WiredError
		}
		if fact.Present {
			return agentinventory.WiredYes
		}
		return agentinventory.WiredNo
	}
	return map[string]func() agentinventory.Wired{
		"claude_code": claude, "claude_cowork": claude,
		"codex": func() agentinventory.Wired {
			if pathsErr != nil {
				return agentinventory.WiredError
			}
			_, err := codexmanaged.InspectInstallation(paths)
			if errors.Is(err, codexmanaged.ErrIncompleteInstallation) {
				return agentinventory.WiredNo
			}
			if err != nil {
				return agentinventory.WiredError
			}
			return agentinventory.WiredYes
		},
	}
}

type agentInventoryHolder struct {
	mu        sync.RWMutex
	inventory agentinventory.Inventory
	present   bool
}

// Fact returns immutable scan data; each refresh replaces the whole value.
func (h *agentInventoryHolder) Fact() (agentinventory.Inventory, bool) {
	if h == nil {
		return agentinventory.Inventory{}, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.inventory, h.present
}

func (h *agentInventoryHolder) run(ctx context.Context, opts DaemonOptions, dbPath string, ready chan<- struct{}) {
	interval := opts.AgentInventoryInterval
	if interval <= 0 {
		interval = agentInventoryIntervalFromEnv()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		opts.Diagnostic.Printf("agent inventory: home unavailable: %v\n", err)
		close(ready)
		return
	}
	first := true
	for {
		started := time.Now()
		scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		inv := agentinventory.Scan(scanCtx, home, os.Getenv, started, AgentWiring())
		cancel()
		opts.Diagnostic.Printf("agent inventory: scanned %d agents in %s (incomplete=%t)\n", len(inv.Agents), time.Since(started), inv.Incomplete)
		if ctx.Err() == nil {
			if err := writeJSONBreadcrumb(AgentInventoryPath(dbPath), inv); err != nil {
				opts.Diagnostic.Printf("write agent inventory breadcrumb: %v\n", err)
			}
			h.mu.Lock()
			h.inventory, h.present = inv, true
			h.mu.Unlock()
		}
		if first {
			close(ready)
			first = false
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
