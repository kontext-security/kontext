package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// AgentWiring shares the daemon's hook facts with the one-shot setup scan.
// The scanner itself must not import managedobserve (managedstream uses it).
// scope is the managed config's: self-serve hooks live in the user's home.
func AgentWiring(scope managedconfig.Scope) map[string]func() agentinventory.Wired {
	paths, err := codexmanaged.DefaultInstallationPaths()
	return agentWiring(paths, err, scope)
}

// AgentWiringWithCodexPaths lets callers inspecting a staged installation keep
// system hook discovery inside that installation instead of reading host policy.
func AgentWiringWithCodexPaths(paths codexmanaged.InstallationPaths) map[string]func() agentinventory.Wired {
	return agentWiring(paths, nil, managedconfig.ScopeSystem)
}

func agentWiring(paths codexmanaged.InstallationPaths, pathsErr error, scope managedconfig.Scope) map[string]func() agentinventory.Wired {
	wired := func(fact managedstream.HooksFact, ok bool) agentinventory.Wired {
		if !ok {
			return agentinventory.WiredError
		}
		if fact.Present {
			return agentinventory.WiredYes
		}
		return agentinventory.WiredNo
	}
	return map[string]func() agentinventory.Wired{
		"claude_code":   func() agentinventory.Wired { return wired(managedObserveHooksFact(scope)) },
		"claude_cowork": func() agentinventory.Wired { return wired(machineClaudeHooksFact()) },
		"codex": func() agentinventory.Wired {
			if pathsErr != nil {
				return agentinventory.WiredError
			}
			installation, err := codexmanaged.InspectInstallation(paths)
			if len(installation.Layers) > 0 {
				return agentinventory.WiredYes
			}
			if errors.Is(err, codexmanaged.ErrIncompleteInstallation) {
				return agentinventory.WiredNo
			}
			if err != nil {
				return agentinventory.WiredError
			}
			return agentinventory.WiredYes
		},
		"cursor": func() agentinventory.Wired { return cursorWired(scope) },
	}
}

// cursorWired reports whether Cursor's machine-wide hooks.json, or for a
// self-serve install the user's, carries the complete Kontext hook set.
// cursorSystemHooksPath is Cursor's machine-wide hooks file (a test seam).
var cursorSystemHooksPath = cursormanaged.SystemHooksPath

func cursorWired(scope managedconfig.Scope) agentinventory.Wired {
	if scope != managedconfig.ScopeUser {
		return cursorFileWired(cursorSystemHooksPath)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return agentinventory.WiredError
	}
	// Self-serve leaves out of the user file what a machine-wide file from an
	// earlier setup covers, so the two count together.
	covered := map[string]bool{}
	for _, path := range []string{cursorSystemHooksPath, filepath.Join(home, ".cursor", "hooks.json")} {
		// A complete machine-wide set is enough; the user's file does not matter.
		if len(covered) == len(cursormanaged.Events) {
			return agentinventory.WiredYes
		}
		// Reading through a link into a privacy-guarded folder would prompt.
		if privacyfolder.Guarded(home, path) {
			return agentinventory.WiredError
		}
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !json.Valid(raw) {
			return agentinventory.WiredError
		}
		for event, binary := range cursormanaged.Coverage(raw) {
			if privacyfolder.Guarded(home, binary) {
				return agentinventory.WiredError
			}
			if info, err := os.Stat(binary); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				covered[event] = true
			}
		}
	}
	if len(covered) == len(cursormanaged.Events) {
		return agentinventory.WiredYes
	}
	return agentinventory.WiredNo
}

func cursorFileWired(path string) agentinventory.Wired {
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return agentinventory.WiredNo
	case err != nil || !json.Valid(raw):
		return agentinventory.WiredError
	}
	binary, err := cursormanaged.ValidateInstalled(raw)
	switch {
	case errors.Is(err, cursormanaged.ErrMalformed):
		return agentinventory.WiredError
	case err != nil:
		return agentinventory.WiredNo
	}
	// Hooks that point at a missing binary fail on every call.
	if info, err := os.Stat(binary); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return agentinventory.WiredError
	}
	return agentinventory.WiredYes
}

type agentInventoryHolder struct {
	scope     managedconfig.Scope
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
		inv := agentinventory.Scan(scanCtx, home, os.Getenv, started, agentinventory.ScanOptions{
			Wired: AgentWiring(h.scope),
			HasCoworkSession: func(id string) (bool, error) {
				return sqlite.HasCoworkSession(scanCtx, dbPath, id)
			},
		})
		cancel()
		versionCtx, cancelVersions := context.WithTimeout(ctx, 5*time.Second)
		agentinventory.AddVersions(versionCtx, home, &inv)
		cancelVersions()
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
