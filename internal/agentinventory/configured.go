package agentinventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/kontext-security/kontext/internal/antigravitymanaged"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/privacyfolder"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const (
	configWalkLimit    = 2000
	configWalkDepth    = 4
	hookFileLimitBytes = 1024 * 1024
)

// kontextHookFiles are the files Kontext writes into an agent's folder, by
// path relative to that folder. Each reports whether nothing but Kontext's own
// entries is in the file.
var kontextHookFiles = map[string]map[string]func([]byte) bool{
	"claude_code": {"settings.json": func(raw []byte) bool {
		return onlyHooks(raw, func(settings map[string]any) error {
			return errors.Join(claudemanaged.RemoveManagedHooks(settings), claudemanaged.RemoveGuardHooks(settings))
		})
	}},
	"codex": {
		"hooks.json":  func(raw []byte) bool { return onlyHooks(raw, codexmanaged.RemoveManagedHooks) },
		"config.toml": onlyCodexFeature,
	},
	"cursor": {"hooks.json": func(raw []byte) bool { return onlyHooks(raw, cursormanaged.RemoveManagedHooks) }},
	"antigravity": {"hooks.json": func(raw []byte) bool {
		return onlyHooks(raw, func(settings map[string]any) error {
			antigravitymanaged.RemoveManagedHooks(settings)
			return nil
		})
	}},
}

// foreignDirs are subfolders that belong to another catalog agent.
var foreignDirs = map[string]map[string]bool{
	"gemini_cli": {"antigravity": true, "antigravity-cli": true, "config": true},
}

// onlyHooks is false for malformed input: Kontext only ever writes valid JSON.
func onlyHooks(raw []byte, remove func(map[string]any) error) bool {
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil {
		return false
	}
	if settings == nil {
		settings = map[string]any{}
	}
	if err := remove(settings); err != nil {
		return false
	}
	if hooks, ok := settings["hooks"].(map[string]any); ok && len(hooks) == 0 {
		delete(settings, "hooks")
	}
	delete(settings, "version")
	return len(settings) == 0
}

// onlyCodexFeature is true for a config.toml holding only the hook feature flag
// and Kontext's model route.
func onlyCodexFeature(raw []byte) bool {
	content, err := codexmanaged.RemoveRoute(string(raw))
	if err != nil {
		return false
	}
	var config map[string]any
	if _, err := toml.Decode(content, &config); err != nil {
		return false
	}
	if features, ok := config["features"].(map[string]any); ok {
		// Kontext only ever writes hooks = true.
		if features["hooks"] == true {
			delete(features, "hooks")
		}
		if len(features) == 0 {
			delete(config, "features")
		}
	}
	return len(config) == 0
}

func isKontextBackup(name string) bool {
	return strings.Contains(name, ".kontext-") && strings.Contains(name, "-backup-")
}

// inspectConfig returns the agent's config folder and whether it holds any
// file the agent owns. A folder holding only Kontext's hooks is not evidence
// of the agent, because Kontext writes hooks for agents not yet on the machine.
func inspectConfig(ctx context.Context, descriptor Descriptor, home string, env func(string) string, clean map[string]bool, health *agentauthority.SourceHealth) (string, bool) {
	candidates := configDirs(descriptor, home, env)
	config := candidates[0]
	existing := false
	for _, candidate := range candidates {
		// Reading through a link into a privacy-guarded folder would prompt.
		if privacyGuarded(descriptor, home, candidate, clean) {
			health.Fail(agentauthority.ReasonPermissionDenied)
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				health.Read()
			} else {
				health.Fail(agentauthority.ReasonFor(err))
			}
			continue
		}
		health.Read()
		if !info.IsDir() {
			continue
		}
		if !existing {
			config, existing = candidate, true
		}
		// Claude Desktop creates these folders and Kontext writes nothing there.
		if descriptor.ID == "claude_cowork" {
			return candidate, true
		}
		walk := configWalk{ctx: ctx, health: health, owned: kontextHookFiles[descriptor.ID], foreign: foreignDirs[descriptor.ID]}
		if walk.agentFiles(candidate, "", 0) {
			return candidate, true
		}
	}
	if descriptor.ID == "claude_code" && claudeRootConfigured(ctx, home, clean, health) {
		return config, true
	}
	return config, false
}

// claudeRootConfigured counts ~/.claude.json, where Claude Code keeps its user
// MCP servers and state. Kontext never writes this file.
func claudeRootConfigured(ctx context.Context, home string, clean map[string]bool, health *agentauthority.SourceHealth) bool {
	path := filepath.Join(home, ".claude.json")
	if linkGuarded(home, path, clean) {
		health.Fail(agentauthority.ReasonPermissionDenied)
		return false
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			health.Read()
		} else {
			health.Fail(agentauthority.ReasonFor(err))
		}
		return false
	}
	health.Read()
	if !info.Mode().IsRegular() {
		return true
	}
	walk := configWalk{ctx: ctx, health: health}
	return walk.notKontextFile(path, func(raw []byte) bool {
		return onlyHooks(raw, func(map[string]any) error { return nil })
	})
}

// privacyGuarded walks each parent once per scan: most candidates share one.
// A catalog folder cannot itself be guarded, so a clean parent only leaves the
// question of whether the folder is a link; an override gets the full check.
func privacyGuarded(descriptor Descriptor, home, candidate string, clean map[string]bool) bool {
	if !slices.ContainsFunc(descriptor.ConfigDirs, func(rel string) bool { return filepath.Join(home, rel) == candidate }) {
		return privacyfolder.Guarded(home, candidate)
	}
	return linkGuarded(home, candidate, clean)
}

// linkGuarded checks a path whose own name cannot be guarded: a clean parent
// leaves only the question of whether the path is a link.
func linkGuarded(home, path string, clean map[string]bool) bool {
	parent := filepath.Dir(path)
	if !clean[parent] {
		if privacyfolder.Guarded(home, parent) {
			return true
		}
		clean[parent] = true
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0 && privacyfolder.Guarded(home, path)
}

type configWalk struct {
	ctx     context.Context
	health  *agentauthority.SourceHealth
	owned   map[string]func([]byte) bool
	foreign map[string]bool
	visited int
	limited bool
}

// agentFiles stops at the first file Kontext did not write.
func (w *configWalk) agentFiles(dir, rel string, depth int) (found bool) {
	if depth == 0 {
		// A deep folder only matters when nothing else proved the agent.
		defer func() {
			if w.limited && !found {
				w.health.Fail(agentauthority.ReasonWalkLimit)
			}
		}()
	}
	file, err := os.Open(dir)
	if err != nil {
		w.failListed(err)
		return false
	}
	defer file.Close()
	for {
		if w.ctx.Err() != nil {
			w.health.Fail(agentauthority.ReasonDeadline)
			return false
		}
		entries, readErr := file.ReadDir(64)
		for _, entry := range entries {
			if w.visited++; w.visited > configWalkLimit {
				w.health.Fail(agentauthority.ReasonWalkLimit)
				return false
			}
			name := entry.Name()
			if name == ".DS_Store" || isKontextBackup(name) {
				continue
			}
			path, relative := filepath.Join(dir, name), filepath.Join(rel, name)
			if entry.IsDir() {
				if w.foreign[relative] {
					continue
				}
				if depth+1 >= configWalkDepth {
					w.limited = true
					continue
				}
				if w.agentFiles(path, relative, depth+1) {
					return true
				}
				continue
			}
			// Kontext never writes links or special files.
			check := w.owned[relative]
			if check == nil || !entry.Type().IsRegular() || w.notKontextFile(path, check) {
				return true
			}
		}
		if errors.Is(readErr, io.EOF) {
			return false
		}
		if readErr != nil {
			w.health.Fail(agentauthority.ReasonFor(readErr))
			return false
		}
	}
}

// failListed is for a path a stat or listing just found, so absence is a change.
func (w *configWalk) failListed(err error) {
	if errors.Is(err, os.ErrNotExist) {
		w.health.Fail(agentauthority.ReasonChangedDuringRead)
		return
	}
	w.health.Fail(agentauthority.ReasonFor(err))
}

// notKontextFile leaves an unreadable file undecided: the failure is latched
// and the file counts as neither ours nor the agent's.
func (w *configWalk) notKontextFile(path string, check func([]byte) bool) bool {
	file, err := os.Open(path)
	if err != nil {
		w.failListed(err)
		return false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, hookFileLimitBytes+1))
	if err != nil {
		w.health.Fail(agentauthority.ReasonFor(err))
		return false
	}
	return len(raw) > hookFileLimitBytes || !check(raw)
}
