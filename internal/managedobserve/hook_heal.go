package managedobserve

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

const hookWatchInterval = time.Minute

// runHookWatch keeps the agent scan current when hook files change, so the
// dashboard does not wait for the next periodic scan. It also keeps the user's
// hook files complete: it restores removed entries and adds a newly supported
// agent's hooks after an upgrade, never asking for an administrator because
// every file it writes is in the user's home. For a self-serve config that is
// every hook file; for an organization-managed config, whose package owns the
// machine-wide files, only the files of agents that read none (Antigravity).
func runHookWatch(ctx context.Context, loaded managedconfig.LoadedConfig, log diagnostic.Logger, rescan func()) {
	heal := hookHealer(loaded, log)
	last, started := "", false
	ticker := time.NewTicker(hookWatchInterval)
	defer ticker.Stop()
	for {
		healed := heal != nil && heal()
		current := hookFilesFingerprint()
		// The inventory scans once at start; later changes need a rescan.
		if healed || started && current != last {
			rescan()
		}
		last, started = current, true
		select {
		case <-ctx.Done():
			// One last pass as the daemon stops: package removal deletes the
			// machine-wide hooks and then stops this daemon, which removes the
			// user's hooks here, before the binary they name is deleted.
			if heal != nil {
				heal()
			}
			return
		case <-ticker.C:
		}
	}
}

// HookRepairAvailable reports whether this install's daemon adds hooks later,
// which is what lets setup leave out an agent that is not on the machine yet.
func HookRepairAvailable() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	brew, _, ok := currentExecutableBrewPath()
	return ok && runningStableBinary(filepath.Join(filepath.Dir(brew), "kontext"))
}

// runningStableBinary reports whether this process is the executable every hook
// names. The healer refuses to write hooks for any other.
func runningStableBinary(binary string) bool {
	exe, err := executablePath()
	if err != nil {
		return false
	}
	running, err := os.Stat(exe)
	if err != nil {
		return false
	}
	installed, err := os.Stat(binary)
	return err == nil && os.SameFile(running, installed)
}

func agentAbsent(home, agent string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return agentinventory.Absent(ctx, home, os.Getenv, agent)
}

// managedHookBinary is the binary an organization package installs and every
// machine-wide hook names (a build seam for end-to-end runs).
var managedHookBinary = claudemanaged.DefaultKontextBinary

// managedHookDropIn, when set, replaces Claude's machine-wide drop-in in the
// check below (a build seam for end-to-end runs).
var managedHookDropIn string

// packageHooks reads the package's machine-wide Claude hooks: in place when
// they name its binary, gone when the file is missing (package removal deletes
// it first), unclear otherwise.
func packageHooks() (inPlace, gone bool) {
	path := managedHookDropIn
	if path == "" {
		path = managedSettingsDropInPath
	}
	if privacyfolder.Guarded("", path) {
		return false, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, errors.Is(err, os.ErrNotExist)
	}
	binary, ok := claudemanaged.ManagedObserveHookBinary(raw)
	return ok && binary == managedHookBinary, false
}

// hookHealer gates on the config source, not on file paths, and on the stable
// binary every hook names: Homebrew's for self-serve, the package's otherwise.
// It returns nil when the daemon must leave hook files alone; the healer
// reports whether it changed one.
func hookHealer(loaded managedconfig.LoadedConfig, log diagnostic.Logger) func() bool {
	if runtime.GOOS != "darwin" {
		return nil
	}
	selfServe := loaded.Scope == managedconfig.ScopeUser
	scope, binary, label := hookinstall.System, managedHookBinary, "managed hooks"
	if selfServe {
		brew, _, ok := currentExecutableBrewPath()
		if !ok {
			return nil
		}
		scope, binary, label = hookinstall.User, filepath.Join(filepath.Dir(brew), "kontext"), "self-serve hooks"
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return nil
	}
	lastErr := ""
	report := func(err error) {
		if msg := fmt.Sprint(err); err != nil && msg != lastErr {
			logAlways(log, "%s: %v\n", label, err)
		}
		lastErr = fmt.Sprint(err)
	}
	return func() bool {
		current, loadErr := managedconfig.Load()
		// The package is being removed: it deleted its machine-wide hooks
		// first, and may delete its config next. The user's hooks go too, and
		// only this daemon, running as the user, touches them; root never does.
		remove := false
		if !selfServe && (loadErr != nil || current.Scope != managedconfig.ScopeUser) {
			inPlace, gone := packageHooks()
			if !inPlace && !gone {
				return false
			}
			remove = gone
		}
		if !remove {
			// A config of the other kind installed while this daemon runs takes
			// over; the daemon it starts heals from then on.
			if loadErr != nil || (current.Scope == managedconfig.ScopeUser) != selfServe {
				return false
			}
			// After an upgrade replaces the binary this process is the old
			// version; it restarts, and the new one installs its hooks.
			if !runningStableBinary(binary) {
				return false
			}
		}
		apply, verb := hookinstall.Install, "installed"
		if remove {
			apply, verb = hookinstall.Remove, "removed"
		}
		defs, err := hookinstall.SetupDefinitions(scope, home)
		if err != nil {
			report(err)
			return false
		}
		var guarded, changed []string
		var errs []error
		// One pass per agent: a broken file of one agent must not stop the
		// repair of another.
		for _, def := range defs {
			err := apply(hookinstall.Options{
				// At system scope PerUser keeps the daemon to the user's files: the
				// package's machine-wide files already run Claude Code, Codex and
				// Cursor hooks, and a user copy would run each twice.
				Scope: scope, PerUser: !selfServe, Home: home, Binary: binary, NoBackup: true, SetupPaths: true,
				SkipAgent: func(agent string) bool { return agentAbsent(home, agent) },
				Skip: func(file hookinstall.File) bool {
					if !slices.Contains(def.Files, file) {
						return true
					}
					// The daemon lacks the terminal's folder access: following a
					// settings symlink into ~/Documents would prompt in the background.
					if privacyfolder.Guarded(home, file.Path) {
						guarded = append(guarded, file.Path)
						return true
					}
					return false
				},
				Report: func(r hookinstall.Result) {
					if r.Action != "skip" && r.Err == nil {
						changed = append(changed, r.File.Path)
					}
				},
			})
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(changed) > 0 {
			logAlways(log, "%s: %s %s\n", label, verb, strings.Join(changed, ", "))
		}
		if len(guarded) > 0 {
			hint := ""
			if selfServe {
				hint = "; run `kontext hooks install --scope user` in a terminal"
			}
			errs = append(errs, fmt.Errorf("skipped %s in a macOS privacy-guarded folder%s", strings.Join(guarded, ", "), hint))
		}
		report(errors.Join(errs...))
		return len(changed) > 0
	}
}

// hookFilesFingerprint covers the content of every hook file either scope can
// install (a file that turns unreadable counts too), plus every machine-wide
// Claude source, whose hooks and disableAllHooks count too. It never touches a
// path in a macOS privacy-guarded folder: from the background that would ask
// the user for folder access.
func hookFilesFingerprint() string {
	home, _ := os.UserHomeDir()
	var b strings.Builder
	add := func(path string) {
		if privacyfolder.Guarded(home, path) {
			return
		}
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		fmt.Fprintf(&b, "%s:%x:%v;", path, sha256.Sum256(data), err)
	}
	// The user copy mirrors the handlers of every machine-wide Claude source.
	for _, path := range claudemanaged.MachineSettingsFiles(managedSettingsDropInPath, managedSettingsFilePath) {
		add(path)
	}
	// The files the healer writes and, under a valid CODEX_HOME, the ones the
	// explicit hooks command writes; an invalid CODEX_HOME hides neither.
	seen := map[string]bool{}
	for _, scope := range []hookinstall.Scope{hookinstall.User, hookinstall.System} {
		for _, list := range []func(hookinstall.Scope, string) ([]hookinstall.Definition, error){hookinstall.SetupDefinitions, hookinstall.Definitions} {
			defs, _ := list(scope, home)
			for _, def := range defs {
				for _, file := range def.Files {
					if !seen[file.Path] {
						seen[file.Path] = true
						add(file.Path)
					}
				}
			}
		}
	}
	return b.String()
}
