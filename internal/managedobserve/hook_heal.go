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

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

const hookWatchInterval = time.Minute

// runHookWatch keeps the agent scan current when hook files change, so the
// dashboard does not wait for the next periodic scan. For a self-serve config
// it also keeps the user's hook files complete: it restores removed entries and
// adds a newly supported agent's hooks after an upgrade, never asking for an
// administrator because every file is in the user's home. Organization-managed
// configs are watched only; their packages own the machine-wide files.
func runHookWatch(ctx context.Context, loaded managedconfig.LoadedConfig, log diagnostic.Logger, rescan func()) {
	heal := selfServeHookHealer(loaded, log)
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
			return
		case <-ticker.C:
		}
	}
}

// selfServeHookHealer gates on the config source, not on file paths, and on a
// Homebrew binary, the stable path every hook names. It returns nil when the
// daemon must leave hook files alone; the healer reports whether it changed one.
func selfServeHookHealer(loaded managedconfig.LoadedConfig, log diagnostic.Logger) func() bool {
	if runtime.GOOS != "darwin" || loaded.Scope != managedconfig.ScopeUser {
		return nil
	}
	brew, _, ok := currentExecutableBrewPath()
	if !ok {
		return nil
	}
	binary := filepath.Join(filepath.Dir(brew), "kontext")
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	lastErr := ""
	report := func(err error) {
		if msg := fmt.Sprint(err); err != nil && msg != lastErr {
			logAlways(log, "self-serve hooks: %v\n", err)
		}
		lastErr = fmt.Sprint(err)
	}
	return func() bool {
		// An organization config installed while this daemon runs takes over;
		// from then on its package owns the hooks.
		if current, err := managedconfig.Load(); err != nil || current.Scope != managedconfig.ScopeUser {
			return false
		}
		// After Homebrew retargets the symlink this process is the old version;
		// the binary watchdog restarts it, and the new one installs its hooks.
		exe, err := executablePath()
		if err != nil {
			return false
		}
		running, err := os.Stat(exe)
		if err != nil {
			return false
		}
		if installed, err := os.Stat(binary); err != nil || !os.SameFile(running, installed) {
			return false
		}
		var guarded, changed []string
		var errs []error
		// One pass per agent: a broken file of one agent must not stop the
		// repair of another.
		for _, kinds := range [][]string{{"claude-user"}, {"codex", "feature"}, {"cursor"}} {
			err := hookinstall.Install(hookinstall.Options{
				Scope: hookinstall.User, Home: home, Binary: binary, NoBackup: true, SetupPaths: true,
				Skip: func(file hookinstall.File) bool {
					if !slices.Contains(kinds, file.Kind) {
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
			logAlways(log, "self-serve hooks: installed %s\n", strings.Join(changed, ", "))
		}
		if len(guarded) > 0 {
			errs = append(errs, fmt.Errorf("skipped %s in a macOS privacy-guarded folder; run `kontext hooks install --scope user` in a terminal", strings.Join(guarded, ", ")))
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
	for _, scope := range []hookinstall.Scope{hookinstall.User, hookinstall.System} {
		// The files the healer writes; a relative CODEX_HOME cannot hide them.
		defs, err := hookinstall.SetupDefinitions(scope, home)
		if err != nil {
			continue
		}
		for _, def := range defs {
			for _, file := range def.Files {
				add(file.Path)
			}
		}
	}
	return b.String()
}
