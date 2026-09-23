package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/profile"
)

// This receipt is shared across profiles, just like Claude's hook file. Save
// the attempt before opening a dialog so a crash or cancelled prompt cannot
// cause a password prompt on every launchd restart.
type hookMigrationState struct {
	Version   string `json:"version"`
	Status    string `json:"status"`
	Digest    string `json:"expected_sha256,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

type hookMigration struct {
	version, binary, hooksPath, statePath string
	canPrompt                             func() bool
	refresh                               func(context.Context, string) error
}

func runSelfServeHookMigration(ctx context.Context, loaded managedconfig.LoadedConfig, version string, log diagnostic.Logger) {
	// Development binaries, custom installations and MDM are not package
	// upgrades. Only the self-serve Homebrew LaunchAgent owns this migration.
	if runtime.GOOS != "darwin" || loaded.Scope != managedconfig.ScopeUser || version == "" || version == "dev" {
		return
	}
	root := profile.Root()
	if !filepath.IsAbs(root) {
		return
	}
	brew, ok := currentExecutableBrewPath()
	if !ok {
		return
	}
	binary := filepath.Join(filepath.Dir(brew), "kontext")
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Never migrate using an old process after Homebrew retargeted its symlink.
	running, err := os.Stat(exe)
	if err != nil {
		return
	}
	installed, err := os.Stat(binary)
	if err != nil || !os.SameFile(running, installed) {
		return
	}
	for _, path := range []string{managedconfig.DefaultPath, claudemanaged.ManagedSettingsPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return
		}
	}
	m := hookMigration{
		version: version, binary: binary, hooksPath: claudemanaged.ManagedSettingsDropInPath,
		statePath: filepath.Join(root, "hook-migration.json"), canPrompt: hookMigrationCanPrompt,
		refresh: func(ctx context.Context, digest string) error {
			return approveClaudeHookMigration(ctx, exe, binary, digest)
		},
	}
	if err := m.run(ctx); err != nil {
		logAlways(log, "Claude hook migration pending: %v; daemon continues running\n", err)
	}
}

func (m hookMigration) run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0700); err != nil {
		return err
	}
	var state hookMigrationState
	prompt := false
	err := managedconfig.WithWriteLock(m.statePath, func() error {
		data, err := os.ReadFile(m.statePath)
		if err == nil {
			if err := json.Unmarshal(data, &state); err != nil {
				// A damaged receipt must not reset the prompt guard.
				return fmt.Errorf("read hook migration receipt: %w", err)
			}
			if state.Version == "" || (state.Status != "complete" && state.Status != "pending" && state.Status != "awaiting_login") {
				return errors.New("invalid hook migration receipt; refusing to reset the approval guard")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if state.Version == m.version && state.Status != "awaiting_login" {
			return nil
		}
		if state.Version != m.version {
			state = hookMigrationState{Version: m.version, Status: "complete"}
			digest, err := hookinstall.ClaudeRefreshDigest(m.hooksPath, m.binary)
			if err != nil {
				state.Status, state.LastError = "pending", err.Error()
			} else if digest != "" {
				state.Status, state.Digest = "awaiting_login", digest
			}
		}
		if state.Status == "awaiting_login" && m.canPrompt() {
			state.Status = "pending"
			state.LastError = "administrator approval has not completed"
			prompt = true
		}
		return writeJSONBreadcrumb(m.statePath, state)
	})
	if err != nil {
		return err
	}
	if !prompt {
		if state.LastError != "" {
			return errors.New(state.LastError)
		}
		return nil
	}
	// Run after the hook socket is serving, with a bounded lifetime. Cancelling
	// approval never stops the daemon or clears the existing hook configuration.
	promptCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	refreshErr := m.refresh(promptCtx, state.Digest)
	if refreshErr == nil {
		var digest string
		digest, refreshErr = hookinstall.ClaudeRefreshDigest(m.hooksPath, m.binary)
		if refreshErr == nil && digest != "" {
			refreshErr = errors.New("hook installation did not satisfy this version's requirements")
		}
	}
	if refreshErr != nil {
		state.LastError = refreshErr.Error()
	} else {
		state.Status, state.LastError = "complete", ""
	}
	err = managedconfig.WithWriteLock(m.statePath, func() error {
		// A different version may have started while approval was outstanding.
		data, err := os.ReadFile(m.statePath)
		if err != nil {
			return err
		}
		var current hookMigrationState
		if err := json.Unmarshal(data, &current); err != nil {
			return err
		}
		if current.Version != m.version {
			return nil
		}
		return writeJSONBreadcrumb(m.statePath, state)
	})
	return errors.Join(refreshErr, err)
}

// AppleScript and the shell each have their own quoting rules. The generated
// script contains no credentials; macOS owns the authentication UI.
func appleScriptString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`).Replace(s) + `"`
}

func claudeHookApprovalScript(executable, binary, digest string) string {
	args := []string{executable, "hooks", "refresh-claude", "--binary", binary, "--expected-sha256", digest}
	for i := range args {
		args[i] = agenthooks.ShellQuote(args[i])
	}
	return "do shell script " + appleScriptString(strings.Join(args, " ")) +
		" with administrator privileges with prompt " + appleScriptString("Kontext needs to update its Claude integration after an upgrade.")
}
