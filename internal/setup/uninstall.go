package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/profile"
)

// Uninstall reverses Run in reverse order. Every step tolerates
// already-removed state so a partially-failed uninstall can simply be re-run.
//
// Deliberately KEPT:
//   - installation.json — it holds only the random ins_* device identity; a
//     later re-setup then reports the same endpoint to the dashboard instead
//     of spawning a phantom second device.
//   - local data (guard.db, stream state) and logs — they are the user's
//     records; locations are printed instead.
//   - the binary — brew owns it (`brew uninstall kontext`).
func Uninstall(ctx context.Context, opts Options) error {
	if goos != "darwin" {
		return errors.New("kontext setup is currently macOS-only")
	}

	organizationManaged, err := organizationManagedInstall()
	if err != nil {
		return err
	}
	if organizationManaged {
		fmt.Fprintln(opts.Stderr, organizationManagedMessage("Self-serve uninstall cannot remove organization-managed state."))
	}

	fmt.Fprintln(opts.Stdout, "Kontext uninstall")
	fmt.Fprintln(opts.Stdout, "\nMac")

	if organizationManaged {
		removed, path, err := removeSelfServeLaunchAgentIfPresent(ctx)
		if err != nil {
			return err
		}
		if removed {
			fmt.Fprintf(opts.Stdout, "  ✓ Self-serve background agent removed (%s)\n", path)
		} else {
			fmt.Fprintf(opts.Stdout, "  • No self-serve background agent to remove (%s)\n", path)
		}
	} else {
		plistPath, err := removeLaunchAgent(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(opts.Stdout, "  ✓ Background agent removed (%s)\n", plistPath)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := hookinstall.Remove(hookinstall.Options{
		Scope: hookinstall.User, Home: home, Setup: true, ClaudePath: managedSettingsPath, CursorPath: cursorHooksPath,
		Report: func(r hookinstall.Result) {
			switch r.File.Kind {
			case "codex":
				if r.Err != nil {
					fmt.Fprintf(opts.Stderr, "warning: Codex hooks could not be removed from ~/.codex/hooks.json (%v)\n", r.Err)
				} else if r.Reason == "absent" {
					fmt.Fprintln(opts.Stdout, "  • No Codex hooks file; no hooks to remove")
				} else {
					fmt.Fprintln(opts.Stdout, "  ✓ Codex hooks removed from ~/.codex/hooks.json")
				}
			case "cursor":
				switch {
				case r.Err != nil:
					fmt.Fprintf(opts.Stderr, "warning: Cursor hooks could not be removed from %s (%v)\n", r.File.Path, r.Err)
				case r.Action == "remove" || r.Action == "write":
					fmt.Fprintf(opts.Stdout, "  ✓ Cursor hooks removed (%s)\n", r.File.Path)
				default:
					fmt.Fprintf(opts.Stdout, "  • No Cursor hooks to remove (%s)\n", r.File.Path)
				}
			case "claude-user":
				if r.Err != nil {
					fmt.Fprintf(opts.Stderr, "warning: Claude Code hooks could not be removed from %s (%v)\n", r.File.Path, r.Err)
				} else if r.Action == "write" {
					fmt.Fprintf(opts.Stdout, "  ✓ Claude Code hooks removed from %s\n", r.File.Path)
				} else {
					fmt.Fprintf(opts.Stdout, "  • No Claude Code hooks to remove (%s)\n", r.File.Path)
				}
			}
		},
	}); err != nil {
		return err
	}
	// Uninstall never asks for a password. Machine-wide hooks an earlier setup
	// wrote stay until the user removes them; an organization install keeps its own.
	if !organizationManaged && legacyMachineHooks() {
		fmt.Fprintln(opts.Stdout, "  • Machine-wide hooks from an earlier setup remain. Remove them with: sudo kontext hooks remove --scope system")
	}

	// Every profile's token, not just the active one: leaving another
	// workspace's credential in the keychain after an uninstall would be a
	// quiet surprise.
	items, unreadable, err := deleteAllInstallTokens(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Install tokens removed from your keychain (%s)\n", strings.Join(items, ", "))
	// Claiming complete cleanup while a token survives is worse than an
	// incomplete uninstall: nothing would ever point at it again.
	if len(unreadable) > 0 {
		fmt.Fprintf(opts.Stderr, "warning: could not read the config for %s, so their token references are unknown.\n", strings.Join(unreadable, ", "))
		fmt.Fprintf(opts.Stderr, "         A renamed profile keeps its token under its FORMER name — check Keychain Access for items starting %q and remove any that remain.\n", profile.LegacyKeychainItemName())
	}

	configPaths, err := allManagedConfigPaths()
	if err != nil {
		return err
	}
	for _, path := range configPaths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Fprintf(opts.Stdout, "  ✓ Managed config removed (%s)\n", path)
	}

	// Clearing the pointer last returns path resolution to the legacy paths, so
	// a re-run of uninstall (or a later plain `kontext setup`) is predictable.
	if err := profile.ClearActive(); err != nil {
		return err
	}

	fmt.Fprintln(opts.Stdout, "\nKept")
	for _, identity := range allInstallationPaths() {
		if _, err := os.Lstat(identity); err == nil {
			fmt.Fprintf(opts.Stdout, "  • Installation identity (%s)\n", identity)
		}
	}
	fmt.Fprintln(opts.Stdout, "  • Local observe data and logs under ~/Library/Application Support/Kontext and ~/Library/Logs/Kontext")
	fmt.Fprintln(opts.Stdout, "  • Homebrew-owned kontext binary (`brew uninstall kontext`)")
	return nil
}

// allManagedConfigPaths lists every self-serve config on this Mac — the legacy
// unprofiled one and one per profile. Uninstall removes the installation, not
// just the profile that happened to be active.
func allManagedConfigPaths() ([]string, error) {
	var paths []string
	if legacy := managedconfig.LegacyUserPath(); legacy != "" {
		paths = append(paths, legacy)
	}
	names, err := profile.List()
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		path, err := profile.ManagedConfigPath(name)
		if err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}

// allInstallationPaths mirrors allManagedConfigPaths for the identities that
// uninstall deliberately keeps, so the printed "Kept" list names each one a
// later re-setup would reuse. A profile whose name no longer validates is
// skipped rather than reported.
func allInstallationPaths() []string {
	var paths []string
	if legacy := installation.LegacyUserPath(); legacy != "" {
		paths = append(paths, legacy)
	}
	names, err := profile.List()
	if err != nil {
		return paths
	}
	for _, name := range names {
		if path, err := profile.InstallationPath(name); err == nil {
			paths = append(paths, path)
		}
	}
	return paths
}

func removeSelfServeLaunchAgentIfPresent(ctx context.Context) (bool, string, error) {
	plistPath, err := launchAgentPath()
	if err != nil {
		return false, "", err
	}
	if _, err := os.Lstat(plistPath); errors.Is(err, os.ErrNotExist) {
		return false, plistPath, nil
	} else if err != nil {
		return false, plistPath, err
	}
	path, err := removeLaunchAgent(ctx)
	return err == nil, path, err
}

// legacyMachineHooks reports Kontext-owned machine-wide hooks: the Claude
// drop-in or Cursor's machine-wide file that earlier setups wrote with sudo.
func legacyMachineHooks() bool {
	if raw, err := os.ReadFile(managedSettingsPath); err == nil && claudemanaged.IsManagedSettingsDropIn(raw) {
		return true
	}
	var settings struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	raw, err := os.ReadFile(cursorHooksPath)
	if err != nil || json.Unmarshal(raw, &settings) != nil {
		return false
	}
	for _, entries := range settings.Hooks {
		for _, entry := range entries {
			if cursormanaged.IsManagedHookCommand(entry.Command) {
				return true
			}
		}
	}
	return false
}

func organizationManagedInstall() (bool, error) {
	if _, err := os.Lstat(systemConfigPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	if _, err := managedconfig.LoadFile(systemConfigPath); err != nil {
		return false, fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	return true, nil
}

func userSettingsPathNoCreate() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return claudemanaged.UserSettingsPathNoCreate(home)
}
