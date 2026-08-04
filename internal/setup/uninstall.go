package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/codexmanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
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

	if organizationManaged {
		fmt.Fprintf(opts.Stdout, "  • Kept Claude Code managed hooks because an organization-managed install is active (%s)\n", managedSettingsPath)
	} else {
		removed, err := removeManagedSettings(ctx)
		if err != nil {
			return err
		}
		if removed {
			fmt.Fprintf(opts.Stdout, "  ✓ Claude Code managed hooks removed (%s)\n", managedSettingsPath)
		} else {
			fmt.Fprintf(opts.Stdout, "  • Kept Claude Code managed hooks because ownership is unknown (%s)\n", managedSettingsPath)
		}
	}

	settingsPath, err := userSettingsPathNoCreate()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(settingsPath); errors.Is(err, os.ErrNotExist) {
		// A removal must never CREATE settings: on a machine without Claude
		// settings (or after the user deleted them) there is nothing to do.
		fmt.Fprintln(opts.Stdout, "  • No Claude Code settings file; no hooks to remove")
	} else if err != nil {
		return err
	} else {
		settings, err := claudemanaged.ReadUserSettings(settingsPath)
		if err != nil {
			return err
		}
		if err := claudemanaged.BackupUserSettings(settingsPath, settingsBackupLabel); err != nil {
			return err
		}
		if err := claudemanaged.RemoveManagedHooks(settings); err != nil {
			return err
		}
		if err := claudemanaged.WriteUserSettings(settingsPath, settings); err != nil {
			return err
		}
		fmt.Fprintln(opts.Stdout, "  ✓ Claude Code hooks removed from ~/.claude/settings.json")
	}

	removedCodexHooks, err := removeCodexUserHooks()
	if err != nil {
		fmt.Fprintf(opts.Stderr, "warning: Codex hooks could not be removed from ~/.codex/hooks.json (%v)\n", err)
	} else if removedCodexHooks {
		fmt.Fprintln(opts.Stdout, "✓ Codex hooks removed from ~/.codex/hooks.json")
	} else {
		fmt.Fprintln(opts.Stdout, "  • No Codex hooks file; no hooks to remove")
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

func removeCodexUserHooks() (bool, error) {
	codexHooksPath, err := codexmanaged.UserHooksPathNoCreate()
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(codexHooksPath); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	settings, err := codexmanaged.ReadHooks(codexHooksPath)
	if err != nil {
		return false, err
	}
	if err := codexmanaged.BackupHooks(codexHooksPath, settingsBackupLabel); err != nil {
		return false, err
	}
	if err := codexmanaged.RemoveManagedHooks(settings); err != nil {
		return false, err
	}
	if err := codexmanaged.WriteHooks(codexHooksPath, settings); err != nil {
		return false, err
	}
	return true, nil
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

// removeManagedSettings removes the drop-in only when it is ours by content
// (mirroring setup's ownership check), so uninstall never deletes an enterprise
// or foreign managed-settings file. Returns whether the file was removed.
func removeManagedSettings(ctx context.Context) (bool, error) {
	existing, err := os.ReadFile(managedSettingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if !claudemanaged.IsManagedSettingsDropIn(existing) {
		return false, nil
	}
	if geteuid() == 0 {
		if err := os.Remove(managedSettingsPath); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		return true, nil
	}
	if err := runPrivilegedCommand(ctx, "sudo", "rm", "-f", managedSettingsPath); err != nil {
		return false, fmt.Errorf("remove Claude managed settings: %w", err)
	}
	return true, nil
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
	return filepath.Join(home, ".claude", "settings.json"), nil
}
