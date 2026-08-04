package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// Test seam (repo convention, cf. execCommand and dialSocket). Migration's
// rollback only matters when a move fails partway, which is unreachable through
// the filesystem without contriving an unmovable file.
var renameFn = os.Rename

// MigrateLegacyInstall converts a pre-profile self-serve install into the
// "default" profile and points the active pointer at it. It reports whether
// anything was migrated.
//
// The migration MOVES state rather than copying it. That is the point: after it
// runs, the legacy paths are empty, so any code still resolving them fails
// closed instead of quietly operating on a stale copy of the config while the
// daemon uses the profile's.
//
// The install token is not touched. The legacy config already names the
// unsuffixed keychain item and keeps naming it, so no keychain write — and no
// keychain prompt — happens here.
//
// The daemon is stopped for the duration: it holds the ledger database open,
// and moving that database under a live writer is precisely what must not
// happen. The agent is restarted on every exit path, including failure.
func MigrateLegacyInstall(ctx context.Context, out io.Writer) (migrated bool, err error) {
	// An active pointer means profiles are already in use. Nothing to do, and
	// re-running must be harmless.
	if _, activeErr := profile.ActiveName(); activeErr == nil {
		return false, nil
	} else if !errors.Is(activeErr, profile.ErrNoActive) {
		return false, activeErr
	}

	legacyConfig := managedconfig.LegacyUserPath()
	if legacyConfig == "" {
		return false, errors.New("cannot resolve your home directory")
	}
	legacyRoot := filepath.Dir(legacyConfig)

	present, err := legacyEntriesPresent(legacyRoot)
	if err != nil {
		return false, err
	}
	if len(present) == 0 {
		// Nothing installed the old way — a fresh machine, or one already
		// cleaned up. The caller creates its profile from scratch.
		return false, nil
	}

	// A default/ directory with no pointer at it is a state this code never
	// produces. Merging into it could silently pair one workspace's config with
	// another's ledger, so refuse and let a human look.
	if exists, err := profile.Exists(profile.DefaultName); err != nil {
		return false, err
	} else if exists {
		dir, _ := profile.Dir(profile.DefaultName)
		return false, fmt.Errorf("profile %q already exists (%s) but no profile is active; move or remove it, then retry", profile.DefaultName, dir)
	}

	if err := StopLaunchAgent(ctx); err != nil {
		return false, fmt.Errorf("stop the background agent before migrating: %w", err)
	}
	defer func() {
		// Restart on every path. A failed migration that also left the agent
		// down would take observability with it.
		if restartErr := BootstrapLaunchAgent(ctx); restartErr != nil && err == nil {
			err = fmt.Errorf("migrated, but the background agent did not restart: %w", restartErr)
		}
	}()

	dir, err := profile.Create(profile.DefaultName)
	if err != nil {
		return false, err
	}

	// Everything below can fail partway. A half-migrated install is the worst
	// outcome available: state split across both layouts, the daemon unable to
	// find its config, and every retry refused because profiles/default now
	// exists. So each move is undone on failure, leaving the machine exactly as it
	// was and the retry clean.
	var undo []func() error
	rollback := func(cause error) error {
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil {
				// Both problems matter: the original failure and the fact that the
				// automatic repair could not finish.
				return fmt.Errorf("%w (and rolling back failed: %v — state is split between %s and %s, repair by hand)",
					cause, err, legacyRoot, dir)
			}
		}
		if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w (rolled back, but %s could not be removed: %v)", cause, dir, err)
		}
		return fmt.Errorf("%w (rolled back; nothing was migrated)", cause)
	}

	move := func(from, to string) error {
		if err := renameFn(from, to); err != nil {
			return err
		}
		undo = append(undo, func() error { return renameFn(to, from) })
		return nil
	}

	// Hoist the cached model weights to the shared root BEFORE moving the ledger
	// directory that currently contains them. They are machine-scoped and can be
	// hundreds of megabytes; left inside the profile they would be stranded where
	// nothing looks for them, and the next profile would re-download them.
	if err := hoistSharedModelCache(legacyRoot, out, move); err != nil {
		return false, rollback(err)
	}

	for _, name := range present {
		from := filepath.Join(legacyRoot, name)
		to := filepath.Join(dir, name)
		if err := move(from, to); err != nil {
			return false, rollback(fmt.Errorf("move %s into profile %q: %w", name, profile.DefaultName, err))
		}
		if out != nil {
			fmt.Fprintf(out, "  ✓ Moved %s into profile %q\n", name, profile.DefaultName)
		}
	}

	if err := profile.SetActive(profile.DefaultName); err != nil {
		return false, rollback(fmt.Errorf("point the active profile at %q: %w", profile.DefaultName, err))
	}
	if out != nil {
		fmt.Fprintf(out, "  ✓ Active profile is now %q (%s)\n", profile.DefaultName, dir)
	}
	return true, nil
}

// hoistSharedModelCache moves <root>/managed-observe/judge-models up to
// <root>/judge-models, which is where the shared (machine-scoped) resolution
// looks for it once a profile is active.
//
// Absent cache is the common case and not an error — the guardrail LLM is
// optional. An existing destination is left alone rather than merged: two caches
// are self-healing (the loser is re-downloaded on demand), whereas interleaving
// two sets of partially-downloaded weights is not.
// move is injected so the hoist participates in the caller's rollback: if a
// later step fails, this relocation is undone too.
func hoistSharedModelCache(legacyRoot string, out io.Writer, move func(from, to string) error) error {
	from := filepath.Join(legacyRoot, profile.ManagedObserveDir, profile.ModelCacheDirName)
	info, err := os.Lstat(from)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if !info.IsDir() {
		return nil
	}
	to := filepath.Join(legacyRoot, profile.ModelCacheDirName)
	if _, err := os.Lstat(to); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := move(from, to); err != nil {
		return fmt.Errorf("move the model cache to %s: %w", to, err)
	}
	if out != nil {
		fmt.Fprintf(out, "  ✓ Moved %s to the shared root (kept for every profile)\n", profile.ModelCacheDirName)
	}
	return nil
}

// legacyEntriesPresent returns the migratable entries that actually exist under
// the legacy root, in MigratedEntries order. A partially-installed machine
// migrates whatever it has rather than refusing.
func legacyEntriesPresent(root string) ([]string, error) {
	var present []string
	for _, name := range profile.MigratedEntries {
		_, err := os.Lstat(filepath.Join(root, name))
		if err == nil {
			present = append(present, name)
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return nil, err
	}
	return present, nil
}
