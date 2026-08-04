package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

// RenameProfile moves a profile's state to a new name, keeping it active if it
// was active.
//
// The keychain is deliberately untouched. A profile's install token is located by
// the ref recorded IN its config, not by its directory name, so a renamed profile
// keeps resolving the same item — no keychain write, and therefore no
// authorization prompt, for what is otherwise a directory move. The next token
// rotation through `profile add` rewrites the ref to match the new name.
//
// This exists because `profile migrate` has to name the migrated profile
// something before it can know what the install pointed at, and "default" is a
// poor description of, say, a staging endpoint.
func RenameProfile(ctx context.Context, oldName, newName string, out io.Writer) (err error) {
	if err := profile.ValidateName(oldName); err != nil {
		return fmt.Errorf("current name: %w", err)
	}
	if err := profile.ValidateName(newName); err != nil {
		return fmt.Errorf("new name: %w", err)
	}
	if oldName == newName {
		fmt.Fprintf(out, "Profile is already named %q.\n", newName)
		return nil
	}

	exists, err := profile.Exists(oldName)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", profile.ErrNotFound, oldName)
	}
	taken, err := profile.Exists(newName)
	if err != nil {
		return err
	}
	if taken {
		return fmt.Errorf("%w: %s", profile.ErrExists, newName)
	}

	active, err := profile.ActiveName()
	if err != nil && !errors.Is(err, profile.ErrNoActive) {
		return err
	}
	renamingActive := active == oldName

	from, err := profile.Dir(oldName)
	if err != nil {
		return err
	}
	to, err := profile.Dir(newName)
	if err != nil {
		return err
	}

	// Only the active profile's rename involves the daemon: its resolved config
	// and database paths are about to change underneath it. Renaming an inactive
	// profile touches nothing the daemon is reading, so it stays untouched — no
	// reason to interrupt observability for a directory move.
	if renamingActive {
		if goos != "darwin" {
			return errors.New("renaming the active profile is currently macOS-only")
		}
		if err := StopLaunchAgent(ctx); err != nil {
			return fmt.Errorf("stop the background agent before renaming the active profile: %w", err)
		}
		defer func() {
			if restartErr := BootstrapLaunchAgent(ctx); restartErr != nil && err == nil {
				err = fmt.Errorf("renamed, but the background agent did not restart: %w", restartErr)
			}
		}()
	}

	if err := os.Rename(from, to); err != nil {
		return fmt.Errorf("move profile %q to %q: %w", oldName, newName, err)
	}
	fmt.Fprintf(out, "  ✓ Renamed %q to %q\n", oldName, newName)

	// Re-point AFTER the move: a pointer naming a directory that does not exist
	// yet is a window in which nothing resolves.
	if renamingActive {
		if err := profile.SetActive(newName); err != nil {
			return fmt.Errorf("profile moved to %q but the active pointer still names %q: %w", newName, oldName, err)
		}
		fmt.Fprintf(out, "  ✓ Active profile is now %q\n", newName)
	}
	return nil
}
