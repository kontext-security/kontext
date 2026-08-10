package setup

import (
	"errors"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// target is the installation slot a setup run writes: one profile's config,
// identity, and keychain item, or the legacy unprofiled slot on a machine that
// has never used profiles.
//
// Keeping the three paths together in one resolved value is deliberate. They
// must agree — a config naming a keychain item that setup wrote under a
// different name is exactly the silent failure mode that only shows up later,
// under launchd, as "daemon: not running".
type target struct {
	// Profile is "" for the legacy unprofiled slot.
	Profile      string
	ConfigPath   string
	IdentityPath string
	KeychainItem string
}

func (t target) label() string {
	if t.Profile == "" {
		return "default (unprofiled)"
	}
	return t.Profile
}

// resolveTarget picks the slot to write.
//
// An explicit name always targets that profile, creating its directory if
// needed — this is what `kontext profile add` uses. An empty name follows the
// active pointer when one exists, so a plain `kontext setup` re-run rotates the
// token of whichever profile is currently active; with no pointer it resolves
// the legacy paths, so a machine that predates profiles behaves exactly as it
// always has.
func resolveTarget(name string) (target, error) {
	if name != "" {
		if err := profile.ValidateName(name); err != nil {
			return target{}, err
		}
		return profileTarget(name)
	}

	active, err := profile.ActiveName()
	switch {
	case err == nil:
		return profileTarget(active)
	case errors.Is(err, profile.ErrNoActive):
		return legacyTarget()
	default:
		return target{}, err
	}
}

// targetSnapshot records what was true about the write target when it was
// resolved, so that a concurrent `kontext profile` command moving that state is
// caught BEFORE this run writes through it.
//
// Resolving the target once removes the divergence between the duplicate guard
// and the write, but a target is only a set of paths: `profile rename` can move
// the directory those paths name, and `profile rm` can delete it. Writing
// afterwards would recreate a profile under a name the user had just renamed
// away, and rotate a token into a keychain item nothing points at.
//
// There is no lock between kontext invocations — an interactive setup holds the
// terminal across a token prompt and a sudo prompt, so holding one would block
// the menu bar app's `profile use` for as long as someone leaves the prompt
// sitting there. This is optimistic instead: it does not prevent the
// interleaving, it refuses to write through it. A refusal that says what
// happened and can be retried beats a stray profile nobody notices.
type targetSnapshot struct {
	profile    string
	fromActive bool
	active     string
	existed    bool
}

func snapshotTarget(profileName string, fromActive bool) (targetSnapshot, error) {
	snapshot := targetSnapshot{profile: profileName, fromActive: fromActive}
	if profileName == "" {
		// The legacy unprofiled slot: no profile state exists to be moved.
		return snapshot, nil
	}
	exists, err := profile.Exists(profileName)
	if err != nil {
		return snapshot, err
	}
	snapshot.existed = exists
	if fromActive {
		active, err := profile.ActiveName()
		if err != nil && !errors.Is(err, profile.ErrNoActive) {
			return snapshot, err
		}
		snapshot.active = active
	}
	return snapshot, nil
}

// confirm reports whether the target still means what it did when resolved.
func (s targetSnapshot) confirm() error {
	if s.profile == "" {
		return nil
	}
	if s.fromActive {
		active, err := profile.ActiveName()
		if err != nil && !errors.Is(err, profile.ErrNoActive) {
			return err
		}
		if active != s.active {
			return fmt.Errorf(
				"the active profile changed from %q to %q while setup was running, so nothing was written; re-run the command",
				s.active, active)
		}
	}
	// Only meaningful when it existed at resolution: a run that is CREATING a
	// profile legitimately finds nothing here.
	if s.existed {
		exists, err := profile.Exists(s.profile)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf(
				"profile %q was renamed or removed while setup was running, so nothing was written; re-run the command",
				s.profile)
		}
	}
	return nil
}

func profileTarget(name string) (target, error) {
	if _, err := profile.Dir(name); err != nil {
		return target{}, err
	}
	configPath, err := profile.ManagedConfigPath(name)
	if err != nil {
		return target{}, err
	}
	identityPath, err := profile.InstallationPath(name)
	if err != nil {
		return target{}, err
	}
	item := profile.KeychainItemName(name)
	if item == "" {
		return target{}, fmt.Errorf("cannot derive a keychain item name for profile %q", name)
	}
	return target{
		Profile:      name,
		ConfigPath:   configPath,
		IdentityPath: identityPath,
		KeychainItem: item,
	}, nil
}

func legacyTarget() (target, error) {
	configPath := managedconfig.LegacyUserPath()
	if configPath == "" {
		return target{}, errors.New("cannot resolve your home directory")
	}
	identityPath := installation.LegacyUserPath()
	if identityPath == "" {
		return target{}, errors.New("cannot resolve your home directory")
	}
	return target{
		ConfigPath:   configPath,
		IdentityPath: identityPath,
		KeychainItem: KeychainItemName,
	}, nil
}
