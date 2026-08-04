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
