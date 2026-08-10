package setup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// SwitchTimeout bounds the wait for the restarted daemon to come back.
const SwitchTimeout = 15 * time.Second

// Test seams (repo convention), so switch tests never wait on — or depend on —
// a real daemon on this machine.
var (
	waitForDaemonRestart = managedobserve.WaitForDaemonRestart
	daemonLive           = managedobserve.DaemonLive
)

// Activate points this Mac at a different profile.
//
// The daemon is RESTARTED rather than signalled to reload, and that is not
// laziness. Only part of its configuration is re-read at runtime: the export
// stream re-reads cloud URL and token on every flush tick, but the Cedar policy
// client and the endpoint-config client are constructed once at startup from
// the config's cloud URL. A config-only switch would therefore leave policy
// decisions being made against the OLD backend while events streamed to the
// new one — the worst possible split.
//
// Order matters. The target is validated before anything is written, so a
// failed switch leaves the previous profile active and serving.
func Activate(ctx context.Context, name string, out, errOut io.Writer) error {
	if goos != "darwin" {
		return errors.New("kontext profiles are currently macOS-only")
	}
	if err := profile.ValidateName(name); err != nil {
		return err
	}
	exists, err := profile.Exists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s (run `kontext profile add %s` first)", profile.ErrNotFound, name, name)
	}

	current, err := profile.ActiveName()
	if err != nil && !errors.Is(err, profile.ErrNoActive) {
		return err
	}
	if current == name {
		// Not simply a no-op. A switch whose BootstrapLaunchAgent failed leaves the
		// pointer moved and the agent stopped, and re-running `profile use <name>`
		// is exactly what someone does next — so this has to be a repair path, or
		// the obvious retry reports success while the Mac stays unobserved.
		return ensureAgentRunning(ctx, name, out, errOut)
	}

	// Validate the destination BEFORE touching the pointer: switching to a
	// profile whose config is unparseable or whose token cannot be read would
	// trade a working install for a broken one.
	if err := verifyProfileUsable(ctx, name); err != nil {
		return err
	}

	if err := StopLaunchAgent(ctx); err != nil {
		return fmt.Errorf("stop the background agent: %w", err)
	}
	if err := profile.SetActive(name); err != nil {
		// Bring the old daemon back rather than leaving the Mac unobserved.
		if restartErr := BootstrapLaunchAgent(ctx); restartErr != nil {
			return fmt.Errorf("%w (and the background agent did not restart: %v)", err, restartErr)
		}
		return err
	}
	if err := BootstrapLaunchAgent(ctx); err != nil {
		return fmt.Errorf("switched to %q, but the background agent did not restart: %w", name, err)
	}

	fmt.Fprintf(out, "Active profile: %s\n", name)

	// The daemon now resolves this profile's database, so wait on THAT path.
	return waitForSwitchedDaemon(ctx, name, out, errOut)
}

// ensureAgentRunning is `profile use <the already-active profile>`: verify the
// profile is serviceable and that the background agent is actually up, starting
// it if it is not.
//
// This is the recovery path for a switch that re-pointed the profile and then
// failed to start the agent. Without it, the natural retry short-circuits on
// "already active" and reports success over a stopped daemon.
func ensureAgentRunning(ctx context.Context, name string, out, errOut io.Writer) error {
	if err := verifyProfileUsable(ctx, name); err != nil {
		return err
	}

	// A reachable socket is NOT proof that our agent is running. An unrelated
	// daemon — a leftover from an enterprise install, or a hand-started one —
	// binds the same path, and trusting reachability alone reports a healthy
	// agent while nothing of ours is installed. The plist is the thing that says
	// this machine has a self-serve agent at all, and only `kontext setup`
	// writes it, so a missing one is reported rather than silently tolerated.
	plistPath, err := launchAgentPath()
	if err != nil {
		return err
	}
	installed, err := regularFileExists(plistPath)
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("profile %q is active, but no background agent is installed (%s); run `kontext setup` to install it", name, plistPath)
	}

	// Not merely "something answers the socket". The socket path is shared, so a
	// foreign daemon — an enterprise leftover, or one started by hand — answers
	// it too, and treating that as our agent would report a healthy install while
	// the intended one stays stopped. DaemonLive additionally requires the status
	// breadcrumb beside THIS profile's database to name a live process.
	dbPath, err := profile.DBPath(name)
	if err != nil {
		return err
	}
	if daemonLive(dbPath, managedobserve.DefaultSocketPath()) {
		fmt.Fprintf(out, "Profile %q is already active; background agent is running.\n", name)
		return nil
	}

	fmt.Fprintf(out, "Profile %q is already active, but the background agent is not running. Starting it.\n", name)
	// Bootstrap alone fails when launchd still has the job loaded but the process
	// is dead, so take the same stop-then-start path a switch does.
	if err := StopLaunchAgent(ctx); err != nil {
		return fmt.Errorf("stop the background agent before restarting it: %w", err)
	}
	if err := BootstrapLaunchAgent(ctx); err != nil {
		return fmt.Errorf("the background agent did not start: %w", err)
	}
	return waitForSwitchedDaemon(ctx, name, out, errOut)
}

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.Mode().IsRegular(), nil
}

// waitForSwitchedDaemon reports whether the restarted daemon came back, against
// the ACTIVE profile's database — the breadcrumb it writes lives beside it.
func waitForSwitchedDaemon(ctx context.Context, name string, out, errOut io.Writer) error {
	waitCtx, cancel := context.WithTimeout(ctx, SwitchTimeout)
	defer cancel()
	dbPath, err := profile.DBPath(name)
	if err != nil {
		return err
	}
	status, err := waitForDaemonRestart(waitCtx, dbPath, managedobserve.DefaultSocketPath(), "")
	if err != nil {
		fmt.Fprintf(errOut, "warning: the background agent has not come back within %s; run `kontext doctor` and check ~/Library/Logs/Kontext/managed-observe.log\n", SwitchTimeout)
		return nil
	}
	fmt.Fprintf(out, "Background agent running (v%s, pid %d)\n", status.Version, status.PID)
	return nil
}

// RemoveProfile deletes a profile's local state and its keychain item.
//
// The active profile is refused (by profile.Remove) so a machine is never left
// with a pointer aimed at nothing — switch away first. The directory goes before
// the keychain item: if the keychain step then fails, what is left behind is an
// orphaned credential the error names, rather than a profile whose config
// references a token that no longer exists.
func RemoveProfile(ctx context.Context, name string, out io.Writer) error {
	if err := profile.ValidateName(name); err != nil {
		return err
	}
	exists, err := profile.Exists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", profile.ErrNotFound, name)
	}
	dir, err := profile.Dir(name)
	if err != nil {
		return err
	}
	// Collect the keychain items BEFORE deleting the directory: the authoritative
	// one is the ref recorded in the profile's own config, which is unreadable
	// afterwards. A profile that was renamed, or migrated from a pre-profile
	// install, has a ref that does NOT match its name — deriving the item from the
	// name alone would leave that workspace's token behind in the keychain.
	items, configReadable := keychainItemsForProfile(name)

	if err := profile.Remove(name); err != nil {
		return err
	}
	fmt.Fprintf(out, "  ✓ Removed profile data (%s)\n", dir)

	if len(items) == 0 {
		return fmt.Errorf("cannot determine the keychain item for profile %q", name)
	}
	for _, item := range items {
		if err := deleteKeychainTokens(ctx, item); err != nil {
			return fmt.Errorf("profile data removed, but its keychain item %q could not be deleted: %w", item, err)
		}
		fmt.Fprintf(out, "  ✓ Removed install token from your keychain (%s)\n", item)
	}
	if !configReadable {
		fmt.Fprintf(out, "  ! %s had no readable config, so its token reference is unknown.\n", name)
		fmt.Fprintf(out, "    If it was renamed, a token may remain under its former name — check Keychain Access for items starting %q.\n", profile.LegacyKeychainItemName())
	}
	return nil
}

// keychainItemsForProfile returns every keychain item that could hold this
// profile's token: the ref its config actually names, plus the name-derived
// convention. Both, deduplicated, because an orphaned credential is worse than a
// redundant delete of an item that does not exist.
// The second return reports whether the profile's config could be read. It
// matters: a profile whose ref does NOT match its name — renamed, or migrated —
// keeps its real token under the old name, and if the config is missing or
// corrupt that name is unrecoverable. Deleting only the name-derived item and
// reporting success would then leave a workspace token in the keychain with
// nothing left pointing at it. Callers say so instead.
func keychainItemsForProfile(name string) (items []string, configReadable bool) {
	seen := map[string]bool{}
	add := func(item string) {
		if item == "" || seen[item] {
			return
		}
		seen[item] = true
		items = append(items, item)
	}

	configPath, err := profile.ManagedConfigPath(name)
	if err == nil {
		loaded, loadErr := managedconfig.LoadFile(configPath)
		if loadErr == nil {
			configReadable = true
			ref := loaded.Config.Credentials.InstallTokenRef
			if ref.Source == "keychain" {
				add(ref.Name)
			}
		}
	}
	add(profile.KeychainItemName(name))
	return items, configReadable
}

// verifyProfileUsable checks the two things that make a profile serviceable:
// a config the daemon's own parser accepts, and a token its own read path can
// resolve. Both failures are otherwise invisible until the daemon dies under
// launchd with nothing but "not running" to show for it.
func verifyProfileUsable(ctx context.Context, name string) error {
	configPath, err := profile.ManagedConfigPath(name)
	if err != nil {
		return err
	}
	loaded, err := managedconfig.LoadFile(configPath)
	if err != nil {
		if errors.Is(err, managedconfig.ErrNotManaged) {
			return fmt.Errorf("profile %q has no config yet (%s); run `kontext profile add %s` to finish setting it up", name, configPath, name)
		}
		return fmt.Errorf("profile %q has an unusable config (%s): %w", name, configPath, err)
	}
	tokenCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := resolveToken(tokenCtx, loaded.Config.Credentials.InstallTokenRef); err != nil {
		return fmt.Errorf("profile %q install token is not readable (%s): %w\n\nUnlock your login keychain, or re-run `kontext profile add %s` with a fresh token", name, loaded.Config.Credentials.InstallTokenRef, err, name)
	}
	return nil
}
