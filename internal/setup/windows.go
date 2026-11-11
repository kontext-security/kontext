package setup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext/internal/autostart"
	"github.com/kontext-security/kontext/internal/credstore"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

// WindowsCredentialName is the entry in the user's Windows credential store
// that holds the install key of a self-serve setup.
const WindowsCredentialName = "kontext-install-token"

// windowsDaemonName is the daemon's program beside the CLI: the same code
// built without a console window, so starting it at sign-in shows nothing.
const windowsDaemonName = "kontextw.exe"

// Seams: the parts of the Windows flow that touch the user's session.
var (
	storeWindowsToken   = credstore.Write
	deleteWindowsToken  = credstore.Delete
	setWindowsAutostart = autostart.Set
	delWindowsAutostart = autostart.Remove
	startWindowsDaemon  = startDetached
	installWindowsHooks = hookinstall.Install
	removeWindowsHooks  = hookinstall.Remove
	userHome            = os.UserHomeDir
	// stopWindowsDaemon ends the user's running daemon, found through its
	// status file; no daemon is not an error.
	stopWindowsDaemon = func() error {
		status := managedobserve.LoadDaemonStatus(managedobserve.DefaultDBPath())
		if status == nil || status.PID <= 0 {
			return nil
		}
		return stopProcess(status.PID)
	}
)

// runWindows is setup for one user of a Windows machine, without administrator
// rights: the key goes into the user's credential store, the config into the
// user's state folder, Claude Code's user hooks are written, and the daemon
// starts now and at every sign-in. Profiles are not available here yet, and
// only Claude Code is hooked (hookinstall skips the other agents on Windows).
func runWindows(ctx context.Context, opts Options) (retErr error) {
	if opts.Profile != "" || opts.DeriveProfileName {
		return errors.New("profiles are not available on Windows yet; run `kontext setup` without one")
	}
	// A machine-wide install wins over a user's (managedconfig.ResolvePath),
	// so setting one up beside it would write a config nothing reads.
	if _, err := os.Lstat(systemConfigPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("this machine is managed by your organization (%s): Kontext is already installed for every user, and a setup of your own would not be used", systemConfigPath)
	}
	binary, _ := StableBinaryPath()
	daemon := filepath.Join(filepath.Dir(binary), windowsDaemonName)
	if info, err := os.Stat(daemon); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is missing beside %s: the background agent ships with the CLI, so this install is incomplete", windowsDaemonName, binary)
	}
	home, err := userHome()
	if err != nil {
		return fmt.Errorf("cannot resolve your home directory: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "Kontext setup")

	cloudURL := strings.TrimSpace(opts.CloudURL)
	if cloudURL == "" {
		cloudURL = CloudURL()
	}
	if err := managedconfig.ValidateCloudURL(cloudURL, opts.AllowHTTPLoopback); err != nil {
		return err
	}
	token, err := acquireToken(opts)
	if err != nil {
		return err
	}
	slot, err := legacyTarget()
	if err != nil {
		return err
	}
	slot.KeychainItem, slot.TokenSource = WindowsCredentialName, "credential"

	fmt.Fprintln(opts.Stdout, "\nWorkspace")
	identity, err := installation.EnsureFile(slot.IdentityPath)
	if err != nil {
		return fmt.Errorf("create the installation identity: %w", err)
	}
	bound, err := ValidateToken(ctx, opts.HTTPClient, cloudURL, token, identity.InstallationID)
	if err != nil {
		return err
	}
	workspace := bound.OrganizationName
	if workspace == "" {
		workspace = bound.OrganizationID
	}
	if bound.UserEmail != "" {
		fmt.Fprintf(opts.Stdout, "  ✓ Connected to %s as %s\n", workspace, bound.UserEmail)
	} else {
		fmt.Fprintf(opts.Stdout, "  ✓ Connected to %s (workspace key, no person attached)\n", workspace)
	}

	// From here on the run writes. On a first install, what it wrote is
	// taken back if a later step fails, so a failed setup leaves no
	// half-installed agent behind. Over an existing install nothing is taken
	// back: its key, config, hooks and sign-in entry were there before this
	// run and are what keeps the machine connected.
	_, statErr := os.Stat(slot.ConfigPath)
	firstInstall := errors.Is(statErr, os.ErrNotExist)
	var undo []func()
	defer func() {
		if retErr == nil || !firstInstall {
			return
		}
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}()

	fmt.Fprintln(opts.Stdout, "\nThis PC")
	if err := storeWindowsToken(WindowsCredentialName, token); err != nil {
		if errors.Is(err, credstore.ErrNoLogonSession) {
			return errors.New("this session has no Windows credential store, so the install key can't be kept: run `kontext setup` in a desktop session, not over SSH with a key")
		}
		return fmt.Errorf("store the install key: %w", err)
	}
	undo = append(undo, func() { _ = deleteWindowsToken(WindowsCredentialName) })
	fmt.Fprintln(opts.Stdout, "  ✓ Install key stored in Windows Credential Manager")

	configPath, err := writeUserManagedConfig(slot, cloudURL, deviceLabelWindows(), opts.AllowHTTPLoopback)
	if err != nil {
		return fmt.Errorf("write the config: %w", err)
	}
	undo = append(undo, func() { _ = os.Remove(configPath) })
	fmt.Fprintf(opts.Stdout, "  ✓ Config written: %s\n", configPath)

	hooks := hookinstall.Options{Scope: hookinstall.User, Home: home, Binary: binary, Out: opts.Stdout}
	if err := installWindowsHooks(hooks); err != nil {
		return fmt.Errorf("install the Claude Code hooks: %w", err)
	}
	undo = append(undo, func() { _ = removeWindowsHooks(hooks) })

	if err := setWindowsAutostart(daemon); err != nil {
		return fmt.Errorf("register the background agent to start at sign-in: %w", err)
	}
	undo = append(undo, func() { _ = delWindowsAutostart() })
	// Over an existing install the old daemon still holds the old key and the
	// socket, and a second one would give way to it: end it first.
	if !firstInstall {
		if err := stopWindowsDaemon(); err != nil {
			return fmt.Errorf("stop the running background agent: %w", err)
		}
	}
	if err := startWindowsDaemon(daemon, "managed-observe-daemon"); err != nil {
		return fmt.Errorf("start the background agent: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "  ✓ Background agent starts at sign-in")
	// The install is in place and the daemon is starting. One that is slow to
	// answer is no reason to take its key and config away under it.
	undo = nil
	if err := waitForDaemon(ctx, opts.Stdout); err != nil {
		return fmt.Errorf("setup is written, but the background agent has not answered yet: %w; `kontext doctor` shows its state", err)
	}

	fmt.Fprintln(opts.Stdout, "\nNext")
	fmt.Fprintln(opts.Stdout, "  Return to the Kontext dashboard.")
	fmt.Fprintln(opts.Stdout, "  Run the hello command shown there to confirm this PC is connected.")
	return nil
}

func deviceLabelWindows() string {
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

// uninstallWindows takes back what runWindows wrote for this user: the
// sign-in entry, the running daemon, Claude Code's user hooks, the key in the
// credential store and the config. Every step tolerates what is already
// gone, so it can be run again.
//
// Kept: the installation identity, so a later setup reports the same endpoint
// (on Windows a machine-wide install uses the same file, which is one more
// reason to leave it); the local records; the programs.
func uninstallWindows(_ context.Context, opts Options) error {
	slot, err := legacyTarget()
	if err != nil {
		return err
	}
	home, err := userHome()
	if err != nil {
		return fmt.Errorf("cannot resolve your home directory: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "Kontext uninstall")
	if _, err := os.Lstat(systemConfigPath); err == nil {
		fmt.Fprintf(opts.Stderr, "This machine is also managed by your organization (%s); that install stays and keeps reporting.\n", systemConfigPath)
	}

	// The key first: a session without a credential store can't remove it,
	// and then nothing else is taken away either.
	switch err := deleteWindowsToken(WindowsCredentialName); {
	case err == nil:
		fmt.Fprintln(opts.Stdout, "  ✓ Install key removed from Windows Credential Manager")
	case errors.Is(err, credstore.ErrNotFound):
	case errors.Is(err, credstore.ErrNoLogonSession):
		return errors.New("this session has no Windows credential store, so the install key can't be removed: run `kontext setup --uninstall` in a desktop session, not over SSH with a key")
	default:
		return fmt.Errorf("remove the install key: %w", err)
	}

	if err := delWindowsAutostart(); err != nil {
		return fmt.Errorf("remove the sign-in entry: %w", err)
	}
	fmt.Fprintln(opts.Stdout, "  ✓ Background agent no longer starts at sign-in")
	// Only a user install's daemon is ours to end; a machine-wide install runs
	// its own for this user.
	if _, err := os.Stat(slot.ConfigPath); err == nil {
		if err := stopWindowsDaemon(); err != nil {
			return fmt.Errorf("stop the background agent: %w", err)
		}
		fmt.Fprintln(opts.Stdout, "  ✓ Background agent stopped")
	}
	binary, _ := StableBinaryPath()
	if err := removeWindowsHooks(hookinstall.Options{Scope: hookinstall.User, Home: home, Binary: binary, Out: opts.Stdout}); err != nil {
		return fmt.Errorf("remove the Claude Code hooks: %w", err)
	}
	if err := os.Remove(slot.ConfigPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the config: %w", err)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Config removed: %s\n", slot.ConfigPath)

	fmt.Fprintln(opts.Stdout, "\nKept")
	if _, err := os.Lstat(slot.IdentityPath); err == nil {
		fmt.Fprintf(opts.Stdout, "  • Installation identity (%s)\n", slot.IdentityPath)
	}
	fmt.Fprintf(opts.Stdout, "  • Local records and logs under %s\n", filepath.Dir(slot.ConfigPath))
	fmt.Fprintln(opts.Stdout, "  • The kontext programs")
	return nil
}
