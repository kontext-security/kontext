// Package setup implements `kontext setup`: connecting a single Mac to a
// Kontext organization without MDM. It produces the same managed-observe
// pipeline as an enterprise package install — managed config, installation
// identity, agent hooks, LaunchAgent running the daemon — but at user scope
// (~/Library, ~/.claude, ~/.codex) with the install token in the login keychain.
package setup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/buildinfo"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/cursormanaged"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/ledgerping"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/internal/profile"
)

const (
	DefaultCloudURL = "https://api.kontext.security"

	// KeychainItemName is the generic-password service name. It MUST stay in
	// lockstep with the managed.json token ref below: the daemon reads the
	// token with `security find-generic-password -s <name> -w`.
	KeychainItemName = "kontext-install-token"
	keychainAccount  = "kontext"

	settingsBackupLabel = "kontext-setup"
)

var errPersonalKeyBoundElsewhere = errors.New("this setup command was already used on another Mac; copy a fresh one from Get started in the dashboard")

// Test seams (repo convention, cf. update.go's brewUpgradeFn). All external
// process and terminal interactions go through these so tests never touch
// launchctl/security/scutil or a real TTY.
var (
	agentWiring = func() map[string]func() agentinventory.Wired {
		return managedobserve.AgentWiring(managedconfig.ScopeUser)
	}
	execCommand = func(ctx context.Context, stdin string, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	readPassword = func(fd int) ([]byte, error) {
		return term.ReadPassword(fd)
	}
	runPrivilegedCommand = func(ctx context.Context, name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	isTerminal = func(fd int) bool {
		return term.IsTerminal(fd)
	}
	readLine = func(r io.Reader) (string, error) {
		return bufio.NewReader(r).ReadString('\n')
	}
	executablePath = os.Executable
	geteuid        = os.Geteuid
	resolveToken   = managedconfig.ResolveInstallToken
	dialSocket     = func(path string, timeout time.Duration) error {
		conn, err := net.DialTimeout("unix", path, timeout)
		if err != nil {
			return err
		}
		return conn.Close()
	}
	// Seam so a test can move the active profile at the one instant that used to
	// matter: between the duplicate check and the write.
	boundProfileLookup  = profileBoundToWorkspace
	systemConfigPath    = managedconfig.DefaultPath
	orgInstallTokenPath = managedconfig.InstallTokenFilePath
	managedSettingsPath = claudemanaged.ManagedSettingsDropInPath
	managedSettingsFile = claudemanaged.ManagedSettingsPath
	cursorHooksPath     = cursormanaged.SystemHooksPath
	goos                = runtime.GOOS
)

type Options struct {
	Token    string
	CloudURL string
	Version  string
	Stdout   io.Writer
	Stderr   io.Writer
	// Profile names the installation slot to write. Empty follows the active
	// profile pointer, falling back to the legacy unprofiled paths on a machine
	// that has never used profiles — so a plain `kontext setup` keeps behaving
	// exactly as it did before profiles existed.
	Profile string
	// DeriveProfileName lets setup name the profile itself, from the environment
	// and the workspace the token resolves to. Only meaningful with an empty
	// Profile, and only for `profile add` — a plain `kontext setup` still targets
	// the active profile or the legacy paths.
	DeriveProfileName bool
	// OnProfileResolved reports the profile setup actually wrote. With
	// DeriveProfileName the caller cannot know the name in advance, and guessing
	// it afterwards from the profile list would be a race and a lie.
	OnProfileResolved func(name string)
	// TokenFromStdin reads the install token from standard input instead of
	// --token. A command-line argument is visible in `ps` to every process on the
	// machine for the duration of the call, so any caller that is not a human at a
	// terminal — a script, or a GUI shelling out — needs a way to pass a
	// credential that does not appear there.
	TokenFromStdin bool
	// AllowHTTPLoopback records, in the written config, that a plaintext http
	// cloud_url is intended — only ever honored for a loopback host. It is
	// persisted rather than taken from the environment because the background
	// agent does not inherit one.
	AllowHTTPLoopback bool
	// HTTPClient overrides the ping client (tests). Nil uses a 10s-timeout
	// default.
	HTTPClient *http.Client
}

// CloudURL returns the hosted API URL for install-token setup.
func CloudURL() string {
	if value := strings.TrimSpace(os.Getenv("KONTEXT_API_URL")); value != "" {
		return value
	}
	return DefaultCloudURL
}

// Run connects this Mac to the org owning the install token. Steps are
// ordered so every irreversible action happens after the token is proven
// valid, and re-running is always safe (token rotation restarts the agent).
func Run(ctx context.Context, opts Options) (retErr error) {
	if goos != "darwin" {
		return errors.New("kontext setup is currently macOS-only")
	}
	binary, binaryNote := StableBinaryPath()
	settingsData, err := managedSettingsData(binary)
	if err != nil {
		return err
	}
	fmt.Fprintln(opts.Stdout, "Kontext setup")

	if err := preflightCodexUserHooks(binary); err != nil {
		return err
	}
	if err := preflightClaudeUserHooks(binary); err != nil {
		return err
	}
	if err := preflightCursorHooks(binary, cursorUserHooksPath()); err != nil {
		return err
	}

	ok, err := prepareManagedEnvironment(ctx, opts, settingsData)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	cloudURL := strings.TrimSpace(opts.CloudURL)
	if cloudURL == "" {
		// Same env-aware default as the --cloud-url flag, so KONTEXT_API_URL
		// is honored even when the flag is explicitly emptied.
		cloudURL = CloudURL()
	}
	// Same rules the daemon's parser applies, so a bad --cloud-url fails
	// before any state is written.
	if err := managedconfig.ValidateCloudURL(cloudURL, opts.AllowHTTPLoopback); err != nil {
		return err
	}

	token, err := acquireToken(opts)
	if err != nil {
		return err
	}

	// Discover the workspace without binding: it determines the final profile.
	ping, err := ValidateToken(ctx, opts.HTTPClient, cloudURL, token, "")
	if err != nil {
		return err
	}
	orgLabel := ping.OrganizationID
	if ping.OrganizationName != "" {
		orgLabel = fmt.Sprintf("%s (%s)", ping.OrganizationName, ping.OrganizationID)
	}
	fmt.Fprintln(opts.Stdout, "\nWorkspace")

	// Never a SECOND profile for a workspace already bound on this backend. Two
	// profiles differing only by name would hold the same workspace's records in
	// two ledgers and present it two device identities — no purpose, and a
	// confusing thing to inherit. A named or deriving run refuses; a plain run
	// rotates the bound profile's token and switches to it instead.
	//
	// The check has to be here, not in a caller: the workspace is only known once
	// the hosted API answers, so nothing earlier can tell two tokens apart. It is
	// deliberately NOT "one profile per environment" — several workspaces on one
	// backend is exactly what workspaces are for.
	// The target is resolved BEFORE the guard, and exactly once: the profile
	// excluded from duplicate detection and the profile written to must be the
	// same one. Resolving the active pointer twice — once to exclude, once to
	// write — leaves a window in which a concurrent `kontext profile use` moves
	// it in between, so the guard clears profile A while the write lands on B.
	// The menu bar app switches profiles on a single click, which makes that
	// window reachable rather than theoretical.
	//
	// Resolving early writes nothing: a target is path arithmetic, and every
	// failure below still leaves the profile untouched.
	//
	// The derived case is the exception, and cannot be resolved yet: its name
	// comes from the workspace, which nothing knows until the hosted API answers.
	// It also needs no exclusion — that run creates a NEW profile, so every
	// existing one is a real candidate duplicate.
	var slot target
	var snapshot targetSnapshot
	deriving := opts.DeriveProfileName && opts.Profile == ""
	// plain is a bare `kontext setup`: no profile named, no derivation asked
	// for. It writes the active profile — the one target the caller did not
	// choose — so it is also the only mode allowed to RETARGET below instead of
	// writing a different workspace over whatever happens to be active.
	plain := opts.Profile == "" && !opts.DeriveProfileName
	// The profile to make active before the agent restarts. Set only when a
	// plain setup retargeted: whoever pasted this token wants THIS Mac reporting
	// to that token's workspace, and the daemon reads the active config.
	// activationBase records what was active when that decision was made, so a
	// `profile use` landing mid-run is detected rather than overwritten.
	var activate, activationBase string
	if !deriving {
		slot, err = resolveTarget(opts.Profile)
		if err != nil {
			return err
		}
		snapshot, err = snapshotTarget(slot.Profile, opts.Profile == "")
		if err != nil {
			return err
		}
	}

	duplicate, err := boundProfileLookup(ping.OrganizationID, cloudURL, slot.Profile)
	if err != nil {
		return err
	}
	switch {
	case duplicate != "" && !plain:
		// A second profile is another installation. Recognize reuse of the
		// existing personal key without binding a fresh key to a refused target.
		if ping.UserEmail != "" {
			stored, err := resolveToken(ctx, managedconfig.TokenRef{Source: "keychain", Name: profile.KeychainItemName(duplicate)})
			if err == nil && stored == token {
				return errPersonalKeyBoundElsewhere
			}
		}
		return fmt.Errorf(
			"workspace %s is already set up as profile %q on %s\n\nSwitch to it with `kontext profile use %s`, or remove it first to re-create it.",
			orgLabel, duplicate, cloudURL, duplicate)
	case duplicate != "":
		// A plain setup with a token for a workspace that already has a profile.
		// The token names the intent unambiguously — "connect this Mac to that
		// workspace" — so rotate THAT profile's token and switch to it. Erroring
		// here (as the named modes still do, where the mismatch between the name
		// given and the profile found needs a human) would only send the user off
		// to run the exact commands this run can perform.
		fmt.Fprintf(opts.Stdout, "  ✓ Already set up as profile %q — rotating its token and switching to it\n", duplicate)
		slot, err = resolveTarget(duplicate)
		if err != nil {
			return err
		}
		snapshot, err = snapshotTarget(duplicate, false)
		if err != nil {
			return err
		}
		activate = duplicate
	case plain && slot.Profile != "":
		// Writing the active profile is only right while the token belongs to the
		// workspace it is already bound to (a rotation). A token for anything
		// else must not overwrite that binding — that is a working workspace
		// silently destroyed, its token gone from the keychain — so the run
		// becomes an addition instead, as if `kontext profile add` had been
		// typed. The legacy unprofiled slot is exempt: it has no recorded
		// binding to compare, and pre-profile machines keep their old behavior.
		if reason := rebindReason(slot, cloudURL, ping.OrganizationID); reason != "" {
			fmt.Fprintf(opts.Stdout, "  • Active profile %q is bound to %s — leaving it untouched\n", slot.Profile, reason)
			profileName, err := DeriveProfileName(cloudURL, ping.OrganizationName, ping.OrganizationID)
			if err != nil {
				return err
			}
			fmt.Fprintf(opts.Stdout, "  ✓ Profile name: %s\n", profileName)
			slot, err = resolveTarget(profileName)
			if err != nil {
				return err
			}
			snapshot, err = snapshotTarget(profileName, false)
			if err != nil {
				return err
			}
			activate = profileName
		}
	}
	if activate != "" {
		activationBase, err = profile.ActiveName()
		if err != nil && !errors.Is(err, profile.ErrNoActive) {
			return err
		}
	}

	if deriving {
		profileName, err := DeriveProfileName(cloudURL, ping.OrganizationName, ping.OrganizationID)
		if err != nil {
			return err
		}
		fmt.Fprintf(opts.Stdout, "  ✓ Profile name: %s\n", profileName)
		slot, err = resolveTarget(profileName)
		if err != nil {
			return err
		}
		snapshot, err = snapshotTarget(slot.Profile, false)
		if err != nil {
			return err
		}
	}
	if opts.OnProfileResolved != nil {
		opts.OnProfileResolved(slot.Profile)
	}

	// Last point at which nothing has been written. Past here the target's
	// meaning is assumed, so a concurrent rename or removal must be caught now.
	if err := snapshot.confirm(); err != nil {
		return err
	}

	// An absent target is CLAIMED now, atomically, before the first write: the
	// mkdir either reserves the name or reports the concurrent creation that
	// confirm — a check, not a reservation — could still miss. A claim the run
	// then fails out of is removed again while still empty and still ours, so
	// a refused setup leaves no hollow profile behind and a replacement claim
	// by another process is never touched.
	if slot.Profile != "" && !snapshot.existed {
		release, err := claimTarget(slot.Profile)
		if err != nil {
			return err
		}
		defer func() { release(retErr != nil) }()
	}

	identityPath := slot.IdentityPath
	if identityPath == "" {
		return errors.New("cannot resolve your home directory")
	}
	identity, err := installation.EnsureFile(identityPath)
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}

	if slot.Profile != "" && opts.Profile == "" {
		defer func() {
			if retErr != nil {
				flags := ""
				if activate != "" {
					flags += " --use"
				}
				if opts.AllowHTTPLoopback {
					flags += " --allow-http-loopback"
				}
				fmt.Fprintf(opts.Stderr, "Retry with `kontext profile add %s --cloud-url '%s'%s` to reuse this installation identity.\n", slot.Profile, strings.ReplaceAll(cloudURL, "'", "'\"'\"'"), flags)
			}
		}()
	}

	// Keep this identity on failure: the server may have bound the key even if
	// its response was lost. A retry must present the same installation ID.
	bound, err := ValidateToken(ctx, opts.HTTPClient, cloudURL, token, identity.InstallationID)
	if err != nil {
		return err
	}
	if bound.OrganizationID != ping.OrganizationID {
		return errors.New("workspace changed during setup; rerun with a fresh command from Get started")
	}
	// The network request can outlive a profile switch, rename, or removal.
	// Newly claimed profiles are pinned; existing targets must be checked again.
	if snapshot.existed {
		if err := snapshot.confirm(); err != nil {
			return err
		}
	}
	currentIdentity, err := installation.LoadFile(identityPath)
	if err != nil || currentIdentity.InstallationID != identity.InstallationID {
		return errors.New("installation identity changed while setup was running; retry using the original profile")
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

	if err := writeKeychainToken(ctx, slot.KeychainItem, token); err != nil {
		return err
	}
	// Read back through the daemon's actual code path so a write/read
	// asymmetry fails HERE, not silently at the first flush under launchd.
	stored, err := resolveToken(ctx, managedconfig.TokenRef{Source: "keychain", Name: slot.KeychainItem})
	if err != nil {
		return fmt.Errorf("keychain read-back failed: %w", err)
	}
	if stored != token {
		return fmt.Errorf("keychain read-back returned a different token; remove stale %q keychain items and retry", slot.KeychainItem)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Token saved to Keychain (%s)\n", slot.KeychainItem)

	fmt.Fprintln(opts.Stdout, "\nMac")
	fmt.Fprintf(opts.Stdout, "  ✓ Installation identity ready (%s)\n", identity.InstallationID)

	// A named profile needs its directory before anything is written into it.
	// Create is idempotent here by construction: re-running setup for an
	// existing profile rotates its token rather than failing.
	if slot.Profile != "" {
		if exists, err := profile.Exists(slot.Profile); err != nil {
			return err
		} else if !exists {
			if _, err := profile.Create(slot.Profile); err != nil {
				return err
			}
		}
	}

	configPath, err := writeUserManagedConfig(slot, cloudURL, deviceLabel(ctx), opts.AllowHTTPLoopback)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Config written (%s)\n", configPath)

	// Cache the workspace label so listings can name the workspace instead of a
	// backend hostname. Failing here must not fail the setup — it is a display
	// convenience, and everything that governs behavior is already written.
	if slot.Profile != "" {
		workspace := Workspace{OrganizationID: ping.OrganizationID, OrganizationName: ping.OrganizationName}
		if err := writeWorkspace(slot.Profile, workspace); err != nil {
			fmt.Fprintf(opts.Stderr, "note: could not cache the workspace label for profile %q (%v); `kontext profile ls` will show the backend URL instead\n", slot.Profile, err)
		}
	}

	if binaryNote != "" {
		fmt.Fprintln(opts.Stderr, binaryNote)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	// Every hook file is in the user's home, so setup never asks for a password.
	codexHooks := ""
	if err := hookinstall.Install(hookinstall.Options{
		Scope: hookinstall.User, Home: home, Binary: binary, Setup: true, ClaudePath: managedSettingsPath, CursorPath: cursorHooksPath,
		Report: func(r hookinstall.Result) {
			switch r.File.Kind {
			case "claude-user":
				fmt.Fprintf(opts.Stdout, "  ✓ Claude Code hooks installed (%s)\n", r.File.Path)
				if raw, err := os.ReadFile(r.File.Path); err == nil && claudemanaged.DisablesAllHooks(raw) {
					fmt.Fprintf(opts.Stderr, "warning: disableAllHooks in %s switches Claude Code hooks off; remove it so Kontext can observe Claude Code.\n", r.File.Path)
				}
			case "codex":
				codexHooks = r.File.Path
				fmt.Fprintf(opts.Stdout, "  ✓ Codex hooks installed (%s)\n", r.File.Path)
			case "cursor":
				fmt.Fprintf(opts.Stdout, "  ✓ Cursor hooks installed (%s)\n", r.File.Path)
			case "feature":
				if r.Err != nil {
					fmt.Fprintf(opts.Stderr, "note: could not enable the Codex hooks feature automatically (%v); set `[features].hooks = true` in ~/.codex/config.toml or the hooks will not run.\n", r.Err)
				} else if r.Action == "write" {
					fmt.Fprintf(opts.Stdout, "  ✓ Codex hooks feature enabled ([features].hooks in %s)\n", r.File.Path)
				}
			}
		},
	}); err != nil {
		return err
	}
	if codexHooks != "" {
		// Codex runs a user hook only once it is trusted in the Codex CLI's /hooks.
		untrusted, err := codexmanaged.UntrustedHooks(codexHooks, filepath.Join(filepath.Dir(codexHooks), "config.toml"))
		if err != nil {
			fmt.Fprintf(opts.Stdout, "  • Codex: could not check whether you trust the Kontext hooks (%v). If Codex skips them, run `codex`, open /hooks and trust each Kontext hook\n", err)
		} else if len(untrusted) > 0 {
			fmt.Fprintln(opts.Stdout, codexTrustHint)
		}
	}
	if !hookinstall.CoworkGoverned(managedSettingsPath, managedSettingsFile) {
		fmt.Fprintln(opts.Stdout, "  • Cowork: not governed. Cowork reads only machine-wide Claude settings, which need an organization install")
	}
	if home, err := os.UserHomeDir(); err == nil {
		scanCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		inv := agentinventory.Scan(scanCtx, home, os.Getenv, time.Now(), agentinventory.ScanOptions{Wired: agentWiring()})
		cancel()
		fmt.Fprintf(opts.Stdout, "  ✓ Agent discovery: %s\n", summariseInventory(inv))
	}

	// The pointer moves BEFORE the agent is (re)installed: the daemon resolves
	// the active profile's config at startup, so this ordering makes the restart
	// below bring it up already serving the retargeted profile — one restart,
	// not a restart onto the old profile followed by a switch.
	//
	// Activation is one atomic compare-and-set: the pointer moves only if it
	// still reads what it read when retargeting was decided. A `kontext
	// profile use` landing anywhere in between — the menu bar app switches on
	// one click — is a choice someone just made, and it wins; the retargeted
	// profile is fully written either way, and the note says how to catch up.
	var restoreActive func() (bool, error)
	if activate != "" {
		switched, err := profile.CompareAndSetActive(activationBase, activate)
		if err != nil {
			return fmt.Errorf("switch the active profile to %q: %w", activate, err)
		}
		if !switched {
			current, err := profile.ActiveName()
			if err != nil && !errors.Is(err, profile.ErrNoActive) {
				return err
			}
			fmt.Fprintf(opts.Stderr, "note: the active profile changed to %q while setup was running, so it was left alone; switch with `kontext profile use %s`.\n", current, activate)
		} else {
			fmt.Fprintf(opts.Stdout, "  ✓ Active profile: %s\n", activate)
			// A run that FAILS below must not leave the Mac silently switched
			// as a side effect. The undo is the same compare-and-set in the
			// other direction: it puts the base back only while the pointer
			// still names OUR profile, never over a concurrent choice.
			restoreActive = func() (bool, error) {
				return profile.CompareAndSetActive(activate, activationBase)
			}
		}
	}

	var plistPath, logPath string
	err = runWithStatus(opts.Stdout, "Installing background agent", func() error {
		var err error
		plistPath, logPath, err = installLaunchAgent(ctx, binary)
		return err
	})
	if err != nil {
		if restoreActive != nil {
			// The run failed after moving the pointer. Put it back and try to
			// bring the agent up for the profile that was serving before —
			// the same "never leave the Mac switched or unobserved by a failed
			// run" contract a failed `profile use` keeps. Best-effort: the
			// error names whatever could not be undone.
			restored, restoreErr := restoreActive()
			if restoreErr != nil {
				return fmt.Errorf("%w\n\nThe active profile could not be restored afterwards (%v); run `kontext profile use` to pick one.", err, restoreErr)
			}
			if !restored {
				// Another process moved the pointer after our switch. Its
				// `profile use` also owns the agent's state now — restarting
				// here would race whatever it is doing.
				return fmt.Errorf("%w\n\nThe active profile was changed by another process while setup was running, so it was left alone.", err)
			}
			if _, _, restartErr := installLaunchAgent(ctx, binary); restartErr != nil {
				return fmt.Errorf("%w\n\nThe active profile was restored, but the background agent did not restart (%v); run `kontext profile use` to repair it.", err, restartErr)
			}
			return fmt.Errorf("%w\n\nThe active profile was restored and the background agent is running on it; nothing switched.", err)
		}
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Background agent installed (%s)\n", plistPath)

	if err := waitForDaemon(opts.Stdout); errors.Is(err, errDaemonNotRunning) {
		fmt.Fprintln(opts.Stdout, "  ! Background agent did not start")
		fmt.Fprintf(opts.Stderr, "warning: %v; check `tail -f %s`\n", err, logPath)
	} else if err != nil {
		fmt.Fprintf(opts.Stdout, "  • Background agent is still starting; `kontext doctor` shows when it runs (log: %s)\n", logPath)
	} else {
		fmt.Fprintln(opts.Stdout, "  ✓ Background agent running")
	}
	if buildinfo.HomebrewBuild() {
		fmt.Fprintln(opts.Stdout, "  • Updates: run `brew upgrade kontext`. For automatic updates, switch to the cask: brew uninstall --formula kontext && brew install --cask kontext-security/tap/kontext")
	}

	fmt.Fprintln(opts.Stdout, "\nNext")
	fmt.Fprintln(opts.Stdout, "  Return to the Kontext dashboard.")
	fmt.Fprintln(opts.Stdout, "  Run the hello command shown there to confirm this Mac is connected.")
	return nil
}

// prepareManagedEnvironment keeps self-serve setup away from machines that
// are silently organization-managed. In an interactive terminal, setup can
// remove the local enterprise state and continue; in non-interactive contexts,
// it refuses with copy-pasteable cleanup steps.
func prepareManagedEnvironment(ctx context.Context, opts Options, settingsData []byte) (bool, error) {
	// ANY env override means config resolution is explicitly env-driven —
	// even one pointing at the user path. Setup must not write state whose
	// activation depends on an environment variable it doesn't control.
	if strings.TrimSpace(os.Getenv(managedconfig.EnvPath)) != "" {
		return false, fmt.Errorf("%s is set; unset it before running setup", managedconfig.EnvPath)
	}
	if _, err := os.Lstat(systemConfigPath); err == nil {
		confirmed, err := confirmRemoveOrganizationManagedInstall(ctx, opts)
		if err != nil {
			return false, err
		}
		if !confirmed {
			return false, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("cannot determine whether this Mac is organization-managed: %w", err)
	}
	if err := refuseUnknownManagedSettingsOwner(settingsData); err != nil {
		return false, err
	}
	return true, nil
}

func confirmRemoveOrganizationManagedInstall(ctx context.Context, opts Options) (bool, error) {
	if !isTerminal(int(os.Stdin.Fd())) {
		return false, errors.New(organizationManagedMessage("Self-serve setup cannot continue because system config wins over user config."))
	}

	fmt.Fprintln(opts.Stdout, "\nMac")
	fmt.Fprintln(opts.Stdout, "  ! Organization-managed install detected")
	fmt.Fprintf(opts.Stdout, "  • System config: %s\n", systemConfigPath)
	fmt.Fprint(opts.Stdout, "  ? Remove organization-managed install and continue? [y/N] ")

	answer, err := readLine(os.Stdin)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		if err := removeOrganizationManagedInstall(ctx); err != nil {
			return false, err
		}
		fmt.Fprintln(opts.Stdout, "  ✓ Organization-managed files removed")
		fmt.Fprintln(opts.Stdout, "  ✓ Organization-managed background agent stopped")
		return true, nil
	default:
		fmt.Fprintln(opts.Stdout, "  • Nothing changed.")
		fmt.Fprintln(opts.Stdout, "\nNext")
		fmt.Fprintln(opts.Stdout, "  Remove the MDM profile or enterprise package that installed Kontext.")
		fmt.Fprintln(opts.Stdout, "  For local testing, remove the enterprise files and run setup again.")
		return false, nil
	}
}

func removeOrganizationManagedInstall(ctx context.Context) error {
	removeRootSettings, err := ownedRootManagedSettingsExists()
	if err != nil {
		return err
	}
	paths := []string{systemConfigPath, orgInstallTokenPath}
	if removeRootSettings {
		paths = append(paths, managedSettingsFile)
	}
	if err := removeOrganizationManagedFiles(ctx, paths...); err != nil {
		return err
	}

	serviceTarget := "gui/" + strconv.Itoa(os.Getuid()) + "/" + LaunchAgentLabel
	out, err := execCommand(ctx, "", "launchctl", "bootout", serviceTarget)
	if err != nil && !managedobserve.LaunchctlPrintMeansAbsent(out) {
		return fmt.Errorf("stop organization-managed background agent: launchctl bootout failed: %w (%s)", err, strings.TrimSpace(out))
	}
	return nil
}

func ownedRootManagedSettingsExists() (bool, error) {
	data, err := os.ReadFile(managedSettingsFile)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot determine Claude root managed settings ownership: %w", err)
	}
	if !claudemanaged.IsManagedSettingsDropIn(data) {
		return false, fmt.Errorf("Claude Code root managed settings already exist\n\nManaged settings\n  %s\n\nSelf-serve setup cannot continue because root managed settings may contain organization or foreign hooks.\nNothing changed.", managedSettingsFile)
	}
	return true, nil
}

func removeOrganizationManagedFiles(ctx context.Context, paths ...string) error {
	if geteuid() == 0 {
		for _, path := range paths {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove organization-managed file %s: %w", path, err)
			}
		}
		return nil
	}

	args := append([]string{"rm", "-f"}, paths...)
	if err := runPrivilegedCommand(ctx, "sudo", args...); err != nil {
		return fmt.Errorf("remove organization-managed files: %w", err)
	}
	return nil
}

func refuseUnknownManagedSettingsOwner(_ []byte) error {
	if _, err := os.Lstat(managedSettingsFile); err == nil {
		return fmt.Errorf("Claude Code root managed settings already exist\n\nManaged settings\n  %s\n\nSelf-serve setup cannot continue because root managed settings may contain organization or foreign hooks.\nNothing changed.", managedSettingsFile)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot determine Claude root managed settings ownership: %w", err)
	}
	existing, err := os.ReadFile(managedSettingsPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot determine Claude managed hooks ownership: %w", err)
	}
	// Ours by content (alias-matched, binary-path-agnostic) → safe to refresh,
	// even if an older self-serve run baked in a now-stale binary path. Anything
	// else (enterprise, a foreign installer) we must not overwrite.
	if !claudemanaged.IsManagedSettingsDropIn(existing) {
		return fmt.Errorf("Claude Code managed hooks already exist\n\nManaged hooks\n  %s\n\nSelf-serve setup cannot continue because hook ownership is unknown.\nNothing changed.", managedSettingsPath)
	}
	return nil
}

func organizationManagedMessage(reason string) string {
	return fmt.Sprintf(`Organization-managed install detected

Mac
  ! %s
  • System config: %s
  • Nothing changed.

Remove the organization-managed install first:
  1. Remove the MDM profile or enterprise package that installed Kontext.
  2. For local testing, clean the enterprise files:
     sudo rm -f "/Library/Application Support/Kontext/managed.json"
     sudo rm -f "/Library/Application Support/Kontext/install-token"
     sudo rm -f "/Library/Application Support/ClaudeCode/managed-settings.json"
     launchctl bootout gui/$(id -u)/%s 2>/dev/null || true
  3. Run self-serve setup again.`, reason, systemConfigPath, LaunchAgentLabel)
}

// acquireToken never mutates the input: a token containing whitespace fails
// loudly instead of being silently trimmed into something the user didn't
// paste — the stored credential must be byte-identical to the dashboard's.
func acquireToken(opts Options) (string, error) {
	if opts.Token != "" {
		return opts.Token, validateTokenShape(opts.Token)
	}
	if opts.TokenFromStdin {
		raw, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read token from stdin: %w", err)
		}
		// Trim only the surrounding whitespace a pipe or heredoc adds; anything
		// inside is the caller's problem and validateTokenShape reports it.
		token := strings.TrimSpace(string(raw))
		if token == "" {
			return "", errors.New("no install token on stdin")
		}
		return token, validateTokenShape(token)
	}
	fd := int(os.Stdin.Fd())
	if !isTerminal(fd) {
		return "", errors.New("no install token: pass --token in non-interactive environments")
	}
	fmt.Fprint(opts.Stderr, "Paste your install token (from the Kontext dashboard, shown once at creation): ")
	raw, err := readPassword(fd)
	fmt.Fprintln(opts.Stderr)
	if err != nil {
		return "", fmt.Errorf("read token: %w", err)
	}
	token := string(raw)
	if token == "" {
		return "", errors.New("no install token entered")
	}
	return token, validateTokenShape(token)
}

// validateTokenShape rejects whitespace and control characters — same rule
// the enterprise install script enforces. Besides catching mangled paste
// input early, it guarantees the token can never smuggle a second line into
// the `security -i` command stream.
func validateTokenShape(token string) error {
	for _, r := range token {
		if r <= ' ' || r == 0x7f {
			return errors.New("install token must not contain whitespace or control characters")
		}
	}
	return nil
}

// ValidateToken delegates the wire work to ledgerping — the daemon resolves
// tokens through the same call, so the two cannot drift — and keeps only the
// user-facing errors shared by setup and whoami.
func ValidateToken(ctx context.Context, client *http.Client, cloudURL, token, installationID string) (ledgerping.Response, error) {
	ping, err := ledgerping.Ping(ctx, client, cloudURL, token, installationID)
	if err != nil {
		if errors.Is(err, ledgerping.ErrUnauthorized) {
			return ledgerping.Response{}, errors.New("install token was rejected — it may be revoked or mistyped; create a new one in the dashboard under Settings → API keys")
		}
		if errors.Is(err, ledgerping.ErrBoundElsewhere) {
			return ledgerping.Response{}, errPersonalKeyBoundElsewhere
		}
		if errors.Is(err, ledgerping.ErrExpired) {
			return ledgerping.Response{}, errors.New("this setup command has expired; copy a fresh one from Get started in the dashboard")
		}
		var status *ledgerping.StatusError
		if errors.As(err, &status) {
			return ledgerping.Response{}, fmt.Errorf("token validation failed: %s returned HTTP %d", cloudURL, status.StatusCode)
		}
		return ledgerping.Response{}, err
	}
	return ping, nil
}

func deviceLabel(ctx context.Context) string {
	if out, err := execCommand(ctx, "", "scutil", "--get", "ComputerName"); err == nil {
		if label := strings.TrimSpace(out); label != "" {
			return label
		}
	}
	host, err := os.Hostname()
	if err != nil {
		return ""
	}
	return host
}

func writeUserManagedConfig(slot target, cloudURL, label string, allowHTTPLoopback bool) (string, error) {
	path := slot.ConfigPath
	if path == "" {
		return "", errors.New("cannot resolve your home directory")
	}

	cfg := managedconfig.Config{
		Version:           managedconfig.Version,
		CloudURL:          cloudURL,
		AllowHTTPLoopback: allowHTTPLoopback,
		// Self-serve installs follow the policy deployment's rollout mode, so
		// the posture is controlled from the dashboard. Static observe/enforce
		// pins remain an MDM (system-scope) concern.
		Mode:  managedconfig.ModeRemote,
		Agent: managedconfig.Agent,
		Credentials: managedconfig.Credentials{
			// The token ref is the profile's own keychain item, so the daemon
			// resolves whatever the ACTIVE config names and a switch needs no
			// keychain work at all.
			InstallTokenRef: managedconfig.TokenRef{Source: "keychain", Name: slot.KeychainItem},
		},
		Device: managedconfig.Device{Label: label},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	// Self-check through the daemon's parser: setup must never write a config
	// the daemon will refuse to load.
	if _, err := managedconfig.Parse(data); err != nil {
		return "", fmt.Errorf("generated managed config is invalid: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	// Same write lock the daemon's mode migration takes, so the two
	// cooperating writers of this file can never interleave a
	// read-verify-replace sequence.
	if err := managedconfig.WithWriteLock(path, func() error {
		temp, err := os.CreateTemp(filepath.Dir(path), ".managed-*.tmp")
		if err != nil {
			return err
		}
		tempPath := temp.Name()
		defer os.Remove(tempPath)
		if err := temp.Chmod(0o600); err != nil {
			temp.Close()
			return err
		}
		if _, err := temp.Write(data); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Sync(); err != nil {
			temp.Close()
			return err
		}
		if err := temp.Close(); err != nil {
			return err
		}
		return os.Rename(tempPath, path)
	}); err != nil {
		return "", err
	}
	return path, nil
}

// StableBinaryPath picks the path baked into hooks and the LaunchAgent. The
// brew prefix symlink (/opt/homebrew/bin, /usr/local/bin) survives `brew
// upgrade`; a Cellar or Caskroom path dies with the next version, so prefer a
// stable symlink that resolves to the same binary.
func StableBinaryPath() (string, string) {
	exe, err := executablePath()
	if err != nil || exe == "" {
		return claudemanaged.DefaultKontextBinary, ""
	}
	if !strings.Contains(exe, "/Cellar/") && !strings.Contains(exe, "/Caskroom/") {
		return exe, ""
	}
	real, err := filepath.EvalSymlinks(exe)
	if err != nil {
		real = exe
	}
	for _, candidate := range []string{"/opt/homebrew/bin/kontext", "/usr/local/bin/kontext"} {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		if resolved == real {
			return candidate, ""
		}
	}
	return exe, "note: using a versioned Homebrew path for hooks; re-run `kontext setup` after `brew upgrade kontext`"
}

func managedSettingsData(binary string) ([]byte, error) {
	data, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		return nil, err
	}
	if err := claudemanaged.Validate(data, binary); err != nil {
		return nil, fmt.Errorf("generated managed settings are invalid: %w", err)
	}
	return data, nil
}

// cursorUserHooksPath is Cursor's per-user hooks file, the one self-serve
// writes.
func cursorUserHooksPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cursor", "hooks.json")
}

// preflightCursorHooks stops setup before anything is written when Cursor's
// hooks file cannot take Kontext's entries.
func preflightCursorHooks(binary, path string) error {
	// Follows a dotfiles symlink; the writer preserves it. A dangling link
	// would fail only after credentials and other hooks are written.
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, lerr := os.Lstat(path); lerr != nil {
			// Absent: the folder must still take the new file.
			if err := writableDir(path); err != nil {
				return fmt.Errorf("check Cursor hooks: %w\n\nFix the folder, then rerun setup.\nNothing changed.", err)
			}
			return nil
		}
		err = errors.New("symlink target does not exist")
	}
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	var settings map[string]any
	if err == nil {
		var raw []byte
		if raw, err = os.ReadFile(path); err == nil {
			err = json.Unmarshal(raw, &settings)
		}
	}
	if err == nil {
		err = cursormanaged.MergeManagedHooks(settings, binary)
	}
	if err == nil {
		err = writableDir(path)
	}
	if err != nil {
		return fmt.Errorf("check Cursor hooks: %w\n\nFix or move %s, then rerun setup.\nNothing changed.", err, path)
	}
	return nil
}

// preflightClaudeUserHooks stops setup before anything is written when the
// user's Claude settings cannot take Kontext's hooks.
func preflightClaudeUserHooks(binary string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	path, err := claudemanaged.UserSettingsPathNoCreate(home)
	if err != nil {
		return fmt.Errorf("check Claude Code hooks: %w", err)
	}
	err = danglingLink(path)
	var settings map[string]any
	if err == nil {
		settings, err = claudemanaged.ReadUserSettings(path)
	}
	if err == nil {
		_, err = claudemanaged.MergeManagedHooks(settings, binary)
	}
	if err == nil {
		err = writableDir(path)
	}
	if err != nil {
		return fmt.Errorf("check Claude Code hooks: %w\n\nFix or move %s, then rerun setup.\nNothing changed.", err, path)
	}
	return nil
}

// danglingLink rejects a symlink whose target is gone: it reads as a missing
// file, but installing through it fails only after setup changed state.
func danglingLink(path string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		if _, err := filepath.EvalSymlinks(path); err != nil {
			return fmt.Errorf("symlink target does not exist: %w", err)
		}
	}
	return nil
}

// writableDir checks that the folders hook installation writes in take a new
// file: the one holding path, for the backup, and through a symlink the
// target's, for the atomic replace.
func writableDir(path string) error {
	dirs := []string{filepath.Dir(path)}
	if resolved, err := filepath.EvalSymlinks(path); err == nil && filepath.Dir(resolved) != dirs[0] {
		dirs = append(dirs, filepath.Dir(resolved))
	}
	for _, dir := range dirs {
		if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
			continue
		}
		probe, err := os.CreateTemp(dir, ".kontext-setup-check-*")
		if err != nil {
			return fmt.Errorf("%s is not writable: %w", dir, err)
		}
		probe.Close()
		if err := os.Remove(probe.Name()); err != nil {
			return err
		}
	}
	return nil
}

// codexTrustHint tells the user how to trust the Kontext hooks in Codex.
// Codex keeps that trust in ~/.codex/config.toml, which the Codex CLI's /hooks
// writes; a hook whose command changed needs trusting again.
const codexTrustHint = "  • Codex: runs the Kontext hooks only after you trust them. Run `codex`, open /hooks and trust each Kontext hook"

func preflightCodexUserHooks(binary string) error {
	path, err := codexmanaged.UserHooksPathNoCreate()
	if err != nil {
		return fmt.Errorf("check Codex hooks: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("check Codex hooks: %w", err)
	}
	settings, err := codexmanaged.ReadHooks(path)
	if err != nil {
		return fmt.Errorf("check Codex hooks: %w\n\nFix or move ~/.codex/hooks.json, then rerun setup.", err)
	}
	if err := codexmanaged.MergeManagedHooks(settings, binary); err != nil {
		return fmt.Errorf("check Codex hooks: %w\n\nFix or move ~/.codex/hooks.json, then rerun setup.", err)
	}
	return nil
}

func waitForDaemon(out io.Writer) error {
	return runWithStatus(out, "Waiting for background agent", probeDaemon)
}

func runWithStatus(out io.Writer, label string, fn func() error) error {
	if !isTerminalWriter(out) {
		fmt.Fprintf(out, "  • %s...\n", label)
		return fn()
	}

	done := make(chan error, 1)
	go func() {
		done <- fn()
	}()

	frames := []string{"◐", "◓", "◑", "◒"}
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	frame := 0
	for {
		fmt.Fprintf(out, "\r  %s %s...", frames[frame%len(frames)], label)
		frame++
		select {
		case err := <-done:
			fmt.Fprint(out, "\r\033[2K")
			return err
		case <-ticker.C:
		}
	}
}

func isTerminalWriter(w io.Writer) bool {
	file, ok := w.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

// daemonStartWait bounds how long setup waits for a new background agent. Its
// first start reads the keychain and creates its database, which can take
// several seconds.
var daemonStartWait = 15 * time.Second

// daemonExitGrace is how long setup waits before it asks launchd whether the
// agent's process still runs; launchd may not have started it yet.
var daemonExitGrace = 3 * time.Second

// errDaemonNotRunning marks an agent whose process exited instead of starting:
// waiting longer cannot help.
var errDaemonNotRunning = errors.New("the background agent's process is not running")

// daemonRunning reports whether launchd has the background agent's process up.
var daemonRunning = func() bool {
	out, err := execCommand(context.Background(), "", "launchctl", "print", "gui/"+strconv.Itoa(os.Getuid())+"/"+LaunchAgentLabel)
	return err == nil && strings.Contains(out, "state = running")
}

func probeDaemon() error {
	socket := managedobserve.DefaultSocketPath()
	start := time.Now()
	for {
		err := dialSocket(socket, 500*time.Millisecond)
		if err == nil || time.Since(start) >= daemonStartWait {
			return err
		}
		if time.Since(start) >= daemonExitGrace && !daemonRunning() {
			return fmt.Errorf("%w (%v)", errDaemonNotRunning, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func summariseInventory(inv agentinventory.Inventory) string {
	labels := make([]string, 0, len(inv.Agents))
	for _, agent := range inv.Agents {
		state := "not governed"
		switch agent.Wired {
		case agentinventory.WiredYes:
			state = "governed"
		case agentinventory.WiredUnsupported:
			state = "not yet supported"
		case agentinventory.WiredError:
			state = "hook status unavailable"
		}
		labels = append(labels, agentinventory.DisplayName(agent.ID)+" ("+state+")")
	}
	summary := strings.Join(labels, ", ")
	if summary == "" {
		summary = "none found"
	}
	if inv.Incomplete {
		summary += " (incomplete scan)"
	}
	return summary
}
