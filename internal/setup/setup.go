// Package setup implements `kontext setup`: connecting a single Mac to a
// Kontext organization without MDM. It produces the same managed-observe
// pipeline as an enterprise package install — managed config, installation
// identity, agent hooks, LaunchAgent running the daemon — but at user scope
// (~/Library, ~/.claude, ~/.codex) with the install token in the login keychain.
package setup

import (
	"bufio"
	"bytes"
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

	"github.com/kontext-security/kontext-cli/internal/guard/judge"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/codexmanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

const (
	DefaultCloudURL = "https://api.kontext.security"

	// KeychainItemName is the generic-password service name. It MUST stay in
	// lockstep with the managed.json token ref below: the daemon reads the
	// token with `security find-generic-password -s <name> -w`.
	KeychainItemName = "kontext-install-token"
	keychainAccount  = "kontext"

	pingPath = "/api/v1/authorization-ledger/ping"

	settingsBackupLabel = "kontext-setup"
)

// Test seams (repo convention, cf. update.go's brewUpgradeFn). All external
// process and terminal interactions go through these so tests never touch
// launchctl/security/scutil or a real TTY.
var (
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
	systemConfigPath    = managedconfig.DefaultPath
	orgInstallTokenPath = "/Library/Application Support/Kontext/install-token"
	managedSettingsPath = claudemanaged.ManagedSettingsDropInPath
	managedSettingsFile = claudemanaged.ManagedSettingsPath
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
	// WithLocalLLM opts this Mac into the local risk model: setup checks the
	// runtime is present, pre-fetches the weights, and tells the background
	// agent to manage a llama-server. Off by default, and everything works
	// without it — the classifier records its embedded model's verdict and notes
	// the LLM's absence.
	WithLocalLLM bool
	// ModelDownloadProgress reports pre-fetch progress. Nil is silent.
	ModelDownloadProgress judge.DownloadProgressHandler
}

// CloudURL returns the hosted API URL for install-token setup.
func CloudURL() string {
	if value := strings.TrimSpace(os.Getenv("KONTEXT_API_URL")); value != "" {
		return value
	}
	return DefaultCloudURL
}

type pingResponse struct {
	OrganizationID string `json:"organization_id"`
	// JSON null (the legacy env-fallback org) decodes to "".
	OrganizationName string `json:"organization_name"`
}

// Run connects this Mac to the org owning the install token. Steps are
// ordered so every irreversible action happens after the token is proven
// valid, and re-running is always safe (token rotation restarts the agent).
func Run(ctx context.Context, opts Options) error {
	if goos != "darwin" {
		return errors.New("kontext setup is currently macOS-only")
	}
	binary, binaryNote := stableBinaryPath()
	settingsData, err := managedSettingsData(binary)
	if err != nil {
		return err
	}
	fmt.Fprintln(opts.Stdout, "Kontext setup")

	if err := preflightLegacyUserHooks(); err != nil {
		return err
	}
	// Before any privileged write: asking for the model without the runtime
	// installed should cost nothing to recover from.
	var llamaServerPath string
	if opts.WithLocalLLM {
		var err error
		if llamaServerPath, err = preflightLocalLLM(); err != nil {
			return err
		}
	}
	if err := preflightCodexUserHooks(binary); err != nil {
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

	ping, err := validateToken(ctx, opts.HTTPClient, cloudURL, token)
	if err != nil {
		return err
	}
	orgLabel := ping.OrganizationID
	if ping.OrganizationName != "" {
		orgLabel = fmt.Sprintf("%s (%s)", ping.OrganizationName, ping.OrganizationID)
	}
	fmt.Fprintln(opts.Stdout, "\nWorkspace")
	fmt.Fprintf(opts.Stdout, "  ✓ %s\n", orgLabel)

	// Refuse a SECOND profile for a workspace already bound on this backend. Two
	// profiles differing only by name would hold the same workspace's records in
	// two ledgers and present it two device identities — no purpose, and a
	// confusing thing to inherit.
	//
	// The check has to be here, not in a caller: the workspace is only known once
	// the hosted API answers, so nothing earlier can tell two tokens apart. It is
	// deliberately NOT "one profile per environment" — several workspaces on one
	// backend is exactly what workspaces are for.
	if duplicate, err := profileBoundToWorkspace(ping.OrganizationID, cloudURL, opts.Profile); err != nil {
		return err
	} else if duplicate != "" {
		return fmt.Errorf(
			"workspace %s is already set up as profile %q on %s\n\nSwitch to it with `kontext profile use %s`, or remove it first to re-create it.",
			orgLabel, duplicate, cloudURL, duplicate)
	}

	// The target is resolved HERE, not before the token: with DeriveProfileName
	// the name comes from the workspace, which nothing knows until the hosted API
	// answers. Nothing above this point writes anything, so the ordering costs
	// nothing and removes the need to invent a name up front.
	profileName := opts.Profile
	if opts.DeriveProfileName && profileName == "" {
		profileName, err = DeriveProfileName(cloudURL, ping.OrganizationName, ping.OrganizationID)
		if err != nil {
			return err
		}
		fmt.Fprintf(opts.Stdout, "  ✓ Profile name: %s\n", profileName)
	}
	slot, err := resolveTarget(profileName)
	if err != nil {
		return err
	}
	if opts.OnProfileResolved != nil {
		opts.OnProfileResolved(slot.Profile)
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

	identityPath := slot.IdentityPath
	if identityPath == "" {
		return errors.New("cannot resolve your home directory")
	}
	identity, err := installation.EnsureFile(identityPath)
	if err != nil {
		return fmt.Errorf("ensure installation identity: %w", err)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Installation identity ready (%s)\n", identity.InstallationID)

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

	settingsPath, err := installManagedSettings(ctx, settingsData)
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Claude Code managed hooks installed (%s)\n", settingsPath)

	codexHooksPath, err := installCodexUserHooks(binary)
	if err != nil {
		return fmt.Errorf("install Codex hooks: %w\n\nFix or move ~/.codex/hooks.json, then rerun setup.", err)
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Codex hooks installed (%s)\n", codexHooksPath)
	if configPath, enabled, err := enableCodexHooksFeature(); err != nil {
		fmt.Fprintf(opts.Stderr, "note: could not enable the Codex hooks feature automatically (%v); set `[features].hooks = true` in ~/.codex/config.toml or the hooks will not run.\n", err)
	} else if enabled {
		fmt.Fprintf(opts.Stdout, "  ✓ Codex hooks feature enabled ([features].hooks in %s)\n", configPath)
	}
	fmt.Fprintln(opts.Stderr, "note: Codex hooks require review before they run; open `/hooks` in Codex to trust the Kontext hooks.")

	var plistPath, logPath string
	err = runWithStatus(opts.Stdout, "Installing background agent", func() error {
		var err error
		// Deliberately without the local model on this pass. Enabling it here
		// would bootstrap a model-managing daemon that starts downloading the
		// weights at the same moment setup does, for two ~680 MB transfers into
		// one cache path. The agent comes up now and protects the endpoint; the
		// model is attached below, once it is on disk.
		plistPath, logPath, err = installLaunchAgent(ctx, binary, nil)
		return err
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Stdout, "  ✓ Background agent installed (%s)\n", plistPath)

	// The model comes last: the agent is already up and observing, so a slow
	// download delays nothing that protects the endpoint, and it is on disk
	// before any daemon is told to look for it.
	if opts.WithLocalLLM {
		agentLLM := prefetchLocalModel(ctx, llamaServerPath, opts.Stdout, opts.Stderr, opts.ModelDownloadProgress)
		err = runWithStatus(opts.Stdout, "Enabling the local risk model", func() error {
			_, _, err := installLaunchAgent(ctx, binary, agentLLM)
			return err
		})
		if err != nil {
			// Enabling reloads the agent: it is booted out, then bootstrapped with
			// the new plist. A failure in the second half leaves no agent running,
			// which is strictly worse than not having the model — so put the
			// working configuration back rather than returning success over a
			// stopped daemon.
			fmt.Fprintf(opts.Stderr, "warning: could not enable the local risk model (%v); restoring the agent without it\n", err)
			if _, _, restoreErr := installLaunchAgent(ctx, binary, nil); restoreErr != nil {
				return fmt.Errorf("enabling the local risk model failed (%w) and the background agent could not be restored: %w", err, restoreErr)
			}
			fmt.Fprintln(opts.Stdout, "  ✓ Background agent restored without the local risk model")
		} else {
			fmt.Fprintf(opts.Stdout, "  ✓ Local risk model enabled (%s)\n", llamaServerPath)
		}
	}

	if err := waitForDaemon(opts.Stdout); err != nil {
		fmt.Fprintln(opts.Stdout, "  ! Background agent is still starting")
		fmt.Fprintf(opts.Stderr, "warning: the background agent has not come up yet (%v); check `tail -f %s`\n", err, logPath)
	} else {
		fmt.Fprintln(opts.Stdout, "  ✓ Background agent running")
	}

	if err := removeLegacyUserHooks(); err != nil {
		fmt.Fprintf(opts.Stderr, "warning: legacy Claude Code user hooks could not be removed after installing managed hooks (%v)\n", err)
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
	if err != nil && !launchctlPrintMeansAbsent(out) {
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

func validateToken(ctx context.Context, client *http.Client, cloudURL, token string) (pingResponse, error) {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(cloudURL, "/")+pingPath, nil)
	if err != nil {
		return pingResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return pingResponse{}, fmt.Errorf("cannot reach %s: %w", cloudURL, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return pingResponse{}, errors.New("install token was rejected — it may be revoked or mistyped; create a new one in the dashboard (Deployments page)")
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return pingResponse{}, fmt.Errorf("token validation failed: %s returned HTTP %d", cloudURL, resp.StatusCode)
	}

	var ping pingResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ping); err != nil {
		return pingResponse{}, fmt.Errorf("parse token validation response: %w", err)
	}
	if strings.TrimSpace(ping.OrganizationID) == "" {
		return pingResponse{}, errors.New("server did not return an organization id for this token")
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

// stableBinaryPath picks the path baked into hooks and the LaunchAgent. The
// brew prefix symlink (/opt/homebrew/bin, /usr/local/bin) survives `brew
// upgrade`; a Cellar path dies with the next version, so prefer a stable
// symlink that resolves to the same binary.
func stableBinaryPath() (string, string) {
	exe, err := executablePath()
	if err != nil || exe == "" {
		return claudemanaged.DefaultKontextBinary, ""
	}
	if !strings.Contains(exe, "/Cellar/") {
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
	return exe, "note: using a Homebrew Cellar path for hooks; re-run `kontext setup` after `brew upgrade kontext`"
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

// installManagedSettings writes the Claude drop-in, skipping the write entirely
// when the file on disk already has exactly this content.
//
// The write needs root, so it costs an administrator password. Re-running setup
// or adding a second profile does not change these settings — they name the
// binary and the hook events, neither of which varies per profile — so asking
// for a password to rewrite identical bytes is pure friction. It also trains
// people to type a password at a prompt that did not need one.
func installManagedSettings(ctx context.Context, data []byte) (string, error) {
	if current, err := os.ReadFile(managedSettingsPath); err == nil && bytes.Equal(current, data) {
		return managedSettingsPath, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		// An unreadable existing file must not be silently overwritten: the
		// privileged write would mask whatever the real problem is.
		return "", fmt.Errorf("cannot read existing Claude managed settings: %w", err)
	}
	if err := writePrivilegedFile(ctx, managedSettingsPath, data); err != nil {
		return "", err
	}
	return managedSettingsPath, nil
}

func writePrivilegedFile(ctx context.Context, path string, data []byte) error {
	if geteuid() == 0 {
		dir := filepath.Dir(path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		temp, err := os.CreateTemp(dir, ".managed-settings-*.tmp")
		if err != nil {
			return err
		}
		tempPath := temp.Name()
		defer os.Remove(tempPath)
		if err := temp.Chmod(0o644); err != nil {
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
		if err := os.Rename(tempPath, path); err != nil {
			return err
		}
		return os.Chmod(path, 0o644)
	}

	temp, err := os.CreateTemp("", "kontext-managed-settings-*.json")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := runPrivilegedCommand(ctx, "sudo", "mkdir", "-p", filepath.Dir(path)); err != nil {
		return fmt.Errorf("create Claude managed settings directory: %w", err)
	}
	if err := runPrivilegedCommand(ctx, "sudo", "install", "-m", "0644", tempPath, path); err != nil {
		return fmt.Errorf("install Claude managed settings: %w", err)
	}
	return nil
}

func removeLegacyUserHooks() error {
	path, err := userSettingsPathNoCreate()
	if err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	settings, err := claudemanaged.ReadUserSettings(path)
	if err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	if disabled, _ := settings["disableAllHooks"].(bool); disabled {
		return fmt.Errorf("clean legacy Claude Code hooks: disableAllHooks must not be true")
	}
	before, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	if err := claudemanaged.RemoveManagedHooks(settings); err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	after, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	if bytes.Equal(before, after) {
		return nil
	}
	if err := claudemanaged.BackupUserSettings(path, settingsBackupLabel); err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	if err := claudemanaged.WriteUserSettings(path, settings); err != nil {
		return fmt.Errorf("clean legacy Claude Code hooks: %w", err)
	}
	return nil
}

func preflightLegacyUserHooks() error {
	path, err := userSettingsPathNoCreate()
	if err != nil {
		return fmt.Errorf("check legacy Claude Code hooks: %w", err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("check legacy Claude Code hooks: %w", err)
	}
	settings, err := claudemanaged.ReadUserSettings(path)
	if err != nil {
		return fmt.Errorf("check legacy Claude Code hooks: %w", err)
	}
	if disabled, _ := settings["disableAllHooks"].(bool); disabled {
		return fmt.Errorf("check legacy Claude Code hooks: disableAllHooks must not be true")
	}
	if err := claudemanaged.RemoveManagedHooks(settings); err != nil {
		return fmt.Errorf("check legacy Claude Code hooks: %w", err)
	}
	return nil
}

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

func installCodexUserHooks(binary string) (string, error) {
	path, err := codexmanaged.UserHooksPath()
	if err != nil {
		return "", err
	}
	before, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		before = nil
	} else if err != nil {
		return "", err
	}
	settings, err := codexmanaged.ReadHooks(path)
	if err != nil {
		return "", err
	}
	if err := codexmanaged.MergeManagedHooks(settings, binary); err != nil {
		return "", err
	}
	after, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", err
	}
	after = append(after, '\n')
	if bytes.Equal(before, after) {
		return path, nil
	}
	if err := codexmanaged.BackupHooks(path, settingsBackupLabel); err != nil {
		return "", err
	}
	if err := codexmanaged.WriteHooks(path, settings); err != nil {
		return "", err
	}
	return path, nil
}

// enableCodexHooksFeature turns on `[features].hooks` in ~/.codex/config.toml so
// the hooks we just installed actually fire — Codex gates its hook engine off
// by default. Non-fatal in the caller: a failure here should warn, not abort a
// setup whose durable state is already written.
func enableCodexHooksFeature() (configPath string, enabled bool, err error) {
	path, err := codexmanaged.UserConfigPath()
	if err != nil {
		return "", false, err
	}
	enabled, err = codexmanaged.EnsureHooksEnabled(path, settingsBackupLabel)
	if err != nil {
		return "", false, err
	}
	return path, enabled, nil
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

func probeDaemon() error {
	socket := managedobserve.DefaultSocketPath()
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		if lastErr = dialSocket(socket, 500*time.Millisecond); lastErr == nil {
			return nil
		}
	}
	return lastErr
}
