package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/codexmanaged"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

type execCall struct {
	stdin string
	name  string
	args  []string
}

// harness stubs every seam so Run/Uninstall never touch launchctl, security,
// scutil, a TTY, or the real /Library — and records what they WOULD have run.
type harness struct {
	t        *testing.T
	home     string
	calls    []execCall
	keychain map[string]string // service -> token, emulating add/delete/find
	out      bytes.Buffer
	errOut   bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, home: t.TempDir(), keychain: map[string]string{}}
	t.Setenv("HOME", h.home)
	t.Setenv(managedconfig.EnvPath, "")
	t.Setenv(installation.EnvPath, "")

	overrideVar(t, &goos, "darwin")
	overrideVar(t, &systemConfigPath, filepath.Join(h.home, "no-system", "managed.json"))
	overrideVar(t, &orgInstallTokenPath, filepath.Join(h.home, "no-system", "install-token"))
	overrideVar(t, &managedSettingsPath, filepath.Join(h.home, "Library", "Application Support", "ClaudeCode", "managed-settings.d", "20-kontext.json"))
	overrideVar(t, &managedSettingsFile, filepath.Join(h.home, "Library", "Application Support", "ClaudeCode", "managed-settings.json"))
	overrideVar(t, &geteuid, func() int { return 0 })
	overrideVar(t, &executablePath, func() (string, error) { return "/opt/homebrew/bin/kontext", nil })
	overrideVar(t, &dialSocket, func(string, time.Duration) error { return nil })
	overrideVar(t, &isTerminal, func(int) bool { return false })
	overrideVar(t, &readPassword, func(int) ([]byte, error) { return nil, errors.New("no tty in tests") })
	overrideVar(t, &resolveToken, func(_ context.Context, ref managedconfig.TokenRef) (string, error) {
		token, ok := h.keychain[ref.Name]
		if !ok {
			return "", errors.New("keychain item not found")
		}
		return token, nil
	})
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		switch name {
		case "scutil":
			return "Test MacBook\n", nil
		case "security":
			// Key the fake keychain by the service name the caller actually
			// passed, so per-profile items are distinguishable here exactly as
			// they are in the real keychain.
			if len(args) > 0 && args[0] == "delete-generic-password" {
				item := serviceNameFromArgs(h.t, args)
				if _, ok := h.keychain[item]; ok {
					delete(h.keychain, item)
					return "", nil
				}
				return "security: The specified item could not be found in the keychain.", errors.New("exit status 44")
			}
			// `security -i` add-generic-password via stdin.
			if len(args) > 0 && args[0] == "-i" {
				item, token := parseAddGenericPassword(h.t, stdin)
				h.keychain[item] = token
				return "", nil
			}
			return "", nil
		case "launchctl":
			return "", nil
		default:
			h.t.Fatalf("unexpected command: %s %v", name, args)
			return "", nil
		}
	})
	overrideVar(t, &runPrivilegedCommand, func(_ context.Context, name string, args ...string) error {
		h.calls = append(h.calls, execCall{name: name, args: args})
		return nil
	})
	return h
}

func overrideVar[T any](t *testing.T, target *T, value T) {
	t.Helper()
	previous := *target
	*target = value
	t.Cleanup(func() { *target = previous })
}

// parseAddGenericPassword returns the service name and token from the
// `security -i` stdin command.
func parseAddGenericPassword(t *testing.T, stdin string) (item, token string) {
	t.Helper()
	// add-generic-password -U -s <service> -a <account> -w "<token>"
	start := strings.Index(stdin, `-w "`)
	if start < 0 {
		t.Fatalf("unexpected security stdin: %q", stdin)
	}
	rest := stdin[start+len(`-w "`):]
	end := strings.LastIndex(rest, `"`)
	if end < 0 {
		t.Fatalf("unterminated token quote: %q", stdin)
	}
	return serviceNameFromArgs(t, strings.Fields(stdin)), rest[:end]
}

// serviceNameFromArgs pulls the value of the `-s` flag out of a security
// invocation, whether it arrived as argv or as `security -i` stdin words.
func serviceNameFromArgs(t *testing.T, args []string) string {
	t.Helper()
	for i, arg := range args {
		if arg == "-s" && i+1 < len(args) {
			return args[i+1]
		}
	}
	t.Fatalf("no -s service name in security args: %v", args)
	return ""
}

func (h *harness) options(token string, server *httptest.Server) Options {
	return Options{
		Token:      token,
		CloudURL:   server.URL,
		Version:    "0.0.0-test",
		Stdout:     &h.out,
		Stderr:     &h.errOut,
		HTTPClient: server.Client(),
	}
}

func pingServer(t *testing.T, expectToken string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authorization-ledger/ping" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+expectToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization_id":   "org_test",
			"organization_name": "Acme",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

// The httptest server is plain http on a loopback address; the managed.json
// self-check (managedconfig.Parse) only accepts that with the loopback
// escape hatch enabled.
func allowLoopback(t *testing.T) {
	t.Setenv(managedconfig.EnvAllowHTTP, "1")
}

func TestRunFullFlow(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatalf("Run() error = %v\nstdout:\n%s\nstderr:\n%s", err, h.out.String(), h.errOut.String())
	}

	// Keychain holds the raw token.
	if h.keychain[KeychainItemName] != "tok-123" {
		t.Fatalf("keychain = %q", h.keychain[KeychainItemName])
	}

	// managed.json at the user path parses through the daemon's loader.
	// (Scope resolution itself is covered by managedconfig's own tests — the
	// host machine may have a real /Library config that Load() would pick.)
	loaded, err := managedconfig.LoadFile(managedconfig.UserPath())
	if err != nil {
		t.Fatalf("LoadFile(user path) after setup: %v", err)
	}
	if loaded.Config.Credentials.InstallTokenRef.String() != "keychain:"+KeychainItemName {
		t.Fatalf("token ref = %q", loaded.Config.Credentials.InstallTokenRef)
	}
	if loaded.Config.Device.Label != "Test MacBook" {
		t.Fatalf("device label = %q", loaded.Config.Device.Label)
	}
	data, err := os.ReadFile(managedconfig.UserPath())
	if err != nil {
		t.Fatalf("ReadFile(user managed config) error = %v", err)
	}
	if strings.Contains(string(data), "organization_id") {
		t.Fatalf("managed config contains organization_id:\n%s", data)
	}

	// Installation identity created at the user path.
	if _, err := installation.LoadFile(installation.UserPath()); err != nil {
		t.Fatalf("installation identity: %v", err)
	}

	// Hooks are installed through Claude managed settings with the stable binary path.
	data, err = os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := claudemanaged.Validate(data, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatalf("managed hooks invalid after setup: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(h.home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("setup created user settings file: %v", err)
	}
	codexHooksPath := filepath.Join(h.home, ".codex", "hooks.json")
	codexHooks, err := codexmanaged.ReadHooks(codexHooksPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"hooks": codexHooks["hooks"]})
	if err := codexmanaged.Validate(raw, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatalf("Codex hooks invalid after setup: %v", err)
	}

	// LaunchAgent plist written and lifecycle ordered bootout -> bootstrap
	// in the user's GUI domain. RunAtLoad starts the daemon after bootstrap.
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if _, err := os.Stat(plist); err != nil {
		t.Fatalf("plist missing: %v", err)
	}
	var launchctl [][]string
	for _, call := range h.calls {
		if call.name == "launchctl" {
			launchctl = append(launchctl, call.args)
		}
	}
	if len(launchctl) != 2 || launchctl[0][0] != "bootout" || launchctl[1][0] != "bootstrap" {
		t.Fatalf("launchctl order = %v", launchctl)
	}
	if len(launchctl[0]) != 3 || !strings.HasSuffix(launchctl[0][2], ".plist") {
		t.Fatalf("bootout args = %v, want domain + plist path", launchctl[0])
	}

	stdout := h.out.String()
	for _, want := range []string{
		"Kontext setup",
		"Workspace\n  ✓ Acme (org_test)",
		"Mac\n  ✓ Config written",
		"  ✓ Claude Code managed hooks installed",
		"  ✓ Codex hooks installed",
		"  • Installing background agent...",
		"  • Waiting for background agent...",
		"  ✓ Background agent running",
		"Next\n  Return to the Kontext dashboard.",
		"  Run the hello command shown there to confirm this Mac is connected.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "Start a Claude Code session") {
		t.Fatalf("stdout still uses old ending:\n%s", stdout)
	}
	if errOut := h.errOut.String(); !strings.Contains(errOut, "Codex hooks require review") || !strings.Contains(errOut, "/hooks") {
		t.Fatalf("stderr missing Codex /hooks trust review note:\n%s", errOut)
	}

	// The raw token never travels in argv — only via `security -i` stdin.
	for _, call := range h.calls {
		for _, arg := range call.args {
			if strings.Contains(arg, "tok-123") {
				t.Fatalf("token leaked into argv: %s %v", call.name, call.args)
			}
		}
	}
}

func TestRunIsIdempotent(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatal(err)
	}
	identityBefore, err := installation.LoadFile(installation.UserPath())
	if err != nil {
		t.Fatal(err)
	}

	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}

	// Identity survives; managed settings stay valid.
	identityAfter, err := installation.LoadFile(installation.UserPath())
	if err != nil {
		t.Fatal(err)
	}
	if identityBefore.InstallationID != identityAfter.InstallationID {
		t.Fatal("installation identity changed across re-runs")
	}
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := claudemanaged.Validate(data, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatalf("managed hooks invalid after re-run: %v", err)
	}
	codexHooks, err := codexmanaged.ReadHooks(filepath.Join(h.home, ".codex", "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	groups := codexHooks["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(groups) != 1 {
		t.Fatalf("Codex PreToolUse groups after re-run = %d, want 1", len(groups))
	}
	backups, err := filepath.Glob(filepath.Join(h.home, ".codex", "hooks.json."+settingsBackupLabel+"-backup-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("Codex hook backups after idempotent re-run = %d, want 0: %v", len(backups), backups)
	}
}

func TestRunRejectsRevokedToken(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "valid-token")

	err := Run(context.Background(), h.options("revoked-token", server))
	if err == nil || !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("Run() error = %v, want rejection", err)
	}
	// Nothing was written before validation failed.
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite rejected token")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite rejected token")
	}
}

func TestRunRejectsMalformedCodexHooksBeforeWritingState(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	codexHooksPath := filepath.Join(h.home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(codexHooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexHooksPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Run(context.Background(), h.options("tok-123", pingServer(t, "tok-123")))
	if err == nil || !strings.Contains(err.Error(), "check Codex hooks") {
		t.Fatalf("Run() error = %v, want Codex hook preflight failure", err)
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite malformed Codex hooks")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite malformed Codex hooks")
	}
	if _, err := os.Stat(installation.UserPath()); !os.IsNotExist(err) {
		t.Fatal("installation identity written despite malformed Codex hooks")
	}
	if _, err := os.Stat(managedSettingsPath); !os.IsNotExist(err) {
		t.Fatal("managed settings written despite malformed Codex hooks")
	}
}

func TestRunRefusesMDMManagedMac(t *testing.T) {
	h := newHarness(t)
	system := filepath.Join(h.home, "system-managed.json")
	if err := os.WriteFile(system, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &systemConfigPath, system)
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "organization-managed") {
		t.Fatalf("Run() error = %v, want MDM refusal", err)
	}
	for _, want := range []string{
		"Organization-managed install detected",
		"System config: " + system,
		"system config wins over user config",
		"Remove the organization-managed install first",
		`sudo rm -f "/Library/Application Support/Kontext/managed.json"`,
		"Nothing changed.",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Run() error = %v, missing %q", err, want)
		}
	}
}

func TestRunStopsWhenOrganizationManagedRemovalDeclined(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &isTerminal, func(int) bool { return true })
	overrideVar(t, &readLine, func(io.Reader) (string, error) { return "no\n", nil })
	server := pingServer(t, "tok")

	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("Run() error = %v, want clean stop", err)
	}

	if _, err := os.Stat(systemConfigPath); err != nil {
		t.Fatalf("system config changed after declined removal: %v", err)
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite declined removal")
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite declined removal")
	}
	for _, call := range h.calls {
		if call.name == "launchctl" {
			t.Fatalf("launchctl called despite declined removal: %v", call.args)
		}
	}
	stdout := h.out.String()
	for _, want := range []string{
		"Kontext setup",
		"Organization-managed install detected",
		"Remove organization-managed install and continue? [y/N]",
		"Nothing changed.",
		"Remove the MDM profile or enterprise package",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunRemovesOrganizationManagedInstallAndContinues(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	ownedRootSettings, err := managedSettingsData("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{systemConfigPath, orgInstallTokenPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsFile, ownedRootSettings, 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &isTerminal, func(int) bool { return true })
	overrideVar(t, &readLine, func(io.Reader) (string, error) { return "yes\n", nil })
	server := pingServer(t, "tok")

	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("Run() error = %v\nstdout:\n%s\nstderr:\n%s", err, h.out.String(), h.errOut.String())
	}

	for _, path := range []string{systemConfigPath, orgInstallTokenPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after org removal: %v", path, err)
		}
	}
	if _, err := os.Stat(managedSettingsFile); !os.IsNotExist(err) {
		t.Fatalf("root managed settings still exist after org removal: %v", err)
	}
	if h.keychain[KeychainItemName] != "tok" {
		t.Fatalf("keychain = %q", h.keychain[KeychainItemName])
	}
	if _, err := managedconfig.LoadFile(managedconfig.UserPath()); err != nil {
		t.Fatalf("user managed config missing after continued setup: %v", err)
	}

	var stoppedOrgAgent bool
	for _, call := range h.calls {
		if call.name == "launchctl" && len(call.args) == 2 && call.args[0] == "bootout" && strings.HasSuffix(call.args[1], "/"+LaunchAgentLabel) {
			stoppedOrgAgent = true
		}
	}
	if !stoppedOrgAgent {
		t.Fatalf("launchctl calls = %v, want org agent bootout by service label", h.calls)
	}
	stdout := h.out.String()
	for _, want := range []string{
		"Remove organization-managed install and continue? [y/N]",
		"Organization-managed files removed",
		"Organization-managed background agent stopped",
		"Workspace\n  ✓ Acme (org_test)",
		"Next\n  Return to the Kontext dashboard.",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestRunDoesNotRemoveForeignRootManagedSettings(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	for _, path := range []string{systemConfigPath, orgInstallTokenPath, managedSettingsFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("foreign settings"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	overrideVar(t, &isTerminal, func(int) bool { return true })
	overrideVar(t, &readLine, func(io.Reader) (string, error) { return "yes\n", nil })
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "root managed settings may contain organization or foreign hooks") {
		t.Fatalf("Run() error = %v, want root settings ownership refusal", err)
	}
	for _, path := range []string{systemConfigPath, orgInstallTokenPath, managedSettingsFile} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s removed before ownership was proven: %v", path, err)
		}
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite root settings ownership refusal")
	}
	for _, call := range h.calls {
		if call.name == "launchctl" {
			t.Fatalf("launchctl called despite root settings ownership refusal: %v", call.args)
		}
	}
}

func TestRunRefusesExistingManagedHooksWithoutSelfServeConfig(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, []byte("enterprise hooks"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "hook ownership is unknown") {
		t.Fatalf("Run() error = %v, want hook ownership refusal", err)
	}
	if h.keychain[KeychainItemName] != "" {
		t.Fatal("keychain written despite hook ownership refusal")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite hook ownership refusal")
	}
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "enterprise hooks" {
		t.Fatalf("managed hooks overwritten: %q", data)
	}
}

func TestRunRefusesExistingRootManagedSettings(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	if err := os.MkdirAll(filepath.Dir(managedSettingsFile), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := managedSettingsData("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsFile, data, 0o644); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")

	err = Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "root managed settings already exist") {
		t.Fatalf("Run() error = %v, want root managed-settings refusal", err)
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json written despite root managed-settings refusal")
	}
}

func TestRunRefreshesStaleSelfServeDropIn(t *testing.T) {
	// A drop-in written by an older self-serve run carries a now-stale binary
	// path. It is still ours (alias-matched), so setup must refresh it in place
	// rather than refuse with "hook ownership is unknown".
	h := newHarness(t)
	allowLoopback(t)
	stale, err := managedSettingsData("/old/Cellar/path/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, stale, 0o644); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")

	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("Run() error = %v, want refresh of owned drop-in", err)
	}
	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(data, stale) {
		t.Fatal("stale drop-in was not refreshed")
	}
	if !claudemanaged.IsManagedSettingsDropIn(data) {
		t.Fatalf("refreshed drop-in is not owned: %q", data)
	}
}

func TestRunPreflightsLegacyCleanupBeforeWritingState(t *testing.T) {
	// A corrupt ~/.claude/settings.json must fail before setup writes active
	// managed config or hooks. Otherwise hook commands can switch to managed
	// observe before the LaunchAgent exists.
	h := newHarness(t)
	allowLoopback(t)
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "check legacy Claude Code hooks") {
		t.Fatalf("Run() error = %v, want legacy cleanup failure", err)
	}
	if _, err := os.Stat(managedSettingsPath); !os.IsNotExist(err) {
		t.Fatalf("managed drop-in written before preflight failure: %v", err)
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatalf("managed config written before preflight failure: %v", err)
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written before preflight failure")
	}
}

func TestRunFailsWhenLegacyUserSettingsDisableHooks(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settingsPath, []byte(`{"disableAllHooks":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "disableAllHooks must not be true") {
		t.Fatalf("Run() error = %v, want disableAllHooks failure", err)
	}
	if _, err := os.Stat(managedSettingsPath); !os.IsNotExist(err) {
		t.Fatalf("managed drop-in written before preflight failure: %v", err)
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatalf("managed config written before preflight failure: %v", err)
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written before preflight failure")
	}
}

func TestRunWarnsAfterInstallWhenLegacyCleanupWriteFails(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	settingsDir := filepath.Join(h.home, ".claude")
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{
			map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"}}},
		},
	}}
	if err := claudemanaged.WriteUserSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(settingsDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(settingsDir, 0o755) })
	server := pingServer(t, "tok")

	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("Run() error = %v, want warning-only legacy cleanup failure", err)
	}
	if _, err := os.Stat(managedSettingsPath); err != nil {
		t.Fatalf("managed drop-in not installed: %v", err)
	}
	var bootstrapped bool
	for _, call := range h.calls {
		if call.name == "launchctl" && len(call.args) > 0 && call.args[0] == "bootstrap" {
			bootstrapped = true
		}
	}
	if !bootstrapped {
		t.Fatal("LaunchAgent was not installed before cleanup failure")
	}
	if !strings.Contains(h.errOut.String(), "legacy Claude Code user hooks could not be removed") {
		t.Fatalf("stderr missing cleanup warning:\n%s", h.errOut.String())
	}
}

func TestRunRefusesEnvOverride(t *testing.T) {
	h := newHarness(t)
	t.Setenv(managedconfig.EnvPath, "/somewhere/else.json")
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), managedconfig.EnvPath) {
		t.Fatalf("Run() error = %v, want env refusal", err)
	}
}

func TestRunRefusesEnvOverrideEvenAtUserPath(t *testing.T) {
	// Any env override means config resolution is env-driven — including one
	// that happens to equal the user path. Setup must refuse them all.
	h := newHarness(t)
	t.Setenv(managedconfig.EnvPath, managedconfig.UserPath())
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), managedconfig.EnvPath) {
		t.Fatalf("Run() error = %v, want env refusal", err)
	}
}

func TestRunRequiresTokenWithoutTTY(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("", server))
	if err == nil || !strings.Contains(err.Error(), "--token") {
		t.Fatalf("Run() error = %v, want --token guidance", err)
	}
}

func TestRunNonDarwin(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &goos, "linux")
	server := pingServer(t, "tok")

	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "macOS-only") {
		t.Fatalf("Run() error = %v, want macOS-only", err)
	}
}

func TestUninstallReversesSetupKeepingIdentity(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")
	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatal(err)
	}

	// A legacy user hook installed before the cutover is removed, foreign hooks survive.
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{
			map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"}}},
			map[string]any{"matcher": "Edit", "hooks": []any{map[string]any{"type": "command", "command": "lint-check"}}},
		},
	}}
	if err := claudemanaged.WriteUserSettings(settingsPath, settings); err != nil {
		t.Fatal(err)
	}
	codexHooksPath := filepath.Join(h.home, ".codex", "hooks.json")
	codexHooks, err := codexmanaged.ReadHooks(codexHooksPath)
	if err != nil {
		t.Fatal(err)
	}
	codexEvents := codexHooks["hooks"].(map[string]any)
	codexEvents["PreToolUse"] = append(codexEvents["PreToolUse"].([]any), map[string]any{
		"matcher": "Edit",
		"hooks":   []any{map[string]any{"type": "command", "command": "codex-lint-check"}},
	})
	if err := codexmanaged.WriteHooks(codexHooksPath, codexHooks); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}

	if len(h.keychain) != 0 {
		t.Fatal("keychain item not removed")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json not removed")
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatal("plist not removed")
	}
	if _, err := os.Stat(managedSettingsPath); !os.IsNotExist(err) {
		t.Fatal("managed settings not removed")
	}
	// Identity kept for endpoint continuity.
	if _, err := installation.LoadFile(installation.UserPath()); err != nil {
		t.Fatalf("installation identity removed: %v", err)
	}
	// Legacy user hook gone, the foreign one intact.
	settings, err = claudemanaged.ReadUserSettings(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	pre := settings["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign hook lost or ours kept: %v", pre)
	}
	codexHooks, err = codexmanaged.ReadHooks(codexHooksPath)
	if err != nil {
		t.Fatal(err)
	}
	pre = codexHooks["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign Codex hook lost or ours kept: %v", pre)
	}

	// Idempotent: a second uninstall is clean.
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("second Uninstall() error = %v", err)
	}
}

func TestUninstallWarnsAndContinuesWhenCodexHooksMalformed(t *testing.T) {
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "tok-123")
	if err := Run(context.Background(), h.options("tok-123", server)); err != nil {
		t.Fatal(err)
	}
	codexHooksPath := filepath.Join(h.home, ".codex", "hooks.json")
	if err := os.WriteFile(codexHooksPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}

	h.errOut.Reset()
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}

	if len(h.keychain) != 0 {
		t.Fatal("keychain item not removed after Codex hook warning")
	}
	if _, err := os.Stat(managedconfig.UserPath()); !os.IsNotExist(err) {
		t.Fatal("managed.json not removed after Codex hook warning")
	}
	if !strings.Contains(h.errOut.String(), "warning: Codex hooks could not be removed") {
		t.Fatalf("stderr missing Codex warning:\n%s", h.errOut.String())
	}
}

func TestUninstallKeepsManagedHooksWhenOrganizationManaged(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemConfigPath, []byte(`{
  "version": "managed-install-v1",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {
    "install_token_ref": "env:KONTEXT_INSTALL_TOKEN"
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(plist), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}

	if _, err := os.Stat(managedSettingsPath); err != nil {
		t.Fatalf("managed settings removed with organization config present: %v", err)
	}
	for _, want := range []string{
		"Organization-managed install detected",
		"Self-serve uninstall cannot remove organization-managed state",
		"Remove the organization-managed install first",
		`sudo rm -f "/Library/Application Support/Kontext/managed.json"`,
	} {
		if !strings.Contains(h.errOut.String(), want) {
			t.Fatalf("stderr missing %q:\n%s", want, h.errOut.String())
		}
	}
	if !strings.Contains(h.out.String(), "Kept Claude Code managed hooks") {
		t.Fatalf("stdout missing kept managed hooks message:\n%s", h.out.String())
	}
	if !strings.Contains(h.out.String(), "Self-serve background agent removed") {
		t.Fatalf("stdout missing self-serve agent removal:\n%s", h.out.String())
	}
	if _, err := os.Stat(plist); !os.IsNotExist(err) {
		t.Fatalf("self-serve LaunchAgent plist still exists after uninstall: %v", err)
	}
	var bootedOutPlist bool
	for _, call := range h.calls {
		if call.name == "launchctl" && len(call.args) == 3 && call.args[0] == "bootout" && call.args[2] == plist {
			bootedOutPlist = true
		}
		if call.name == "launchctl" && len(call.args) == 2 && strings.HasSuffix(call.args[1], "/"+LaunchAgentLabel) {
			t.Fatalf("organization-managed uninstall booted out by label: %v", call.args)
		}
	}
	if !bootedOutPlist {
		t.Fatalf("launchctl calls = %v, want bootout by self-serve plist path", h.calls)
	}
}

func TestUninstallKeepsForeignManagedHooks(t *testing.T) {
	// No organization config, but the drop-in is not ours (another installer).
	// Uninstall must not delete it.
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := []byte(`{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"/opt/other/tool observe"}]}]}}` + "\n")
	if err := os.WriteFile(managedSettingsPath, foreign, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}

	data, err := os.ReadFile(managedSettingsPath)
	if err != nil {
		t.Fatalf("foreign managed hooks removed: %v", err)
	}
	if !bytes.Equal(data, foreign) {
		t.Fatalf("foreign managed hooks altered: %q", data)
	}
	if !strings.Contains(h.out.String(), "Kept Claude Code managed hooks because ownership is unknown") {
		t.Fatalf("stdout missing ownership-kept message:\n%s", h.out.String())
	}
}

func TestUninstallRejectsStaleOrganizationConfigBeforeKeepingManagedHooks(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "cannot determine whether this Mac is organization-managed") {
		t.Fatalf("Uninstall() error = %v, want ownership failure", err)
	}
	if _, err := os.Stat(managedSettingsPath); err != nil {
		t.Fatalf("managed settings changed after ownership failure: %v", err)
	}
	if h.out.Len() != 0 {
		t.Fatalf("stdout = %q, want no uninstall progress before ownership failure", h.out.String())
	}
}

func TestInstallManagedSettingsUsesSudoWhenNotRoot(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &geteuid, func() int { return 501 })
	data, err := managedSettingsData("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := installManagedSettings(context.Background(), data); err != nil {
		t.Fatalf("installManagedSettings() error = %v", err)
	}

	var sudo [][]string
	for _, call := range h.calls {
		if call.name == "sudo" {
			sudo = append(sudo, call.args)
		}
	}
	if len(sudo) != 2 || sudo[0][0] != "mkdir" || sudo[1][0] != "install" {
		t.Fatalf("sudo calls = %v, want mkdir then install", sudo)
	}
}

func TestWritePrivilegedFileRootWritesAtomicallyWithMode(t *testing.T) {
	newHarness(t)
	path := filepath.Join(t.TempDir(), "managed-settings.d", "20-kontext.json")

	if err := writePrivilegedFile(context.Background(), path, []byte(`{"hooks":{}}`+"\n")); err != nil {
		t.Fatalf("writePrivilegedFile() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"hooks\":{}}\n" {
		t.Fatalf("data = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644", info.Mode().Perm())
	}
}

func TestRemoveManagedSettingsRootTreatsMissingAfterReadAsSuccess(t *testing.T) {
	newHarness(t)
	path := filepath.Join(t.TempDir(), "20-kontext.json")
	data, err := managedSettingsData("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &managedSettingsPath, path)
	remove := os.Remove
	removedDuringStat := false
	overrideVar(t, &geteuid, func() int {
		if !removedDuringStat {
			removedDuringStat = true
			if err := remove(path); err != nil {
				t.Fatalf("remove during race setup: %v", err)
			}
		}
		return 0
	})

	removed, err := removeManagedSettings(context.Background())
	if err != nil {
		t.Fatalf("removeManagedSettings() error = %v", err)
	}
	if !removed {
		t.Fatal("removeManagedSettings() reported kept for an owned drop-in")
	}
}

func TestRunRejectsTokenWithControlCharacters(t *testing.T) {
	// A token must never be able to smuggle a second line into the
	// `security -i` command stream.
	h := newHarness(t)
	allowLoopback(t)
	server := pingServer(t, "x")

	// Leading/trailing whitespace must FAIL, never be silently trimmed —
	// the stored credential must be byte-identical to what was pasted.
	for _, token := range []string{"a\nb", "a b", "a\tb", "a\rb", " abc", "abc\n", "abc "} {
		err := Run(context.Background(), h.options(token, server))
		if err == nil || !strings.Contains(err.Error(), "whitespace or control") {
			t.Fatalf("Run(token=%q) error = %v, want shape rejection", token, err)
		}
	}
	if len(h.keychain) != 0 {
		t.Fatal("keychain written despite malformed token")
	}
}

func TestInstallLaunchAgentRejectsLoadedStaleJob(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "Boot-out failed", errors.New("exit status 5")
		}
		// `launchctl print` succeeding means the stale service is still loaded.
		return "", nil
	})

	_, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil)
	if err == nil || !strings.Contains(err.Error(), "launchctl bootout failed") {
		t.Fatalf("installLaunchAgent() error = %v, want stale loaded job failure", err)
	}
}

func TestInstallLaunchAgentBootsOutOwnedPlistBeforeBootstrap(t *testing.T) {
	h := newHarness(t)

	_, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil)
	if err != nil {
		t.Fatal(err)
	}
	var launchctl [][]string
	for _, call := range h.calls {
		if call.name == "launchctl" {
			launchctl = append(launchctl, call.args)
		}
	}
	if len(launchctl) < 2 {
		t.Fatalf("launchctl calls = %v, want bootout then bootstrap", launchctl)
	}
	if launchctl[0][0] != "bootout" || len(launchctl[0]) != 3 || !strings.HasSuffix(launchctl[0][2], ".plist") {
		t.Fatalf("bootout args = %v, want domain + plist path", launchctl[0])
	}
	if launchctl[1][0] != "bootstrap" {
		t.Fatalf("second launchctl call = %v, want bootstrap", launchctl[1])
	}
}

func TestInstallLaunchAgentIgnoresBootoutWhenServiceIsAbsent(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name != "launchctl" {
			return "", nil
		}
		switch args[0] {
		case "bootout":
			return "No such process", errors.New("exit status 113")
		case "print":
			return "Could not find service", errors.New("exit status 113")
		default:
			return "", nil
		}
	})

	if _, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil); err != nil {
		t.Fatal(err)
	}
}

func TestInstallLaunchAgentBoundsMutatingLaunchctlCalls(t *testing.T) {
	h := newHarness(t)
	checked := 0
	overrideVar(t, &execCommand, func(ctx context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name != "launchctl" {
			return "", nil
		}
		switch args[0] {
		case "bootout", "bootstrap":
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatalf("launchctl %v ran without a deadline", args)
			}
			remaining := time.Until(deadline)
			if remaining <= 0 || remaining > launchctlCommandTimeout {
				t.Fatalf("launchctl deadline remaining = %s, want within %s", remaining, launchctlCommandTimeout)
			}
			checked++
		}
		return "", nil
	})

	if _, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil); err != nil {
		t.Fatal(err)
	}
	if checked != 2 {
		t.Fatalf("bounded launchctl calls = %d, want 2", checked)
	}
}

func TestInstallLaunchAgentSurfacesBootstrapFailure(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootstrap" {
			return "Bootstrap failed: 17: File exists", errors.New("exit status 17")
		}
		return "", nil
	})

	_, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil)
	if err == nil || !strings.Contains(err.Error(), "launchctl bootstrap failed") {
		t.Fatalf("installLaunchAgent() error = %v, want bootstrap failure", err)
	}
}

func TestInstallLaunchAgentDoesNotKickstartAfterBootstrap(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name != "launchctl" {
			return "", nil
		}
		if args[0] == "kickstart" {
			t.Fatalf("installLaunchAgent should not kickstart after bootstrap: %v", args)
		}
		return "", nil
	})

	if _, _, err := installLaunchAgent(context.Background(), "/opt/homebrew/bin/kontext", nil); err != nil {
		t.Fatalf("installLaunchAgent() error = %v", err)
	}
}

func TestRemoveLaunchAgentDoesNotTreatUnknownServiceStateAsAbsent(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(ctx context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name != "launchctl" {
			return "", nil
		}
		switch args[0] {
		case "bootout":
			return "No such process", errors.New("exit status 113")
		case "print":
			if _, ok := ctx.Deadline(); ok {
				t.Fatal("uninstall service-state check must not use the install timeout")
			}
			return "timed out", context.DeadlineExceeded
		default:
			return "", nil
		}
	})

	_, err := removeLaunchAgent(context.Background())
	if err == nil || !strings.Contains(err.Error(), "state is unknown") {
		t.Fatalf("removeLaunchAgent() error = %v, want unknown-state failure", err)
	}
}

func TestRemoveLaunchAgentAcceptsKnownAbsentServiceState(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name != "launchctl" {
			return "", nil
		}
		switch args[0] {
		case "bootout":
			return "No such process", errors.New("exit status 113")
		case "print":
			return "Could not find service", errors.New("exit status 113")
		default:
			return "", nil
		}
	})

	if _, err := removeLaunchAgent(context.Background()); err != nil {
		t.Fatalf("removeLaunchAgent() error = %v, want known absent service accepted", err)
	}
}

func TestUninstallWithoutSettingsFileDoesNotCreateOne(t *testing.T) {
	// A removal must never CREATE config: uninstall on a machine with no
	// ~/.claude/settings.json leaves none behind.
	h := newHarness(t)

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v", err)
	}
	settingsPath := filepath.Join(h.home, ".claude", "settings.json")
	if _, err := os.Lstat(settingsPath); !os.IsNotExist(err) {
		t.Fatalf("uninstall created %s", settingsPath)
	}
	codexHooksPath := filepath.Join(h.home, ".codex", "hooks.json")
	if _, err := os.Lstat(codexHooksPath); !os.IsNotExist(err) {
		t.Fatalf("uninstall created %s", codexHooksPath)
	}
	if _, err := os.Lstat(filepath.Dir(codexHooksPath)); !os.IsNotExist(err) {
		t.Fatalf("uninstall created %s", filepath.Dir(codexHooksPath))
	}
}

func TestUninstallSurfacesKeychainFailures(t *testing.T) {
	// A locked/denied keychain must fail uninstall loudly — not report the
	// token as removed while it still exists.
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "security" && len(args) > 0 && args[0] == "delete-generic-password" {
			return "SecKeychainItemDelete: User interaction is not allowed.", errors.New("exit status 36")
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "delete keychain item") {
		t.Fatalf("Uninstall() error = %v, want keychain failure surfaced", err)
	}
}

func TestDeleteKeychainTokensAcceptsNotFoundVariants(t *testing.T) {
	for _, output := range []string{
		"security: The specified item could not be found in the keychain.",
		"SECURITY: THE SPECIFIED ITEM COULD NOT BE FOUND IN THE KEYCHAIN.",
		"item not found",
	} {
		t.Run(output, func(t *testing.T) {
			overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
				return output, errors.New("exit status 44")
			})
			if err := deleteKeychainTokens(context.Background(), KeychainItemName); err != nil {
				t.Fatalf("deleteKeychainTokens() error = %v, want nil", err)
			}
		})
	}
}

func TestUninstallSurfacesLaunchAgentBootoutFailure(t *testing.T) {
	h := newHarness(t)
	plistPath := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if err := os.MkdirAll(filepath.Dir(plistPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plistPath, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "permission denied", errors.New("exit status 5")
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "launchctl bootout failed") {
		t.Fatalf("Uninstall() error = %v, want bootout failure surfaced", err)
	}
}

func TestUninstallSurfacesLoadedLaunchAgentWithoutPlist(t *testing.T) {
	h := newHarness(t)
	overrideVar(t, &execCommand, func(_ context.Context, stdin, name string, args ...string) (string, error) {
		h.calls = append(h.calls, execCall{stdin: stdin, name: name, args: args})
		if name == "launchctl" && args[0] == "bootout" {
			return "No such file", errors.New("exit status 5")
		}
		if name == "launchctl" && args[0] == "print" {
			return "service is loaded", nil
		}
		return "", nil
	})

	err := Uninstall(context.Background(), h.options("", pingServer(t, "unused")))
	if err == nil || !strings.Contains(err.Error(), "still loaded") {
		t.Fatalf("Uninstall() error = %v, want loaded service failure", err)
	}
}

func TestUninstallBootsOutByPlistPath(t *testing.T) {
	// Bootout must target OUR plist, not the shared label — a label-target
	// bootout could unload an MDM agent holding the same label.
	h := newHarness(t)
	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatal(err)
	}
	for _, call := range h.calls {
		if call.name == "launchctl" && call.args[0] == "bootout" {
			if len(call.args) != 3 || !strings.HasSuffix(call.args[2], ".plist") {
				t.Fatalf("bootout args = %v, want domain + plist path", call.args)
			}
			return
		}
	}
	t.Fatal("no bootout call recorded")
}

func TestSecurityQuote(t *testing.T) {
	cases := map[string]string{
		`plain`:      `"plain"`,
		`with"quote`: `"with\"quote"`,
		`back\slash`: `"back\\slash"`,
	}
	for in, want := range cases {
		if got := securityQuote(in); got != want {
			t.Errorf("securityQuote(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestStableBinaryPathPrefersBrewSymlink(t *testing.T) {
	// Non-Cellar paths pass through untouched.
	overrideVar(t, &executablePath, func() (string, error) { return "/usr/local/bin/kontext", nil })
	if got, note := stableBinaryPath(); got != "/usr/local/bin/kontext" || note != "" {
		t.Fatalf("stableBinaryPath() = %q, %q", got, note)
	}

	// Cellar path with no matching stable symlink keeps the Cellar path and
	// warns about brew upgrades.
	overrideVar(t, &executablePath, func() (string, error) {
		return "/usr/local/Cellar/kontext/1.0.0/bin/kontext", nil
	})
	got, note := stableBinaryPath()
	if got != "/usr/local/Cellar/kontext/1.0.0/bin/kontext" || !strings.Contains(note, "brew upgrade") {
		t.Fatalf("stableBinaryPath() = %q, %q", got, note)
	}
}
