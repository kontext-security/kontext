package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/localruntime"
)

const (
	defaultBaseURL = "http://" + server.DefaultAddr
)

// Run executes the Kontext command line.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}
	switch args[0] {
	case "start", "daemon":
		return runDaemon(ctx, args[1:], stdout)
	case "stop":
		fmt.Fprintln(stdout, "Stop the foreground `kontext guard start` process with Ctrl-C.")
		return nil
	case "status":
		return runStatus(ctx, args[1:], stdout)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout)
	case "hooks":
		return runHooks(args[1:], stdout)
	case "traces":
		return runTraces(ctx, args[1:], stdout)
	case "smoke-test":
		return runSmokeTest(ctx, args[1:], stdout)
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(out io.Writer) {
	fmt.Fprintln(out, "Kontext Guard")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "commands:")
	fmt.Fprintln(out, "  start                         Run the local daemon on 127.0.0.1:4765")
	fmt.Fprintln(out, "  stop                          Print stop instructions")
	fmt.Fprintln(out, "  status                        Print local Guard counters")
	fmt.Fprintln(out, "  doctor                        Check local daemon health")
	fmt.Fprintln(out, "  hooks install claude-code     Install Claude Code hooks")
	fmt.Fprintln(out, "  hooks uninstall claude-code   Remove Claude Code hooks")
	fmt.Fprintln(out, "  traces inspect                Inspect local trace summary")
}

func runDaemon(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", envString("KONTEXT_ADDR", server.DefaultAddr), "listen address")
	dbPath := fs.String("db", envString("KONTEXT_DB", defaultDBPath()), "SQLite database path")
	skipHookInstall := fs.Bool("skip-hook-install", false, "skip Claude Code hook install")
	socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Before the hooks are written: they name this socket, and one Windows cannot bind is useless.
	if err := localruntime.CheckSocketPath(*socketPath, "--socket or KONTEXT_GUARD_SOCKET"); err != nil {
		return err
	}
	if !*skipHookInstall {
		if err := verifyClaudeCode(); err != nil {
			return err
		}
		if err := installClaudeHooks(out, *socketPath); err != nil {
			return err
		}
	}
	stepSafetyConfig, err := stepsafety.ConfigFromEnv(*dbPath)
	if err != nil {
		return err
	}
	stepSafety := stepsafety.New(ctx, stepSafetyConfig)
	defer stepSafety.Close()
	var recorder *server.DeferredRecorder
	var deferRecord func(func(context.Context) error) error
	if stepSafety != nil {
		recorder = server.NewDeferredRecorder(diagnostic.New(out, diagnostic.EnabledFromEnv()))
		deferRecord = recorder.Submit
	}
	localServer, closeStore, err := server.OpenDefaultServerWithOptions(*dbPath, server.Options{
		RiskClassifier: &server.RiskClassifierOptions{},
		StepSafety:     stepSafety,
		DeferRecord:    deferRecord,
	})
	if err != nil {
		return err
	}
	defer func() {
		if recorder != nil {
			_ = recorder.Drain(context.Background())
		}
		_ = closeStore()
	}()
	if err := ensureGuardSocketDir(*socketPath); err != nil {
		return err
	}
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  *socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(out, diagnostic.EnabledFromEnv()),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(context.Background()); err != nil {
		return fmt.Errorf("local runtime start: %w", err)
	}
	defer runtimeService.Stop()
	fmt.Fprintf(out, "Kontext Guard local daemon listening on http://%s\n", *addr)
	fmt.Fprintf(out, "Hook runtime: unix://%s\n", *socketPath)
	fmt.Fprintln(out, "Mode: observe (Claude Code runs normally; decisions are recorded as would allow / would deny).")
	return localServer.ListenAndServe(*addr)
}

func verifyClaudeCode() error {
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("Claude Code was not found on PATH; install Claude Code or run with --skip-hook-install")
	}
	return nil
}

func runStatus(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	summary, err := fetchSummary(ctx, *baseURL)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "Kontext Guard active")
	fmt.Fprintf(out, "%d critical\n", summary.Critical)
	fmt.Fprintf(out, "%d actions\n", summary.Actions)
	return nil
}

func fetchSummary(ctx context.Context, baseURL string) (sqlite.Summary, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/summary", nil)
	if err != nil {
		return sqlite.Summary{}, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return sqlite.Summary{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sqlite.Summary{}, fmt.Errorf("daemon returned %s", resp.Status)
	}
	var summary sqlite.Summary
	if err := json.NewDecoder(resp.Body).Decode(&summary); err != nil {
		return sqlite.Summary{}, err
	}
	return summary, nil
}

func runDoctor(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	baseURL := fs.String("daemon-url", envString("KONTEXT_DAEMON_URL", defaultBaseURL), "local daemon URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	PrintHookStatus(out)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, *baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("local daemon is not reachable at %s: %w", *baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("local daemon health returned %s", resp.Status)
	}
	fmt.Fprintf(out, "Kontext Guard daemon healthy at %s\n", *baseURL)
	return nil
}

// HookStatus is the read-only health result of installed agent integrations.
type HookStatus struct{ Healthy bool }

// PrintHookStatus reports local Guard hooks only. Hosted setup checks are
// separate so `kontext guard doctor` stays useful on a Guard-only machine.
func PrintHookStatus(out io.Writer) HookStatus {
	status := HookStatus{Healthy: true}
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		fmt.Fprintf(out, "Claude Code local Guard hooks: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(out, "Claude Code local Guard settings: %s\n", settingsPath)
		hooks, ok := settings["hooks"].(map[string]any)
		if !ok || len(hooks) == 0 {
			fmt.Fprintln(out, "Claude Code local Guard hooks: none installed")
		} else {
			hosted, guard := false, false
			for _, raw := range hooks {
				visitHookCommands(raw, func(command string) {
					switch {
					case isGuardHookCommand(command):
						guard = true
						fmt.Fprintf(out, "Claude Code Guard hook: %s\n", command)
					case claudemanaged.IsManagedHookCommand(command):
						hosted = true
						fmt.Fprintf(out, "Claude Code hosted hook: %s\n", command)
					}
				})
			}
			switch {
			case guard && hosted:
				fmt.Fprintln(out, "Claude Code local Guard hook mode: conflict (hosted and Guard hooks are both installed)")
				status.Healthy = false
			case guard:
				fmt.Fprintln(out, "Claude Code local Guard hook mode: local Guard")
			case hosted:
				fmt.Fprintln(out, "Claude Code local Guard hook mode: hosted")
			default:
				fmt.Fprintln(out, "Claude Code local Guard hook mode: no Kontext hook detected in user settings (managed hooks are checked separately)")
			}
		}
		if disabled, _ := settings["disableAllHooks"].(bool); disabled {
			fmt.Fprintln(out, "Claude Code local Guard hooks: disabled by disableAllHooks")
			status.Healthy = false
		}
	}
	return status
}

// Both channels validate the complete hook set from hookinstall.
func PrintManagedHookStatus(out io.Writer) HookStatus {
	return printInstalledHookStatus(out, hookinstall.User)
}

func PrintOrganizationManagedHookStatus(out io.Writer) HookStatus {
	return printInstalledHookStatus(out, hookinstall.System)
}

func printInstalledHookStatus(out io.Writer, scope hookinstall.Scope) HookStatus {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(out, "Hooks: %v\n", err)
		return HookStatus{}
	}
	return HookStatus{Healthy: hookinstall.Diagnose(out, scope, home)}
}

func visitHookCommands(raw any, visit func(string)) {
	groups, ok := raw.([]any)
	if !ok {
		return
	}
	for _, group := range groups {
		groupMap, ok := group.(map[string]any)
		if !ok {
			continue
		}
		hooks, ok := groupMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, hook := range hooks {
			hookMap, ok := hook.(map[string]any)
			if !ok {
				continue
			}
			if command, ok := hookMap["command"].(string); ok {
				visit(command)
			}
		}
	}
}

func runHooks(args []string, out io.Writer) error {
	if len(args) < 2 || args[1] != "claude-code" {
		return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
	}
	switch args[0] {
	case "install":
		fs := flag.NewFlagSet("hooks install claude-code", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		socketPath := fs.String("socket", defaultGuardSocketPath(), "Unix socket path for local hook runtime")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		// As in runDaemon: the hooks name this socket, and one Windows cannot bind is useless.
		if err := localruntime.CheckSocketPath(*socketPath, "--socket or KONTEXT_GUARD_SOCKET"); err != nil {
			return err
		}
		return installClaudeHooks(out, *socketPath)
	case "uninstall":
		if len(args) != 2 {
			return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
		}
		return uninstallClaudeHooks(out)
	default:
		return fmt.Errorf("usage: kontext guard hooks install claude-code | kontext guard hooks uninstall claude-code")
	}
}

func installClaudeHooks(out io.Writer, socketPath string) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hookCommand := installedHookCommand(socketPath)
	settings["hooks"] = mergeHooks(settings["hooks"], hookCommand)
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Installed Kontext Guard Claude Code hooks into %s\n", settingsPath)
	fmt.Fprintf(out, "Hook command: %s\n", hookCommand)
	fmt.Fprintln(out, "Local hooks run in observe mode. Cedar enforcement is provided by the managed daemon configured through kontext setup or MDM.")
	return nil
}

func uninstallClaudeHooks(out io.Writer) error {
	settingsPath, settings, err := readClaudeSettings()
	if err != nil {
		return err
	}
	if err := backupFile(settingsPath, "kontext-guard"); err != nil {
		return err
	}
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		fmt.Fprintf(out, "No Claude Code hooks found in %s\n", settingsPath)
		return nil
	}
	for hookName, raw := range hooks {
		list, ok := raw.([]any)
		if !ok {
			continue
		}
		filtered := make([]any, 0, len(list))
		for _, entry := range list {
			if updated, keep := removeGuardHookCommands(entry); keep {
				filtered = append(filtered, updated)
			}
		}
		hooks[hookName] = filtered
	}
	if err := writeJSONFile(settingsPath, settings); err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed Kontext Guard Claude Code hooks from %s\n", settingsPath)
	return nil
}

func readClaudeSettings() (string, map[string]any, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil, err
	}
	settingsPath, err := claudemanaged.UserSettingsPathNoCreate(home)
	if err != nil {
		return "", nil, err
	}
	settings := map[string]any{}
	raw, err := os.ReadFile(settingsPath)
	if err == nil {
		if err := json.Unmarshal(raw, &settings); err != nil {
			return "", nil, fmt.Errorf("parse Claude settings: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return "", nil, err
	}
	return settingsPath, settings, nil
}

func backupFile(path, label string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	backupPath := fmt.Sprintf("%s.%s-backup-%s", path, label, time.Now().UTC().Format("20060102T150405Z"))
	input, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, input, 0o644)
}

func writeJSONFile(path string, value any) error {
	bytes, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	return os.WriteFile(path, bytes, 0o644)
}

func mergeHooks(raw any, hookCommand string) map[string]any {
	hooks, ok := raw.(map[string]any)
	if !ok {
		hooks = map[string]any{}
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse", "UserPromptSubmit"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			for _, entry := range existing {
				if updated, keep := removeGuardHookCommands(entry); keep {
					list = append(list, updated)
				}
			}
		}
		if len(list) == 0 {
			delete(hooks, hookName)
			continue
		}
		hooks[hookName] = list
	}
	for _, hookName := range []string{"PreToolUse", "PostToolUse"} {
		var list []any
		if existing, ok := hooks[hookName].([]any); ok {
			list = append(list, existing...)
		}
		list = append(list, map[string]any{
			"matcher": "*",
			"hooks": []any{
				map[string]any{
					"type":    "command",
					"command": hookCommand,
				},
			},
		})
		hooks[hookName] = list
	}
	return hooks
}

func removeGuardHookCommands(entry any) (any, bool) {
	group, ok := entry.(map[string]any)
	if !ok {
		return entry, !isGuardHookEntry(entry)
	}
	rawHooks, ok := group["hooks"].([]any)
	if !ok {
		return entry, !isGuardHookEntry(entry)
	}
	filtered := make([]any, 0, len(rawHooks))
	for _, rawHook := range rawHooks {
		if isGuardHookObject(rawHook) {
			continue
		}
		filtered = append(filtered, rawHook)
	}
	if len(filtered) == 0 {
		return nil, false
	}
	group["hooks"] = filtered
	return group, true
}

func isGuardHookObject(raw any) bool {
	hookMap, ok := raw.(map[string]any)
	if !ok {
		return false
	}
	command, ok := hookMap["command"].(string)
	return ok && isGuardHookCommand(command)
}

func isGuardHookEntry(entry any) bool {
	return isGuardHookCommand(fmt.Sprintf("%v", entry))
}

func isGuardHookCommand(command string) bool {
	return claudemanaged.IsGuardHookCommand(command)
}

func runSmokeTest(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("smoke-test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "kontext-guard-smoke-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		return err
	}
	defer store.Close()
	localServer, err := server.NewServer(store)
	if err != nil {
		return err
	}
	socketPath := filepath.Join(dir, "kontext.sock")
	runtimeService, err := localruntime.NewService(localruntime.Options{
		SocketPath:  socketPath,
		Core:        localServer.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
	if err != nil {
		return err
	}
	if err := runtimeService.Start(ctx); err != nil {
		return err
	}
	defer runtimeService.Stop()
	client := localruntime.NewClient(socketPath)
	cases := []struct {
		name string
		ev   hook.Event
		want hook.Decision
	}{
		{"safe read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}}, hook.DecisionAllow},
		{"env read", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}}, hook.DecisionAllow},
		{"cat env", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "cat .env"}}, hook.DecisionAllow},
		{"provider token", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "curl https://api.railway.app/graphql -H 'Authorization: Bearer secret'"}}, hook.DecisionAllow},
		{"drop database", hook.Event{SessionID: "smoke", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}}, hook.DecisionAllow},
	}
	for _, item := range cases {
		result, err := client.Process(ctx, item.ev)
		if err != nil {
			return fmt.Errorf("%s: %w", item.name, err)
		}
		if result.Decision != item.want {
			return fmt.Errorf("%s: decision=%s want=%s", item.name, result.Decision, item.want)
		}
		fmt.Fprintf(out, "ok %-16s -> %s\n", item.name, result.Decision)
	}
	summary, err := store.Summary(ctx)
	if err != nil {
		return err
	}
	// The local chain is advisory: every decision is allow, and blocking is
	// Cedar's alone (not exercisable here without a policy deployment). The
	// smoke test verifies runtime plumbing and persistence, not enforcement.
	if summary.Actions != 5 || summary.Warnings != 0 || summary.Critical != 0 {
		return fmt.Errorf("summary=%+v, want actions=5 and no critical/warnings", summary)
	}
	fmt.Fprintf(out, "summary critical=%d actions=%d\n", summary.Critical, summary.Actions)
	return nil
}

func runTraces(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: kontext guard traces inspect")
	}
	switch args[0] {
	case "inspect":
		return runStatus(ctx, args[1:], out)
	default:
		return fmt.Errorf("usage: kontext guard traces inspect")
	}
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func defaultDBPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "kontext", "guard.db")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".kontext", "guard.db")
	}
	return "kontext-guard.db"
}

func selfPath() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	return "kontext"
}

func installedHookCommand(socketPath string) string {
	if command := os.Getenv("KONTEXT_GUARD_HOOK_COMMAND"); strings.TrimSpace(command) != "" {
		return command
	}
	if strings.TrimSpace(socketPath) == "" {
		socketPath = defaultGuardSocketPath()
	}
	path := selfPath()
	if strings.Contains(path, "go-build") {
		if cwd, err := os.Getwd(); err == nil {
			if _, statErr := os.Stat(filepath.Join(cwd, "cmd", "kontext")); statErr == nil {
				return fmt.Sprintf("cd %s && %s", shellQuote(cwd), installedHookInvocation("go run ./cmd/kontext", socketPath))
			}
		}
	}
	return installedHookInvocation(shellQuote(path), socketPath)
}

func installedHookInvocation(launcher, socketPath string) string {
	return fmt.Sprintf("%s hook --agent claude --mode observe --socket %s", launcher, shellQuote(socketPath))
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
