package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/buildinfo"
	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	guardcli "github.com/kontext-security/kontext-cli/internal/guard/cli"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookcmd"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/spf13/cobra"

	_ "github.com/kontext-security/kontext-cli/internal/agent/claude"
	_ "github.com/kontext-security/kontext-cli/internal/agent/codex"
	_ "github.com/kontext-security/kontext-cli/internal/agent/cowork"
)

var version = "dev"

var userHomeDir = os.UserHomeDir

func main() {
	root := newRootCmd()
	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "kontext",
		Short: "Kontext CLI — governed agent sessions",
		// Reported with the source revision appended, because the version
		// string on its own cannot answer "which build is this": it is a
		// link-time label, and release channels that name builds by date give
		// no way to tell two sources apart. Every other use of `version` stays
		// the bare string — only what a human reads gains the revision.
		Version: buildinfo.Describe(version),
	}

	root.AddCommand(setupCmd())
	root.AddCommand(profileCmd())
	root.AddCommand(hookCmd())
	root.AddCommand(managedObserveDaemonCmd())
	root.AddCommand(doctorCmd())
	root.AddCommand(claudeCmd())
	root.AddCommand(guardCmd())
	return root
}

func doctorCmd() *cobra.Command {
	var fix bool
	var asJSON bool
	cmd := &cobra.Command{
		Use:           "doctor",
		Short:         "Inspect local Kontext CLI setup",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if asJSON {
				if fix {
					return errors.New("--json and --fix cannot be combined; run the repair first, then re-run with --json")
				}
				return runDoctorJSON(cmd.OutOrStdout())
			}
			managed := managedobserve.PrintStatus(cmd.OutOrStdout(), version)
			hooksHealthy, localHooksHealthy := checkHooks(cmd.OutOrStdout(), managed)
			healthy := overallHealthy(managed, hooksHealthy, localHooksHealthy)
			if fix {
				if !managed.Repairable {
					if healthy {
						fmt.Fprintln(cmd.OutOrStdout(), "nothing to fix")
						return nil
					}
					fmt.Fprintln(cmd.OutOrStdout(), "no automatic fixes are available for the reported issues")
					return errDoctorUnhealthy
				}
				ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				defer cancel()
				if err := managedobserve.KickstartLaunchdKill(ctx, managedobserve.DefaultLabel()); err != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "failed to restart managed-observe daemon: %v\n", err)
					return err
				}
				// launchd accepting the kickstart is not a comeback: the new
				// daemon can exit immediately (unreadable token, codesigning
				// kill). Only report success once the restarted daemon is
				// serving on the installed version.
				waitCtx, waitCancel := context.WithTimeout(cmd.Context(), 10*time.Second)
				defer waitCancel()
				status, err := managedobserve.WaitForDaemonRestart(
					waitCtx,
					managedobserve.DefaultDBPath(),
					managedobserve.DefaultSocketPath(),
					version,
				)
				if err != nil {
					fmt.Fprintln(cmd.ErrOrStderr(), "daemon has not come back within 10s — it may still be restarting; re-run `kontext doctor` in a minute and check ~/Library/Logs/Kontext/managed-observe.log")
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "restarted managed-observe daemon (v%s, pid %d)\n", status.Version, status.PID)
				fmt.Fprintln(cmd.OutOrStdout(), "\nAfter repair:")
				managed = managedobserve.PrintStatus(cmd.OutOrStdout(), version)
				hooksHealthy, localHooksHealthy = checkHooks(cmd.OutOrStdout(), managed)
				healthy = overallHealthy(managed, hooksHealthy, localHooksHealthy)
			}
			if !healthy {
				return errDoctorUnhealthy
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&fix, "fix", false, "restart the managed-observe daemon when it is running a stale binary")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON instead of the human readout")
	return cmd
}

// checkHooks reports hook health for a managed-observe status, writing its
// readout to out. Shared by the text and JSON paths so the two can never
// disagree about what "healthy" means.
func checkHooks(out io.Writer, managed managedobserve.DoctorStatus) (managedHooks, localHooks bool) {
	managedHooks = true
	if managed.SelfServe {
		managedHooks = guardcli.PrintManagedHookStatus(out).Healthy
	} else if managed.Configured {
		managedHooks = guardcli.PrintOrganizationManagedHookStatus(out).Healthy
	}
	localHooks = guardcli.PrintHookStatus(out).Healthy
	return managedHooks, localHooks
}

// overallHealthy is the single definition of a healthy install. Local hook
// health only counts once the machine is configured at all.
func overallHealthy(managed managedobserve.DoctorStatus, managedHooks, localHooks bool) bool {
	return managed.Healthy && managedHooks && (!managed.Configured || localHooks)
}

// doctorJSONPayload is the documented shape of `kontext doctor --json`.
//
// This is a CONSUMED CONTRACT, not an internal detail: external tooling decodes
// it (see docs/json-contract.md). Its key set is pinned by a test, so adding,
// removing, or renaming a field is a deliberate act with a failing test rather
// than a silent break in something that is not built from this repository.
type doctorJSONPayload struct {
	managedobserve.Report
	ManagedHooksHealthy bool `json:"managed_hooks_healthy"`
	LocalHooksHealthy   bool `json:"local_hooks_healthy"`
}

// runDoctorJSON emits the report a GUI consumes. Unlike the text form it exits
// zero even when unhealthy: the caller reads `healthy` from the payload, and a
// non-zero exit would leave it interpreting both a status code and a document
// that already says the same thing.
func runDoctorJSON(out io.Writer) error {
	managed, report := managedobserve.Diagnose(io.Discard, version)
	managedHooks, localHooks := checkHooks(io.Discard, managed)
	report.Healthy = overallHealthy(managed, managedHooks, localHooks)

	payload := doctorJSONPayload{
		Report:              report,
		ManagedHooksHealthy: managedHooks,
		LocalHooksHealthy:   localHooks,
	}

	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

var errDoctorUnhealthy = errors.New("local Kontext setup is unhealthy")

func guardCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "guard",
		Short:              "Run local-only Kontext Guard mode",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return guardcli.Run(context.Background(), args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
}

func claudeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "claude",
		Short: "Manage Claude Code integration",
	}
	cmd.AddCommand(claudeManagedSettingsCmd())
	return cmd
}

func claudeManagedSettingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "managed-settings",
		Short: "Render and validate Claude Code managed settings",
	}
	cmd.AddCommand(claudeManagedSettingsTemplateCmd())
	cmd.AddCommand(claudeManagedSettingsValidateCmd())
	return cmd
}

func claudeManagedSettingsTemplateCmd() *cobra.Command {
	var kontextBinary string

	cmd := &cobra.Command{
		Use:   "template",
		Short: "Print Claude Code managed settings for Kontext hooks",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := claudemanaged.TemplateJSON(kontextBinary)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
	cmd.Flags().StringVar(&kontextBinary, "kontext-binary", claudemanaged.DefaultKontextBinary, "Kontext executable path for managed hooks")
	return cmd
}

func claudeManagedSettingsValidateCmd() *cobra.Command {
	var kontextBinary string

	cmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate Claude Code managed settings for Kontext hooks",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := claudemanaged.DefaultManagedSettingsPath()
			if len(args) == 1 {
				path = args[0]
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read managed settings: %w", err)
			}
			if err := claudemanaged.Validate(data, kontextBinary); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Claude managed settings valid: %s\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&kontextBinary, "kontext-binary", claudemanaged.DefaultKontextBinary, "Kontext executable path expected in managed hooks")
	return cmd
}

func hookCmd() *cobra.Command {
	var (
		agentName  string
		socketPath string
		mode       string
	)

	cmd := &cobra.Command{
		Use:    "hook [event]",
		Short:  "Process a hook event (called by the agent, not by users)",
		Hidden: true,
		Args: func(cmd *cobra.Command, args []string) error {
			_, err := expectedHookEventFromArgs(args)
			return err
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			expectedEvent, err := expectedHookEventFromArgs(args)
			if err != nil {
				return err
			}
			a, ok := agent.Get(agentName)
			if !ok {
				fmt.Fprintf(os.Stderr, "unknown agent: %s\n", agentName)
				os.Exit(2)
			}

			explicitSocket := cmd.Flags().Changed("socket")
			explicitMode := cmd.Flags().Changed("mode")
			if shouldUseManagedObserve(explicitSocket, explicitMode) {
				lifecycle := managedobserve.NewLifecycle()
				lifecycle.Diagnostic = diagnostic.New(cmd.ErrOrStderr(), diagnostic.EnabledFromEnv())
				hookcmd.RunWithExpectedEvent(managedHookAgent{Agent: a}, expectedEvent, func(e hook.Event) (hook.Result, error) {
					return lifecycle.Process(context.Background(), e), nil
				})
				return nil
			}

			resolvedSocketPath := resolveHookSocketPath(socketPath)
			if mode != "" {
				hookMode, err := guardhookruntime.ParseMode(mode)
				if err != nil {
					return err
				}
				var adapter guardhookruntime.Adapter = guardhookruntime.AgentAdapter{Agent: a, AgentName: agentName}
				if expectedEvent != "" {
					adapter = expectedHookAdapter{Adapter: adapter, expected: expectedEvent}
				}
				processor := rootHookProcessor{socketPath: resolvedSocketPath, mode: hookMode}
				return guardhookruntime.Run(context.Background(), adapter, processor, hookMode, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			hookcmd.RunWithExpectedEvent(a, expectedEvent, func(e hook.Event) (hook.Result, error) {
				return evaluateHookWithSidecar(resolvedSocketPath, e)
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&agentName, "agent", "claude", "Agent type")
	cmd.Flags().StringVar(&socketPath, "socket", "", "Unix socket path for local hook runtime")
	cmd.Flags().StringVar(&mode, "mode", "", "hook mode: observe or enforce")

	return cmd
}

type managedHookAgent struct {
	agent.Agent
}

func (a managedHookAgent) DecodeHookInput(input []byte) (hook.Event, error) {
	event, err := a.Agent.DecodeHookInput(input)
	if err != nil {
		return hook.Event{}, err
	}
	if isCoworkHookContext(input, event) {
		event.Agent = "cowork"
	}
	return event, nil
}

func isCoworkHookContext(input []byte, event hook.Event) bool {
	if isCoworkPath(event.CWD) {
		return true
	}
	var paths struct {
		TranscriptPathSnake string `json:"transcript_path"`
		TranscriptPathCamel string `json:"transcriptPath"`
		SessionPathSnake    string `json:"session_path"`
		SessionPathCamel    string `json:"sessionPath"`
	}
	if err := json.Unmarshal(input, &paths); err != nil {
		return false
	}
	for _, value := range []string{paths.TranscriptPathSnake, paths.TranscriptPathCamel, paths.SessionPathSnake, paths.SessionPathCamel} {
		if isCoworkPath(value) {
			return true
		}
	}
	return false
}

func isCoworkPath(value string) bool {
	normalized := strings.ReplaceAll(value, "\\", "/")
	home, err := userHomeDir()
	if err != nil || home == "" {
		return false
	}
	root := strings.ReplaceAll(home, "\\", "/") + "/Library/Application Support/Claude/local-agent-mode-sessions"
	if normalized != root && !strings.HasPrefix(normalized, root+"/") {
		return false
	}
	suffix := strings.TrimPrefix(strings.TrimPrefix(normalized, root), "/")
	parts := strings.Split(suffix, "/")
	return len(parts) >= 3 && parts[0] != "" && parts[1] != "" && strings.HasPrefix(parts[2], "local_")
}

func shouldUseManagedObserve(explicitSocket, explicitMode bool) bool {
	return !explicitSocket && !explicitMode && os.Getenv("KONTEXT_SOCKET") == "" && managedobserve.Active()
}

func managedObserveDaemonCmd() *cobra.Command {
	var socketPath, dbPath, idleTimeout string
	cmd := &cobra.Command{
		Use:    "managed-observe-daemon",
		Short:  "Run the managed observe socket daemon",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			timeout := managedobserve.DefaultIdleTimeout()
			if idleTimeout != "" {
				parsed, err := time.ParseDuration(idleTimeout)
				if err != nil || parsed <= 0 {
					return fmt.Errorf("--idle-timeout must be a positive duration")
				}
				timeout = parsed
			}
			return managedobserve.RunDaemon(context.Background(), managedobserve.DaemonOptions{
				SocketPath:    socketPath,
				DBPath:        dbPath,
				IdleTimeout:   timeout,
				Diagnostic:    diagnostic.New(cmd.ErrOrStderr(), diagnostic.EnabledFromEnv()),
				BinaryVersion: version,
				// "cli-" prefix lets the dashboard distinguish self-serve brew
				// installs (no MDM deployment-version marker) from packages.
				FallbackDeploymentVersion: "cli-" + version,
			})
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "", "managed observe socket path")
	cmd.Flags().StringVar(&dbPath, "db", "", "managed observe database path")
	cmd.Flags().StringVar(&idleTimeout, "idle-timeout", "", "managed observe stale session timeout")
	_ = cmd.Flags().MarkHidden("socket")
	_ = cmd.Flags().MarkHidden("db")
	_ = cmd.Flags().MarkHidden("idle-timeout")
	return cmd
}

type expectedHookAdapter struct {
	guardhookruntime.Adapter
	expected hook.HookName
}

func (a expectedHookAdapter) Decode(in io.Reader) (hook.Event, error) {
	event, err := a.Adapter.Decode(in)
	if err != nil {
		return hook.Event{}, err
	}
	if event.HookName != a.expected {
		return hook.Event{}, fmt.Errorf("hook event alias %q does not match stdin event %q", a.expected, event.HookName)
	}
	return event, nil
}

func expectedHookEventFromArgs(args []string) (hook.HookName, error) {
	if len(args) == 0 {
		return "", nil
	}
	if len(args) > 1 {
		return "", fmt.Errorf("expected at most one hook event alias")
	}
	event, ok := hook.ParseEventAlias(args[0])
	if !ok {
		return "", fmt.Errorf("unknown hook event alias %q", args[0])
	}
	return event, nil
}

type rootHookProcessor struct {
	socketPath string
	mode       guardhookruntime.Mode
}

func (p rootHookProcessor) Process(_ context.Context, event hook.Event) (hook.Result, error) {
	return evaluateHookWithSidecarForMode(p.socketPath, event, string(p.mode))
}

func resolveHookSocketPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if socketPath := os.Getenv("KONTEXT_SOCKET"); socketPath != "" {
		return socketPath
	}
	return localruntime.DefaultSocketPath()
}

func evaluateHookWithSidecar(socketPath string, event hook.Event) (hook.Result, error) {
	return evaluateHookWithSidecarForMode(socketPath, event, "")
}

func evaluateHookWithSidecarForMode(socketPath string, event hook.Event, mode string) (hook.Result, error) {
	if socketPath == "" {
		return sidecarFailureResult(event, "sidecar socket missing", mode), nil
	}
	return evaluateViaSidecarForMode(socketPath, event, mode)
}

func evaluateViaSidecar(socketPath string, event hook.Event) (hook.Result, error) {
	return evaluateViaSidecarForMode(socketPath, event, "")
}

func evaluateViaSidecarForMode(socketPath string, event hook.Event, mode string) (hook.Result, error) {
	conn, err := net.DialTimeout("unix", socketPath, 5*time.Second)
	if err != nil {
		return sidecarFailureResult(event, "sidecar unreachable", mode), nil
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return sidecarFailureResult(event, "sidecar deadline error", mode), nil
	}

	req, err := localruntime.EvaluateRequestFromEvent(event)
	if err != nil {
		return sidecarFailureResult(event, "sidecar marshal error", mode), nil
	}

	if err := localruntime.WriteMessage(conn, req); err != nil {
		return sidecarFailureResult(event, "sidecar write error", mode), nil
	}

	var result localruntime.EvaluateResult
	if err := localruntime.ReadMessage(conn, &result); err != nil {
		return sidecarFailureResult(event, "sidecar read error", mode), nil
	}

	return localruntime.ResultFromEvaluateResult(result), nil
}

func sidecarFailureResult(event hook.Event, reason, mode string) hook.Result {
	if !event.HookName.CanBlock() {
		return hook.Result{Decision: hook.DecisionAllow, Reason: reason}
	}
	if hookMode := normalizedHookMode(mode); hookMode != "" {
		if hookMode != "enforce" {
			return hook.Result{Decision: hook.DecisionAllow, Reason: reason, Mode: hookMode}
		}
		return hook.Result{Decision: hook.DecisionDeny, Reason: reason, Mode: "enforce"}
	}
	return hook.Result{Decision: hook.DecisionAllow, Reason: reason}
}

func normalizedHookMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "observe", "enforce":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

// isInteractivePrompt reports whether both stdin (where the answer is read)
// and stderr (where the prompt is written) are terminals. If either is
// redirected, the user cannot meaningfully answer the prompt, so we fall
// back to a background update check.
func isInteractivePrompt() bool {
	return isCharDevice(os.Stdin) && isCharDevice(os.Stderr)
}

func isCharDevice(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
