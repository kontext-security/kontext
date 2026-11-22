package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// hookVerifyTimeout bounds one run of the hook: Claude Code's own default
// for a command hook is longer, but a daemon that answers at all answers in
// well under this.
const hookVerifyTimeout = 30 * time.Second

func hooksVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify",
		Short: "Check that Kontext's PreToolUse hook runs and that its deny is honoured",
		Long: "Run Kontext's PreToolUse hook the way Claude Code runs it, for a Bash call whose command is a\n" +
			"shell no-op, and check that it answers with a deny. The Kontext daemon always denies that\n" +
			"no-op, in every rollout mode, and records the verification with the Claude Code version, the\n" +
			"hook's configuration and the policy revision. A later change to any of them makes the\n" +
			"verification an older result.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			key, _, err := managedobserve.LocalHookKey(cmd.Context())
			if err != nil {
				return fmt.Errorf("hook verification needs this Mac's hardware id: %w", err)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			configDir, err := managedobserve.ClaudeConfigDir()
			if err != nil {
				return err
			}
			agent, _, err := agentauthority.ScanHooks(cmd.Context(), agentauthority.HookScanOptions{Home: home, ConfigDir: configDir, Key: key, OwnBinary: agentauthority.SameFileAs(self), Now: time.Now()})
			if err != nil {
				return err
			}
			if !runsKontextPreToolUse(agent) {
				return errors.New("no Kontext PreToolUse hook from this binary is set to run in Claude Code; run kontext hooks inventory to see why")
			}
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), hookVerifyTimeout)
			defer cancel()
			denied, reason, err := runHookProbe(ctx, self, home, hex.EncodeToString(nonce))
			if err != nil {
				return err
			}
			if !denied {
				return fmt.Errorf("the hook ran but did not deny the probe (%s); the Kontext daemon may not be running", reason)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Verified: Kontext's PreToolUse hook ran and denied the probe. The daemon records the verification, and the dashboard shows it after the next upload.")
			return nil
		},
	}
}

// runsKontextPreToolUse reports a PreToolUse handler of this binary that
// Claude Code would run.
func runsKontextPreToolUse(agent agentauthority.HookAgent) bool {
	for _, r := range agent.Hooks {
		if r.Event == "PreToolUse" && r.Origin == agentauthority.HookOriginKontext && r.Enablement.State == "enabled" {
			return true
		}
	}
	return false
}

// runHookProbe runs `kontext hook pre-tool-use`, which is the command a
// Kontext handler holds, with the probe as Claude Code would send it.
func runHookProbe(ctx context.Context, self, cwd, nonce string) (bool, string, error) {
	input, err := json.Marshal(map[string]any{
		"session_id":      "kontext-hooks-verify-" + nonce,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": managedobserve.HookVerifyCommandPrefix + nonce},
		"tool_use_id":     "kontext-hooks-verify-" + nonce,
		"cwd":             cwd,
		"permission_mode": "default",
	})
	if err != nil {
		return false, "", err
	}
	var stdout, stderr bytes.Buffer
	probe := exec.CommandContext(ctx, self, "hook", "pre-tool-use")
	probe.Stdin, probe.Stdout, probe.Stderr = bytes.NewReader(input), &stdout, &stderr
	probe.Dir = cwd
	runErr := probe.Run()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return false, "", fmt.Errorf("run the hook: %w", runErr)
	}
	return readProbeAnswer(stdout.Bytes(), probe.ProcessState.ExitCode(), &stderr)
}

// readProbeAnswer reads a Claude Code hook's answer: a PreToolUse deny in
// its JSON output, or exit code 2, which Claude Code also reads as a block.
func readProbeAnswer(stdout []byte, exitCode int, stderr io.Reader) (bool, string, error) {
	if exitCode == 2 {
		return true, "exit code 2", nil
	}
	var output struct {
		HookSpecificOutput *struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if len(bytes.TrimSpace(stdout)) > 0 && json.Unmarshal(stdout, &output) == nil && output.HookSpecificOutput != nil {
		if output.HookSpecificOutput.PermissionDecision == "deny" {
			return true, "deny", nil
		}
		return false, "answered " + output.HookSpecificOutput.PermissionDecision, nil
	}
	detail, _ := io.ReadAll(io.LimitReader(stderr, 512))
	reason := "no decision"
	if line := strings.TrimSpace(string(detail)); line != "" {
		reason += ": " + printable(strings.SplitN(line, "\n", 2)[0])
	}
	if exitCode != 0 {
		reason += fmt.Sprintf(", exit code %d", exitCode)
	}
	return false, reason, nil
}
