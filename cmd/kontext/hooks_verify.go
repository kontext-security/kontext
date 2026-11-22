package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/localruntime"
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
		Short: "Self-test Kontext's PreToolUse hook: run it and check that its deny comes back",
		Long: "Check that a Kontext PreToolUse handler from this binary is set to run in Claude Code for every\n" +
			"Bash call (synchronously, in every project), then run that handler's command the way Claude Code\n" +
			"runs it, for a Bash call whose command is a shell no-op, and check that the Kontext daemon's deny\n" +
			"comes back. The daemon always denies that no-op, in every rollout mode. A second call confirms\n" +
			"the deny arrived, and only then does the daemon record the verification, with the Claude Code\n" +
			"version, the hook's configuration and the policy revision. A later change to any of them makes\n" +
			"the verification an older result. This tests Kontext's side of the hook; it doesn't start Claude Code.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			self, err := os.Executable()
			if err != nil {
				return err
			}
			// The check needs no stable ids: a throwaway key keeps it local,
			// with no request to the cloud for this Mac's own.
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				return err
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
			if !guardsEveryBashCall(agent) {
				return errors.New("no Kontext PreToolUse hook from this binary runs for every Bash call in Claude Code; run kontext hooks inventory to see why")
			}
			// Ask the daemon the hook talks to: an older one would take the probe for ordinary activity and
			// keep it in its ledger: ask first.
			capabilities, err := localruntime.NewClient(hookDaemonSocketPath()).Capabilities(cmd.Context())
			if err != nil {
				return fmt.Errorf("the Kontext daemon isn't answering: %w", err)
			}
			if !capabilities.HookVerify {
				return errors.New("the running Kontext daemon is older than this command; update or restart it, then run this again")
			}
			nonce := make([]byte, 16)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			// A neutral directory: no project's settings or policy apply.
			cwd, err := os.MkdirTemp("", "kontext-hooks-verify-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(cwd)
			ctx, cancel := context.WithTimeout(cmd.Context(), hookVerifyTimeout)
			defer cancel()
			id := hex.EncodeToString(nonce)
			reason, err := runHookProbe(ctx, self, cwd, id, managedobserve.HookVerifyCommandPrefix+id)
			if err != nil {
				return err
			}
			if reason != managedobserve.HookVerifyReason {
				if reason == probeAnswerMissing {
					return errors.New("the hook ran but its deny did not come back: Kontext may be set to observe only on this Mac, where every deny is turned into an allow")
				}
				return fmt.Errorf("the hook ran but the Kontext daemon did not deny the probe (%s)", describeAnswer(reason))
			}
			reason, err = runHookProbe(ctx, self, cwd, id, managedobserve.HookVerifyAckPrefix+id)
			if err != nil {
				return err
			}
			switch reason {
			case managedobserve.HookVerifyAckReason:
			case managedobserve.HookVerifyNotRecordedReason:
				return errors.New("the hook ran and its deny came back, but the daemon did not record a verification: the hook inventory is off for this Mac, the rollout is observe only, or no hook scan has run yet")
			default:
				return fmt.Errorf("the daemon did not confirm the verification (%s)", describeAnswer(reason))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Verified: Kontext's PreToolUse hook ran and its deny came back. The daemon recorded the verification, and the dashboard shows it after the next upload.")
			return nil
		},
	}
}

// guardsEveryBashCall reports a Kontext PreToolUse handler of this binary
// that Claude Code runs, and waits for, on every Bash call: device wide,
// unconditional, synchronous, with a matcher that covers Bash.
func guardsEveryBashCall(agent agentauthority.HookAgent) bool {
	return slices.ContainsFunc(agent.Hooks, agentauthority.HookRecord.GuardsEveryBashCall)
}

// probeAnswerMissing stands for an answer with no deny reason.
const probeAnswerMissing = ""

func describeAnswer(reason string) string {
	switch reason {
	case probeAnswerMissing:
		return "no deny"
	case managedobserve.HookVerifyReason, managedobserve.HookVerifyAckReason, managedobserve.HookVerifyNotRecordedReason:
		return "out of order"
	}
	return "another deny"
}

// runHookProbe runs `kontext hook pre-tool-use`, which is the command a
// Kontext handler holds, with a Bash call as Claude Code would send it, and
// returns the deny's reason, or "" for no deny. The hook's error output
// isn't shown: it may name local paths.
func runHookProbe(ctx context.Context, self, cwd, nonce, command string) (string, error) {
	input, err := json.Marshal(map[string]any{
		"session_id":      "kontext-hooks-verify-" + nonce,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": command},
		"tool_use_id":     "kontext-hooks-verify-" + nonce,
		"cwd":             cwd,
		"permission_mode": "default",
	})
	if err != nil {
		return "", err
	}
	var stdout, stderr bytes.Buffer
	probe := exec.CommandContext(ctx, self, "hook", "pre-tool-use")
	probe.Stdin, probe.Stdout, probe.Stderr = bytes.NewReader(input), &stdout, &stderr
	probe.Dir = cwd
	runErr := probe.Run()
	var exit *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exit) {
		return "", fmt.Errorf("run the hook: %w", runErr)
	}
	return readProbeAnswer(stdout.Bytes(), probe.ProcessState.ExitCode(), stderr.Bytes()), nil
}

// readProbeAnswer reads a Claude Code hook's deny reason: a PreToolUse deny
// in its JSON output, or exit code 2 with the reason on stderr, which Claude
// Code also reads as a block. Anything else is no deny.
func readProbeAnswer(stdout []byte, exitCode int, stderr []byte) string {
	if exitCode == 2 {
		return strings.TrimSpace(string(stderr))
	}
	var output struct {
		HookSpecificOutput *struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	// A deny Claude Code reads: for this event, with its decision.
	if exitCode == 0 && json.Unmarshal(bytes.TrimSpace(stdout), &output) == nil && output.HookSpecificOutput != nil &&
		output.HookSpecificOutput.HookEventName == "PreToolUse" && output.HookSpecificOutput.PermissionDecision == "deny" {
		return output.HookSpecificOutput.PermissionDecisionReason
	}
	return probeAnswerMissing
}

// hookDaemonSocketPath is the socket `kontext hook` talks to when Claude Code
// runs it with no flags: the managed daemon's on an enrolled Mac, else the
// local sidecar's.
func hookDaemonSocketPath() string {
	if shouldUseManagedObserve(false, false) {
		return managedobserve.DefaultSocketPath()
	}
	return resolveHookSocketPath("")
}
