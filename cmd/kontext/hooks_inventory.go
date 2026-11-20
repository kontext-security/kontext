package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// hookInventoryOutput is what `kontext hooks inventory --json` prints: the
// record the daemon would upload, and which key its ids are under.
type hookInventoryOutput struct {
	KeyScope string                      `json:"key_scope"`
	Source   agentauthority.SourceResult `json:"source"`
	Agent    agentauthority.HookAgent    `json:"agent"`
}

func hooksInventoryCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List every Claude Code hook this Mac loads, and whether each is expected to run",
		Long: "List every Claude Code hook this Mac loads: managed settings and drop-ins, user settings,\n" +
			"the settings of each project Claude Code lists, and installed plugins. Each hook shows whether\n" +
			"its configuration lets it run. Only runtime evidence says a hook works; configuration alone\n" +
			"says it is expected to run. Commands are summarized, and secrets in them are never printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			key, scope, err := managedobserve.LocalHookKey(cmd.Context())
			if err != nil {
				return fmt.Errorf("hook inventory needs this Mac's hardware id: %w", err)
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			var own func(string) bool
			if self, err := os.Executable(); err == nil {
				own = agentauthority.SameFileAs(self)
			}
			configDir, err := managedobserve.ClaudeConfigDir()
			if err != nil {
				return fmt.Errorf("%w; Claude Code won't load a profile from it either", err)
			}
			agent, source, err := agentauthority.ScanHooks(cmd.Context(), agentauthority.HookScanOptions{Home: home, ConfigDir: configDir, Key: key, OwnBinary: own, Now: time.Now()})
			if err != nil {
				return err
			}
			output := hookInventoryOutput{KeyScope: scope, Source: source, Agent: agent}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(output)
			}
			printHookInventory(cmd.OutOrStdout(), output)
			if dir := configDir; dir != "" {
				// The daemon reads the profile its own environment names,
				// which a shell's CLAUDE_CONFIG_DIR doesn't reach.
				fmt.Fprintf(cmd.OutOrStdout(), "\nRead the Claude Code profile in %s (CLAUDE_CONFIG_DIR). The Kontext daemon reports the profile set in its own environment, which may differ.\n", printable(dir))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the inventory as JSON")
	return cmd
}

// hookStateWording keeps configuration-only evidence from reading as proof.
func hookStateWording(r agentauthority.HookRecord) string {
	switch r.Enablement.State {
	case "enabled":
		switch r.Evidence.Level {
		case agentauthority.HookEvidenceInvocationObserved, agentauthority.HookEvidencePolicyEvaluated, agentauthority.HookEvidenceEnforcementVerified:
			return "working"
		}
		return "expected to run"
	case "conditional":
		return "runs once the project is trusted"
	case "disabled":
		return "not running"
	}
	return "could not check"
}

func printHookInventory(out io.Writer, o hookInventoryOutput) {
	scopes := map[string]agentauthority.HookScope{}
	for _, s := range o.Agent.Scopes {
		scopes[s.ID] = s
	}
	fmt.Fprintf(out, "Claude Code hooks: %d (scan %s", len(o.Agent.Hooks), o.Source.Status)
	if len(o.Source.Reasons) > 0 {
		fmt.Fprintf(out, ": %s", strings.Join(o.Source.Reasons, ", "))
	}
	fmt.Fprintln(out, ")")
	switch o.Agent.KontextHooks.State {
	case "complete":
		fmt.Fprintln(out, "Kontext hooks: all events configured")
	case "needs_update":
		fmt.Fprintf(out, "Kontext hooks: missing %s; run kontext setup to repair\n", strings.Join(o.Agent.KontextHooks.MissingEvents, ", "))
	case agentauthority.KontextHooksUnknown:
		// A setting that decides it went unread: neither missing nor there.
		fmt.Fprintln(out, "Kontext hooks: could not check, because a setting that decides it could not be read (see below)")
	default:
		fmt.Fprintln(out, "Kontext hooks: not configured")
	}
	if o.KeyScope == managedobserve.HookKeyLocal {
		fmt.Fprintln(out, "Ids are keyed to this Mac only; they match the dashboard once Kontext is set up.")
	}
	for _, r := range o.Agent.Hooks {
		matcher := "*"
		if r.Matcher != nil && *r.Matcher != "" {
			matcher = *r.Matcher
		}
		summary := r.Type
		if r.Summary != nil {
			summary = *r.Summary
		}
		where := scopes[r.ScopeID].Kind
		if r.Plugin != nil {
			where = "plugin " + r.Plugin.Name
		}
		fmt.Fprintf(out, "\n%s [%s] %s\n  from %s, %s", printable(r.Event), printable(matcher), printable(summary), printable(where), hookStateWording(r))
		if len(r.Enablement.Reasons) > 0 {
			fmt.Fprintf(out, " (%s)", strings.Join(r.Enablement.Reasons, ", "))
		}
		fmt.Fprintln(out)
	}
	for _, s := range o.Agent.Scopes {
		if s.Status != agentauthority.StatusComplete {
			fmt.Fprintf(out, "\nCould not fully read a %s source: %s\n", s.Kind, strings.Join(s.Reasons, ", "))
		}
	}
}

// printable shows text that settings files supply with its control
// characters escaped, so a matcher can't forge or hide a line of the listing.
func printable(text string) string {
	if !strings.ContainsFunc(text, func(r rune) bool { return !unicode.IsPrint(r) && r != ' ' }) {
		return text
	}
	quoted := strconv.QuoteToGraphic(text)
	return quoted[1 : len(quoted)-1]
}
