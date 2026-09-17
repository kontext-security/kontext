package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/spf13/cobra"
)

func reportCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use: "report", Short: "Show discovery and authority exactly as last sent to the cloud",
		Args: cobra.NoArgs, SilenceUsage: true, SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			state, err := managedstream.LoadState(managedstream.DefaultStatePathForDB(managedobserve.DefaultDBPath()))
			if err != nil {
				return err
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(state.LastReport)
			}
			return writeReport(cmd.OutOrStdout(), state.LastReport)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the raw discovery and authority payload")
	return cmd
}

func writeReport(out io.Writer, report managedstream.Report) error {
	if report.Agents == nil && report.Authority == nil {
		_, err := fmt.Fprintln(out, "No discovery or authority report has been sent yet.")
		return err
	}
	lines := map[string]string{}
	ids := []string{}
	if report.Agents != nil {
		fmt.Fprintf(out, "Discovery · %s\n", report.AgentsReportedAt)
		for _, agent := range *report.Agents {
			ids = append(ids, agent.ID)
			activity := "not reported"
			if agent.LastActivityAt != nil {
				activity = *agent.LastActivityAt
			}
			lines[agent.ID] = fmt.Sprintf("wired %s, last activity %s", agent.Wired, activity)
		}
	}
	authority := report.Authority
	if authority != nil {
		fmt.Fprintf(out, "Authority · %s · hash %s\n", authority.ScannedAt, authority.Hash)
		for _, agent := range authority.Agents {
			bypassed := agent.Permissions.DefaultMode != nil && *agent.Permissions.DefaultMode == "bypassPermissions"
			if codex := agent.Permissions.Codex; codex != nil {
				bypassed = bypassed || codex.SandboxMode != nil && *codex.SandboxMode == "danger-full-access"
			}
			detail := countLabel(len(agent.MCPServers), "MCP server") + ", " + countLabel(len(agent.Plugins), "plugin")
			if bypassed {
				detail += ", prompts bypassed"
			}
			if discovery, exists := lines[agent.ID]; exists {
				detail += ", " + discovery
			} else {
				ids = append(ids, agent.ID)
			}
			lines[agent.ID] = detail
		}
	}
	for _, id := range ids {
		fmt.Fprintf(out, "%s: %s\n", agentinventory.DisplayName(id), lines[id])
	}
	if authority == nil {
		_, err := fmt.Fprintln(out, "Authority: not sent yet")
		return err
	}
	env := authority.Environment
	fmt.Fprintf(out, "Environment: uid %d, root %t, admin %t, container %t\n", env.UID, env.Root, env.Admin, env.Container)
	credentials := []string{}
	for _, credential := range authority.Credentials {
		if !credential.Present {
			continue
		}
		label := map[string]string{"gh_token": "gh", "ssh_key": "SSH key", "aws_credentials": "AWS profile", "aws_config_profiles": "AWS config profile", "gcloud_adc": "gcloud ADC", "kubeconfig": "Kubernetes context", "npm_token": "npm token", "docker_config_auth": "Docker registry login"}[credential.Kind]
		if label == "" {
			label = credential.Kind
		}
		if credential.Detail > 1 {
			label = countLabel(credential.Detail, label)
		}
		details := []string{}
		if credential.Host != nil {
			details = append(details, *credential.Host)
		}
		if credential.Login != nil {
			details = append(details, *credential.Login)
		}
		if len(details) > 0 {
			label += " (" + strings.Join(details, ", ") + ")"
		}
		credentials = append(credentials, label)
	}
	if len(credentials) == 0 {
		credentials = append(credentials, "none found")
	}
	fmt.Fprintf(out, "Ambient credentials: %s; values never read\n", strings.Join(credentials, ", "))
	_, err := fmt.Fprintf(out, "Coverage: %d skipped files, %d errors, unknown formats [%s], limits [%s], truncated %t; %s\n", authority.Coverage.SkippedFiles, len(authority.Coverage.Errors), strings.Join(authority.Coverage.UnknownFormat, ", "), strings.Join(authority.Coverage.Limits, "; "), authority.Truncated, strings.Join(authority.Coverage.Errors, "; "))
	return err
}

func countLabel(count int, noun string) string {
	if count != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", count, noun)
}
