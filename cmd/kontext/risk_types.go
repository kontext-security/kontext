package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

func riskTypesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "risk-types",
		Short: "Manage advisory local risk-type annotations",
	}
	cmd.AddCommand(riskTypesEnrichCmd())
	return cmd
}

func riskTypesEnrichCmd() *cobra.Command {
	var dbPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:           "enrich",
		Short:         "Append risk types to previously recorded risky shell calls",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			model, err := riskclassifier.LoadRiskTypeSVM()
			if err != nil {
				return fmt.Errorf("load risk-type model: %w", err)
			}
			store, err := sqlite.OpenStore(dbPath)
			if err != nil {
				return fmt.Errorf("open local ledger: %w", err)
			}
			defer store.Close()
			result, err := store.EnrichRiskyShellCalls(cmd.Context(), model)
			if err != nil {
				return fmt.Errorf("enrich local risky calls: %w", err)
			}
			if asJSON {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "risk-type enrichment: %d eligible, %d appended, %d already present, %d non-shell skipped\n",
				result.EligibleRisky, result.Inserted, result.AlreadyPresent, result.IneligibleRisky)
			for _, item := range result.Items {
				labels := strings.Join(item.Annotation.RiskTypes, ", ")
				if item.Annotation.Abstained {
					labels = "abstained"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "- %s: %s (primary: %s) — %s\n",
					item.ActionID, labels, item.Annotation.PrimaryRiskType, oneLineCommand(item.Command))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", managedobserve.DefaultDBPath(), "local ledger database path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the complete machine-readable result")
	return cmd
}

func oneLineCommand(command string) string {
	command = strings.Join(strings.Fields(command), " ")
	const max = 120
	if len(command) <= max {
		return command
	}
	runes := []rune(command)
	if len(runes) <= max {
		return command
	}
	return string(runes[:max]) + "..."
}
