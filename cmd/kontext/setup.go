package main

import (
	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/setup"
)

func setupCmd() *cobra.Command {
	var token, cloudURL string
	var uninstall bool
	cmd := &cobra.Command{
		Use:           "setup",
		Short:         "Connect this Mac to your Kontext organization",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Connect this Mac to your Kontext organization (self-serve managed observe).

Setup asks for the install token created in the Kontext dashboard, stores it
in your login keychain, installs hooks for supported local agents, and starts
a background agent that streams agent activity to your workspace.

Re-running setup is safe: it rotates the stored token and restarts the agent.
Use --uninstall to remove everything setup installed (the kontext binary
itself stays — it is managed by Homebrew).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := setup.Options{
				Token:    token,
				CloudURL: cloudURL,
				Version:  version,
				Stdout:   cmd.OutOrStdout(),
				Stderr:   cmd.ErrOrStderr(),
			}
			if uninstall {
				return setup.Uninstall(cmd.Context(), opts)
			}
			return setup.Run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "install token from the Kontext dashboard (prompted interactively when omitted)")
	cmd.Flags().StringVar(&cloudURL, "cloud-url", setup.CloudURL(), "Kontext cloud URL")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the self-serve managed install from this Mac")
	_ = cmd.Flags().MarkHidden("cloud-url")
	return cmd
}
