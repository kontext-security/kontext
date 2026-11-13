package main

import (
	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/setup"
)

func setupCmd() *cobra.Command {
	var token, cloudURL string
	var uninstall, tokenStdin bool
	var allowHTTPLoopback bool
	cmd := &cobra.Command{
		Use:           "setup",
		Short:         "Connect " + thisMachine() + " to your Kontext organization",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long:          setupLong(),
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := setup.Options{
				Token:             token,
				CloudURL:          cloudURL,
				Version:           version,
				AllowHTTPLoopback: allowHTTPLoopback,
				TokenFromStdin:    tokenStdin,
				Stdout:            cmd.OutOrStdout(),
				Stderr:            cmd.ErrOrStderr(),
			}
			if uninstall {
				return setup.Uninstall(cmd.Context(), opts)
			}
			return setup.Run(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "install token from the Kontext dashboard (prompted interactively when omitted)")
	cmd.Flags().StringVar(&cloudURL, "cloud-url", setup.CloudURL(), "Kontext cloud URL")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read the install token from stdin, so it never appears in the process list")
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the self-serve managed install from "+thisMachine())
	cmd.Flags().BoolVar(&allowHTTPLoopback, "allow-http-loopback", false, "accept a plaintext http cloud URL pointing at localhost (local development)")
	_ = cmd.Flags().MarkHidden("cloud-url")
	_ = cmd.Flags().MarkHidden("allow-http-loopback")
	return cmd
}
