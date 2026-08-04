package main

import (
	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/setup"
	"github.com/kontext-security/kontext-cli/internal/startupui"
)

func setupCmd() *cobra.Command {
	var token, cloudURL string
	var uninstall, withLocalLLM, tokenStdin bool
	var allowHTTPLoopback bool
	cmd := &cobra.Command{
		Use:           "setup",
		Short:         "Connect this Mac to your Kontext organization",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Connect this Mac to your Kontext organization (self-serve managed observe).

Setup asks for the install token created in the Kontext dashboard, stores it
in your login keychain, installs hooks for supported local agents, and starts
a background agent that streams agent activity to your workspace.

The local risk model is optional and off by default. Everything works without
it: the classifier scores every command with its embedded model and records why
the second opinion is absent. Pass --with-local-llm to opt in — setup then
checks llama-server is installed, downloads the weights (~680 MB) while you
watch, and tells the background agent to run it.

Re-running setup is safe: it rotates the stored token and restarts the agent.
Use --uninstall to remove everything setup installed (the kontext binary
itself stays — it is managed by Homebrew).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := setup.Options{
				Token:             token,
				CloudURL:          cloudURL,
				Version:           version,
				AllowHTTPLoopback: allowHTTPLoopback,
				TokenFromStdin:    tokenStdin,
				Stdout:            cmd.OutOrStdout(),
				Stderr:            cmd.ErrOrStderr(),
				WithLocalLLM:      withLocalLLM,
			}
			if withLocalLLM {
				opts.ModelDownloadProgress = startupui.New(cmd.OutOrStdout()).HandleDownloadProgress
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
	cmd.Flags().BoolVar(&uninstall, "uninstall", false, "remove the self-serve managed install from this Mac")
	cmd.Flags().BoolVar(&withLocalLLM, "with-local-llm", false, "also run the local risk model (requires llama-server on PATH; downloads ~680 MB of weights)")
	cmd.Flags().BoolVar(&allowHTTPLoopback, "allow-http-loopback", false, "accept a plaintext http cloud URL pointing at localhost (local development)")
	_ = cmd.Flags().MarkHidden("cloud-url")
	_ = cmd.Flags().MarkHidden("allow-http-loopback")
	return cmd
}
