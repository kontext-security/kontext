package main

import (
	"github.com/kontext-security/kontext/internal/setup"
	"github.com/spf13/cobra"
)

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "update",
		Short:         "Install this release over your own Kontext install (Windows)",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `Install this release over your own Kontext install on Windows.

Unzip the newer release to a folder of its own and run its kontext.exe update
from there, not the installed one. Update finds your install through its
sign-in entry, stops the background agent, puts this release's two programs in
place of the installed ones, starts the agent again and checks that the new
one answers. The install key, the config, the hooks and the sign-in entry stay
as they are. If the programs cannot be put in place, the installed ones stay
and the background agent runs again.

Check the zip against checksums.txt before you unzip it, as for the first
install. An install from the MSI is updated by its installer.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.Update(cmd.Context(), setup.UpdateOptions{Version: version, Stdout: cmd.OutOrStdout()})
		},
	}
}
