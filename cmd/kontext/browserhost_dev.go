//go:build kontext_browser_dev

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext/internal/browserhost"
)

// addBrowserHostDevCommands adds `browser-host register`, which registers this
// binary for one user and the dev extension ID. Only dev builds have it.
func addBrowserHostDevCommands(parent *cobra.Command) {
	var browser, userDataDir string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register this dev build as the browser extension's host for one user",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			path, err := browserhost.RegisterDev(browserhost.DevRegistration{
				Browser: browser, UserDataDir: userDataDir, Executable: executable,
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), path)
			return nil
		},
	}
	cmd.Flags().StringVar(&browser, "browser", "chrome", "chrome, edge or chromium")
	cmd.Flags().StringVar(&userDataDir, "user-data-dir", "", "a browser profile folder to register in instead of the user's default")
	parent.AddCommand(cmd)
}
