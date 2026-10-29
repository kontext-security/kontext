package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/setup"
	"github.com/spf13/cobra"
)

func hooksCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hooks", Short: "Install or remove the shared Kontext agent hook set"}
	for _, action := range []string{"install", "remove"} {
		var scope, binary string
		var dryRun bool
		sub := &cobra.Command{Use: action, Short: action + " Kontext hooks", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS != "darwin" {
				return fmt.Errorf("kontext hooks is currently macOS-only")
			}
			if scope != "user" && scope != "system" {
				return fmt.Errorf("invalid scope %q: want user or system", scope)
			}
			// Dry-run needs no privileges and must not create directories or backups.
			if scope == "system" && !dryRun && os.Geteuid() != 0 {
				return fmt.Errorf("system hook installation and removal require root; use sudo with --scope system")
			}
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			// User scope writes only the user's own files; organization packages
			// install the machine-wide set with --scope system.
			if binary == "" && scope == "user" {
				binary, _ = setup.StableBinaryPath()
			} else if binary == "" {
				binary = claudemanaged.DefaultKontextBinary
			}
			opts := hookinstall.Options{Scope: hookinstall.Scope(scope), Home: home, Binary: binary, DryRun: dryRun, Out: cmd.OutOrStdout()}
			if action == "remove" {
				return hookinstall.Remove(opts)
			}
			return hookinstall.Install(opts)
		}}
		sub.Flags().StringVar(&scope, "scope", "user", "Installation scope: user or system")
		sub.Flags().BoolVar(&dryRun, "dry-run", false, "Print the plan without writing any files")
		if action == "install" {
			sub.Flags().StringVar(&binary, "binary", "", "Absolute Kontext executable path (default: this executable's stable path for --scope user, "+claudemanaged.DefaultKontextBinary+" for --scope system)")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}
