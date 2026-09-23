package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/spf13/cobra"
)

func hooksCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "hooks", Short: "Install or remove the shared Kontext agent hook set"}
	cmd.AddCommand(refreshClaudeHooksCmd())
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
			opts := hookinstall.Options{Scope: hookinstall.Scope(scope), Home: home, Binary: binary, DryRun: dryRun, Out: cmd.OutOrStdout()}
			if scope == "user" {
				run := func(name string, args ...string) error {
					c := exec.CommandContext(cmd.Context(), name, args...)
					c.Stdin = cmd.InOrStdin()
					c.Stdout = cmd.ErrOrStderr()
					c.Stderr = cmd.ErrOrStderr()
					return c.Run()
				}
				opts.WriteClaude = func(path string, data []byte) error {
					return hookinstall.WriteClaudeFile(path, data, os.Geteuid(), run)
				}
				opts.RemoveClaude = func(path string) error {
					if os.Geteuid() == 0 {
						return os.Remove(path)
					}
					return run("sudo", "rm", "-f", path)
				}
			}
			if action == "remove" {
				return hookinstall.Remove(opts)
			}
			return hookinstall.Install(opts)
		}}
		sub.Flags().StringVar(&scope, "scope", "user", "Installation scope: user or system")
		sub.Flags().BoolVar(&dryRun, "dry-run", false, "Print the plan without writing any files")
		if action == "install" {
			sub.Flags().StringVar(&binary, "binary", claudemanaged.DefaultKontextBinary, "Absolute Kontext executable path")
		}
		cmd.AddCommand(sub)
	}
	return cmd
}

// This is the narrow elevated entry point used by the self-serve daemon. It
// never resolves root's home or installs Codex hooks into the wrong account.
func refreshClaudeHooksCmd() *cobra.Command {
	var binary, digest string
	cmd := &cobra.Command{
		Use: "refresh-claude", Hidden: true, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if runtime.GOOS != "darwin" || os.Geteuid() != 0 {
				return fmt.Errorf("Claude hook migration requires administrator privileges on macOS")
			}
			// MDM may have enrolled the machine while the approval dialog was open.
			for _, path := range []string{managedconfig.DefaultPath, claudemanaged.ManagedSettingsPath} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					return fmt.Errorf("cannot migrate self-serve hooks while managed settings exist or are unreadable at %s", path)
				}
			}
			exe, err := os.Executable()
			if err != nil {
				return err
			}
			running, err := os.Stat(exe)
			if err != nil {
				return err
			}
			target, err := os.Stat(binary)
			if err != nil || !os.SameFile(running, target) {
				return fmt.Errorf("Kontext binary changed while awaiting approval; retry with the current version")
			}
			return hookinstall.RefreshClaude(claudemanaged.ManagedSettingsDropInPath, binary, digest)
		},
	}
	cmd.Flags().StringVar(&binary, "binary", "", "Stable path to the running Kontext executable")
	cmd.Flags().StringVar(&digest, "expected-sha256", "", "Digest of the approved existing hook file")
	return cmd
}
