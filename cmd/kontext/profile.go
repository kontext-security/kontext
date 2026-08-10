package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
	"github.com/kontext-security/kontext-cli/internal/setup"
)

func profileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage local profiles (workspace + backend pairs)",
		// Hidden, like `hook` and `managed-observe-daemon`: profiles are a
		// development convenience for people who need one Mac to talk to several
		// workspaces or backends, not a product feature. The code has to ship —
		// it lives in the same binary the daemon and hooks run — but it stays out
		// of `kontext --help` until it is deliberately made customer-facing.
		Hidden: true,
		Long: `Manage local profiles.

A profile binds one workspace on one backend to its own config, installation
identity, install token, and ledger cache. Exactly one profile is active at a
time; switching restarts the background agent so policy decisions and streamed
events always agree on the destination.

Each profile keeps a separate ledger cache, so events captured for one workspace
are never exported to another.`,
	}
	cmd.AddCommand(profileListCmd())
	cmd.AddCommand(profileAddCmd())
	cmd.AddCommand(profileUseCmd())
	cmd.AddCommand(profileRenameCmd())
	cmd.AddCommand(profileRemoveCmd())
	cmd.AddCommand(profileMigrateCmd())
	return cmd
}

func profileListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:           "ls",
		Aliases:       []string{"list"},
		Short:         "List local profiles",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inventory, err := setup.LoadInventory()
			if err != nil {
				return err
			}
			if asJSON {
				return inventory.WriteJSON(cmd.OutOrStdout())
			}
			return inventory.WriteText(cmd.OutOrStdout())
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON")
	return cmd
}

func profileAddCmd() *cobra.Command {
	var token, cloudURL, environment string
	var use, tokenStdin bool
	var allowHTTPLoopback bool
	cmd := &cobra.Command{
		Use:   "add [name]",
		Short: "Create a profile and connect it to a workspace",
		Long: `Create a profile and connect it to a workspace.

Runs the same setup a plain ` + "`kontext setup`" + ` does, but writes into the named
profile: its own config, installation identity, and keychain item. The install
token comes from the Kontext dashboard for the backend you are pointing at — a
staging token will not work against production.

The new profile does not become active unless --use is passed.

For a backend you are running locally, pass --allow-http-loopback so a plaintext
` + "`http://localhost`" + ` URL is accepted. It is recorded in the profile, so the
background agent honors it too — unlike the ` + managedconfig.EnvAllowHTTP + `
environment variable, which a LaunchAgent never sees.

Environment and workspace are separate: the environment is which backend the
profile talks to, the workspace is which install token it uses. Several profiles
can share an environment while pointing at different workspaces.

Pass --env to choose the environment explicitly:

  prod, production    ` + setup.DefaultCloudURL + `
  staging, stg        ` + setup.StagingCloudURL + `
  local, localdev,    ` + setup.LocalCloudURL + ` (plaintext loopback enabled)
  dev

A profile NAMED after one of those ("prod", "staging", "localdev") gets that
environment without --env. Any other name needs --env or --cloud-url, or it falls
back to production. The backend is always printed before the token is asked for.`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// The name is optional: it is only a handle, and after the token is
			// validated the workspace and environment are both known, which is
			// enough to derive one. Requiring it up front made every caller invent
			// a label before it had anything to name.
			var name string
			if len(args) == 1 {
				name = args[0]
				if err := profile.ValidateName(name); err != nil {
					return err
				}
			} else if environment == "" && !cmd.Flags().Changed("cloud-url") {
				return fmt.Errorf("give a profile name, or --env (%s) so the name can be derived", strings.Join(setup.PresetNames(), ", "))
			}
			// Environment (which backend) and workspace (which token) are separate
			// axes. Keying the endpoint off the profile NAME alone only works while
			// names happen to be "staging" or "prod"; the moment someone wants
			// `staging_hasan`, or two workspaces on one backend, the name stops
			// carrying that information. --env states it outright.
			//
			// Precedence, most explicit first: --cloud-url, then --env, then a
			// preset matching the name.
			source := ""
			if preset, ok := setup.LookupPreset(environment); ok {
				if !cmd.Flags().Changed("cloud-url") {
					cloudURL = preset.CloudURL
				}
				if !cmd.Flags().Changed("allow-http-loopback") {
					allowHTTPLoopback = preset.AllowHTTPLoopback
				}
				source = preset.Description
			} else if environment != "" {
				return fmt.Errorf("unknown --env %q; use one of: %s", environment, strings.Join(setup.PresetNames(), ", "))
			} else if preset, ok := setup.LookupPreset(name); ok {
				if !cmd.Flags().Changed("cloud-url") {
					cloudURL = preset.CloudURL
				}
				if !cmd.Flags().Changed("allow-http-loopback") {
					allowHTTPLoopback = preset.AllowHTTPLoopback
				}
				source = preset.Description + ", inferred from the profile name"
			}
			if cloudURL == "" {
				cloudURL = setup.CloudURL()
				source = "default"
			}
			// ALWAYS say which backend this profile will talk to, before asking for a
			// token. Printing only when a preset matched is how an unrecognized name
			// silently lands on production and the token is then rejected with an
			// error that names neither cause.
			if source == "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Backend: %s\n", cloudURL)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "Backend: %s (%s)\n", cloudURL, source)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "The install token must come from THIS backend's dashboard.")
			// Migrate first: adding a second profile to a machine whose original
			// install still sits at the legacy paths would leave that install
			// unreachable by name and impossible to switch back to.
			if _, err := setup.MigrateLegacyInstall(cmd.Context(), cmd.OutOrStdout()); err != nil {
				return err
			}
			opts := setup.Options{
				Token:             token,
				CloudURL:          cloudURL,
				Version:           version,
				Profile:           name,
				DeriveProfileName: name == "",
				OnProfileResolved: func(resolved string) { name = resolved },
				AllowHTTPLoopback: allowHTTPLoopback,
				TokenFromStdin:    tokenStdin,
				Stdout:            cmd.OutOrStdout(),
				Stderr:            cmd.ErrOrStderr(),
			}
			if err := setup.Run(cmd.Context(), opts); err != nil {
				return err
			}
			if use {
				return setup.Activate(cmd.Context(), name, cmd.OutOrStdout(), cmd.ErrOrStderr())
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\nProfile %q is ready. Run `kontext profile use %s` to switch to it.\n", name, name)
			return nil
		},
	}
	cmd.Flags().StringVar(&token, "token", "", "install token from the Kontext dashboard (prompted interactively when omitted)")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "read the install token from stdin, so it never appears in the process list")
	// Defaulted to "" rather than the production URL so a preset can tell whether
	// the caller actually chose an endpoint.
	cmd.Flags().StringVar(&environment, "env", "", "environment to point at: "+strings.Join(setup.PresetNames(), ", "))
	cmd.Flags().StringVar(&cloudURL, "cloud-url", "", "exact Kontext cloud URL (overrides --env)")
	cmd.Flags().BoolVar(&use, "use", false, "switch to the profile after creating it")
	cmd.Flags().BoolVar(&allowHTTPLoopback, "allow-http-loopback", false, "accept a plaintext http cloud URL pointing at localhost (local development)")
	return cmd
}

func profileRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <current> <new>",
		Short: "Rename a profile",
		Long: `Rename a profile.

Useful after ` + "`kontext profile migrate`" + `, which has to name the migrated
install "default" before it can know which backend that install pointed at.

The install token is not touched: a profile's token is located by the reference
recorded in its config, not by its directory name, so renaming needs no keychain
access and produces no authorization prompt. Renaming the ACTIVE profile restarts
the background agent, because its resolved paths change.`,
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.RenameProfile(cmd.Context(), args[0], args[1], cmd.OutOrStdout())
		},
	}
	return cmd
}

func profileUseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <name>",
		Short: "Switch to a profile",
		Long: `Switch to a profile.

Validates the target profile's config and install token, stops the background
agent, re-points the active pointer, and starts the agent again. A failure at
any step leaves the current profile active and serving.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.Activate(cmd.Context(), args[0], cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

func profileRemoveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "rm <name>",
		Aliases:       []string{"remove"},
		Short:         "Remove a profile and its local data",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return setup.RemoveProfile(cmd.Context(), args[0], cmd.OutOrStdout())
		},
	}
	return cmd
}

func profileMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Move a pre-profile install into the \"default\" profile",
		Long: `Move a pre-profile install into the "default" profile.

Installs made before profiles existed keep their state directly under
~/Library/Application Support/Kontext. This moves that state into the "default"
profile and makes it active, so it can be switched away from and back to. The
install token is not touched.

Running this on a machine that already uses profiles does nothing.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			migrated, err := setup.MigrateLegacyInstall(cmd.Context(), cmd.OutOrStdout())
			if err != nil {
				return err
			}
			if migrated {
				return nil
			}
			// Nothing moved for one of two quite different reasons; say which.
			if active, err := profile.ActiveName(); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Nothing to migrate — this Mac already uses profiles (active: %s).\n", active)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "Nothing to migrate — no pre-profile install found. Run `kontext profile add <name> --cloud-url <url>` to create one.")
			}
			return nil
		},
	}
	return cmd
}
