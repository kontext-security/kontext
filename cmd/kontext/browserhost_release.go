//go:build !kontext_browser_dev

package main

import "github.com/spf13/cobra"

// Release builds are registered machine-wide by the installers only.
func addBrowserHostDevCommands(*cobra.Command) {}
