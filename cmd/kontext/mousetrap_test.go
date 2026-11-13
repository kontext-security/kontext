package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestDaemonRunsWhenTheShellStartsIt(t *testing.T) {
	previous := cobra.MousetrapHelpText
	t.Cleanup(func() { cobra.MousetrapHelpText = previous })
	if cobra.MousetrapHelpText == "" {
		t.Skip("cobra's check for a start from Explorer is already off")
	}
	startedByTheShell()
	if cobra.MousetrapHelpText != "" {
		t.Fatalf("cobra would still stop a daemon started from Explorer: %q", cobra.MousetrapHelpText)
	}
}
