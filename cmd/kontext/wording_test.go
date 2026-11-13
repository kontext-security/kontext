package main

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// helpOf collects every text a command shows in its help: its descriptions
// and the usage of its flags, for the command and everything below it.
func helpOf(cmd *cobra.Command) map[string]string {
	texts := map[string]string{}
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		texts[c.CommandPath()+" (short)"] = c.Short
		texts[c.CommandPath()+" (long)"] = c.Long
		c.Flags().VisitAll(func(f *pflag.Flag) { texts[c.CommandPath()+" --"+f.Name] = f.Usage })
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(cmd)
	return texts
}

func helpFor(t *testing.T, goos string) map[string]string {
	t.Helper()
	was := helpGOOS
	helpGOOS = goos
	t.Cleanup(func() { helpGOOS = was })
	return helpOf(newRootCmd())
}

// On Windows the help of setup and whoami names the PC and what setup does
// there, and nothing that only a Mac has.
func TestHelpOnWindowsNamesThePC(t *testing.T) {
	texts := helpFor(t, "windows")
	for _, name := range []string{"kontext setup (short)", "kontext setup (long)", "kontext setup --uninstall", "kontext whoami (short)"} {
		text, ok := texts[name]
		if !ok || text == "" {
			t.Fatalf("no help text %q", name)
		}
		for _, word := range []string{"Mac", "keychain", "Homebrew", "profile add"} {
			if strings.Contains(text, word) {
				t.Errorf("%s names %q on Windows: %s", name, word, text)
			}
		}
	}
	for name, want := range map[string]string{
		"kontext setup (short)":     "this PC",
		"kontext setup (long)":      "Windows Credential Manager",
		"kontext setup --uninstall": "this PC",
		"kontext whoami (short)":    "this PC",
	} {
		if !strings.Contains(texts[name], want) {
			t.Errorf("%s = %q, want it to name %q", name, texts[name], want)
		}
	}
}

// What other tests ask of setup's long help holds on every system.
func TestSetupLongHelpNamesAgentHooksOnEverySystem(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if long := helpFor(t, goos)["kontext setup (long)"]; !strings.Contains(long, "hooks for supported local agents") {
			t.Errorf("on %s setup's long help does not name the agent hooks:\n%s", goos, long)
		}
	}
}

// The Mac's help is what it was.
func TestHelpOnMacOSIsUnchanged(t *testing.T) {
	texts := helpFor(t, "darwin")
	for name, want := range map[string]string{
		"kontext setup (short)":     "Connect this Mac to your Kontext organization",
		"kontext setup (long)":      "for the workspace this Mac is already connected to rotates the stored token",
		"kontext setup --uninstall": "remove the self-serve managed install from this Mac",
		"kontext whoami (short)":    "Show the workspace and person connected to this Mac",
	} {
		if !strings.Contains(texts[name], want) {
			t.Errorf("%s = %q, want it to contain %q", name, texts[name], want)
		}
	}
	if !strings.Contains(texts["kontext setup (long)"], "in your login keychain") || !strings.Contains(texts["kontext setup (long)"], "managed by Homebrew") {
		t.Errorf("setup's long help lost its macOS wording: %s", texts["kontext setup (long)"])
	}
}
