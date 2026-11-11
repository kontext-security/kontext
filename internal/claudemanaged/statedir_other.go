//go:build !windows

package claudemanaged

// savedOutputStateDir is the Kontext state folder relative to the user's home,
// as the rule for Claude Code names it.
const savedOutputStateDir = "Library/Application Support/Kontext"
