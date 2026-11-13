package claudemanaged

// savedOutputStateDir is the Kontext state folder relative to the user's home,
// as the rule for Claude Code names it. On Windows that is the local app data
// folder, in its usual place under the profile; a profile whose local app
// data was moved elsewhere is not covered by the rule.
const savedOutputStateDir = "AppData/Local/Kontext"
