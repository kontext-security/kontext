package shellprojection

import "github.com/kontext-security/kontext/internal/cedareval"

// FactDialectPowerShell marks a projection of a command the agent ran
// through its PowerShell tool, so a policy can tell that dialect apart from
// a POSIX shell's.
const FactDialectPowerShell = "shell/dialect=powershell"

// ProjectPowerShell projects a command run through an agent's PowerShell
// tool. Every projection carries FactDialectPowerShell.
func ProjectPowerShell(command string) []cedareval.ShellProjectionV2 {
	projections := Project(command)
	for i := range projections {
		projections[i].Facts = sortedUnique(append(projections[i].Facts, FactDialectPowerShell))
	}
	return projections
}
