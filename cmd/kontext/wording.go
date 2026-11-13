package main

import "runtime"

// helpGOOS is the system the help texts are written for (a test seam).
var helpGOOS = runtime.GOOS

// thisMachine is how help and readouts call the computer Kontext runs on.
func thisMachine() string {
	switch helpGOOS {
	case "darwin":
		return "this Mac"
	case "windows":
		return "this PC"
	default:
		return "this machine"
	}
}

// setupLong is the long help of `kontext setup`. Windows has its own text:
// the key is kept elsewhere, there are no profiles there, and nothing else
// manages the programs.
func setupLong() string {
	if helpGOOS == "windows" {
		return `Connect this PC to your Kontext organization (self-serve managed observe).

Setup asks for the install token created in the Kontext dashboard, stores it
in Windows Credential Manager, installs hooks for Claude Code and Codex in
your user profile, and starts a background agent that streams agent activity
to your workspace. It needs no administrator rights. Run it in a desktop
session: an SSH session cannot reach the credential store.

Re-running setup is safe. A new token for the same Kontext server replaces
the stored one and restarts the agent. A token for another server is refused,
and the message says how to move this PC over.

Use --uninstall to remove what setup installed: the install token, the hooks,
the sign-in entry and the config. The two programs, the installation identity
and the local records stay.`
	}
	return `Connect ` + thisMachine() + ` to your Kontext organization (self-serve managed observe).

Setup asks for the install token created in the Kontext dashboard, stores it
in your login keychain, installs hooks for supported local agents, and starts
a background agent that streams agent activity to your workspace.

Merlin provides local advisory assessment by default. It does not block tool calls.

Re-running setup is safe, and never overwrites an existing workspace. A token
for the workspace ` + thisMachine() + ` is already connected to rotates the stored token
and restarts the agent. A token for a workspace that already has another
profile rotates that profile's token and switches to it. A token for a new
workspace adds a profile for it (like ` + "`kontext profile add`" + `) and switches to
it, leaving the current profile untouched.

Use --uninstall to remove everything setup installed (the kontext binary
itself stays — it is managed by Homebrew).`
}
