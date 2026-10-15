//go:build !darwin

package managedobserve

import "github.com/kontext-security/kontext/internal/diagnostic"

// healLaunchAgentPriority is a no-op off darwin: only launchd runs the LaunchAgent whose plist it
// heals.
func healLaunchAgentPriority(string, diagnostic.Logger) {}
