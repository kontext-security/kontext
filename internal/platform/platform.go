// Package platform names the directories Kontext uses on each operating
// system. It only computes paths: it creates nothing and vouches for nothing,
// so whoever trusts a file under a system directory checks its owner first.
//
//   - SystemConfigDir holds Kontext's machine-wide configuration.
//   - UserStateDir holds this user's Kontext state.
//   - ClaudeManagedDir holds Claude Code's managed settings.
//   - CodexSystemDir holds Codex's system configuration.
package platform
