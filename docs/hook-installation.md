# Shared hook installation

`internal/hookinstall.Definitions` owns the hook set for `kontext setup`,
`kontext hooks`, and doctor. Both installation channels install every supported
agent's hooks, even when that agent is absent.

| Scope | Agent | Files |
| --- | --- | --- |
| user | Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json` |
| user | Codex | `~/.codex/hooks.json`, `~/.codex/config.toml` |
| system | Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json` |
| system | Codex | `/etc/codex/hooks.json`, `/etc/codex/config.toml` |

Claude's drop-in is system-scoped in both channels. Cowork uses the Claude
managed settings. The managed config contract remains `agent: claude`.

## Package commands

```sh
kontext hooks install --scope system --dry-run --binary /usr/local/bin/kontext
sudo kontext hooks install --scope system --binary /usr/local/bin/kontext
sudo kontext hooks remove --scope system
```

The explicit user commands honor `CODEX_HOME` when set; the table shows its
default. Existing `kontext setup` paths remain unchanged at `~/.codex`.

These commands are macOS-only. System mutations require root. Dry-run requires
no elevation and creates no files, directories, or backups. A real install
requires the target binary to be an executable file; dry-run can plan before
the binary exists. User scope runs as
the target user and uses sudo only for the Claude drop-in:

```sh
kontext hooks install --scope user --binary /opt/homebrew/bin/kontext
kontext hooks remove --scope user --dry-run
```

Output is one tab-separated line per file, in definition order:
`action<TAB>scope<TAB>absolute path<TAB>reason`. Actions are `write`, `remove`,
`skip`; dry-run uses `would-write` and `would-remove`. Reasons include `missing`,
`stale`, `unchanged`, `owned`, `absent`, and `foreign`. Errors exit nonzero.
No daemon or launch agent is started, stopped, or reconfigured.

Installation refuses unknown Claude drop-in ownership and malformed Codex
configuration. It preserves foreign Codex hooks and TOML settings. An unchanged
installation produces only `skip` lines. Changed Codex files use the existing
`.kontext-setup-backup-<timestamp>` backups; system files are readable by all
users. Backups remain after removal.

`hooks remove` removes only Kontext hook commands and its own Claude drop-in.
A comment on a changed Codex feature line records its previous value. Removal
restores that line or removes an added flag; it leaves pre-enabled flags and
unrelated settings alone. Removing the ownership comment relinquishes ownership.
Self-serve setup retains its existing messages, backups, and uninstall behavior,
including leaving its Codex feature setting enabled.

## Self-serve upgrades

The existing Homebrew daemon checks its Claude drop-in once on the first
successful startup of each CLI version. The receipt is shared by all profiles
at `~/Library/Application Support/Kontext/hook-migration.json`. Normal restarts
read that receipt and skip hook inspection; no periodic migration check runs.

If the existing Kontext-owned hooks need updating (for example, the older
five-event configuration lacks Stop and SubagentStop), the daemon requests
administrator approval through macOS and refreshes only the Claude drop-in.
Unchanged hooks need no approval. Both automatic and manual Homebrew upgrades
are covered by the existing daemon restart mechanism. No management app or
additional user command is required for an approved migration.

The approval runs after the hook socket starts serving, so waiting, cancellation
or failure does not interrupt existing hooks or exports. An attempt is saved
before the dialog opens; cancellation, timeout or failure leaves the receipt
pending and does not prompt again for that version. If no console session is
available, approval is deferred until a subsequent daemon startup with the
user logged in. Existing hook health checks continue reporting missing hooks.
An explicit `kontext hooks install --scope user --binary <stable-kontext-path>`
can retry a declined or failed migration without waiting for another release.

Automatic migration never creates a missing drop-in or replaces foreign,
malformed or symlinked settings. The elevated command rechecks the approved
file digest, the running binary and the absence of organization-managed
configuration before writing. System/MDM, environment-scoped and development
installations do not use this flow. Already-running Claude sessions may still
need restarting to load updated hooks.

## Codex system configuration

Codex reads `/etc/codex/config.toml` as its Unix system configuration layer.
Its `[features]` table accepts `hooks = true`. This is documented in OpenAI's
[configuration precedence and feature flags](https://developers.openai.com/codex/config-basic#configuration-precedence)
and present in the [Codex configuration loader](https://github.com/openai/codex/blob/da05cafd27cb70f84f6f9b4f40d2b2c5ca62f224/codex-rs/core/src/config_loader/mod.rs#L65).
There is no need to modify the console user's home during a system install.

User and trusted project configuration can override system defaults. Doctor
checks the channel's hook files and feature flag and reports a user-level
`hooks = false` override as unhealthy. This is a configuration check, not proof
of hook trust approval or session-specific/project overrides. Codex may require
review in `/hooks` before hooks run; installation does not grant that trust.

Doctor applies the same rule to both scopes. It detects agent executables on
PATH and common install paths, plus `/Applications` and `~/Applications` app
bundles. Inert `.claude`/`.codex` files are not evidence of agent presence.
Absent agents print `<Agent> hooks: not installed (agent not present)` and do
not affect health. Present agents require a complete valid channel hook set,
a runnable Kontext binary, and Codex feature enablement.
