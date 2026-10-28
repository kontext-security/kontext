# Shared hook installation

`internal/hookinstall.Definitions` owns the hook set for `kontext setup`,
`kontext hooks`, and doctor. Both installation channels install every supported
agent's hooks, even when that agent is absent.

| Scope | Agent | Files |
| --- | --- | --- |
| user | Claude Code | `~/.claude/settings.json` (or `CLAUDE_CONFIG_DIR/settings.json`) |
| user | Codex | `~/.codex/hooks.json`, `~/.codex/config.toml` |
| user | Cursor | `~/.cursor/hooks.json` |
| system | Claude Code | `/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json` |
| system | Codex | `/etc/codex/hooks.json`, `/etc/codex/config.toml` |
| system | Cursor | `/Library/Application Support/Cursor/hooks.json` |

Self-serve (`kontext setup`, `hooks install --scope user`) writes only files in
the user's home, so it never asks for a password. It merges into existing
files, preserving foreign settings and symlinks and backing up changed files.
Setup stops before writing anything when a Claude, Codex or Cursor file cannot
take the hooks. Organization packages install the system set; their output is
pinned byte for byte by `TestSystemScopeOutputPinned`. The managed config
contract remains `agent: claude`.

Cowork starts Claude with a per-session `CLAUDE_CONFIG_DIR`, so it reads only
Claude's machine-wide managed settings. Self-serve does not write them: Cowork
is governed on a self-serve Mac only when an earlier setup left the drop-in.
Setup and doctor say so. A project `.claude/settings.json` with
`disableAllHooks: true` switches off user-level hooks in that project but not
managed ones.

Machine-wide files an earlier self-serve setup wrote stay untouched and keep
governing. Claude runs a handler present in two files once only when both are
identical (differing paths or timeouts run twice), so the user copy repeats the
binary path the earlier drop-in names. Cursor runs every hooks file it finds
without deduplication, so the user file stays free of Kontext while the
machine-wide file carries the complete set. Uninstall removes only Kontext's
handlers from the user files and names `sudo kontext hooks remove --scope
system` when an earlier setup's machine-wide hooks remain. It leaves an empty
user settings object rather than deleting that file.

## Package commands

```sh
kontext hooks install --scope system --dry-run --binary /usr/local/bin/kontext
sudo kontext hooks install --scope system --binary /usr/local/bin/kontext
sudo kontext hooks remove --scope system
```

The explicit user commands honor `CODEX_HOME` and `CLAUDE_CONFIG_DIR` when set;
the table shows their defaults. Existing `kontext setup` Codex paths remain at
`~/.codex`. `--binary` defaults to this executable's stable Homebrew path for
user scope and `/usr/local/bin/kontext` for system scope.

These commands are macOS-only. System mutations require root. Dry-run requires
no elevation and creates no files, directories, or backups. A real install
requires the target binary to be an executable file; dry-run can plan before
the binary exists. User scope runs as the target user without elevation:

```sh
kontext hooks install --scope user
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

## Self-serve upgrades and self-heal

Once a minute the self-serve daemon runs `hooks install --scope user` with its
stable Homebrew binary. Unchanged files are left alone; a removed entry comes
back, and the first start of a version that supports a new agent adds that
agent's hooks. Nothing needs a password, because every file is in the user's
home. The daemon skips the run while it is an old process after Homebrew
retargeted its symlink, and skips a settings file that resolves into a macOS
privacy-guarded folder (`kontext hooks install --scope user` in a terminal
covers that case).

To switch Kontext off on a self-serve Mac, run `kontext setup --uninstall`: it
stops the background agent before removing the hooks, so they stay removed.
Removing hook entries by hand while the agent runs is undone within a minute,
and doctor says so.

This runs only when the daemon loaded the self-serve user config. An
organization-managed config never reaches it, whatever files exist on disk.
Development and custom builds outside Homebrew are left alone too.

When any hook file of either scope changes, the daemon rescans agents right
away, so the dashboard's agent inventory follows within a minute instead of
waiting for the ten-minute scan. Already-running agent sessions may need
restarting to load updated hooks.

## Claude diagnostics and dispatch verification

Doctor checks the Homebrew user hooks against the managed template, reports
drift that can cause duplicate execution, and provides the repair command.
It inspects `managed-settings.json` and all non-hidden JSON drop-ins for invalid
JSON and hook restrictions, in filename order. A later Boolean value replaces
an earlier one. It never changes `disableAllHooks` or `allowManagedHooksOnly`.

A local `remote-settings.json` cache is a clue, not proof of an active policy:
it can belong to another account or provider. Doctor reports its presence and
asks for `/status` to establish which sources a session actually selected.
Installation health remains an offline configuration check, including in
`doctor --json`; it is not proof of session activation. The text output says
activation is unverified and directs the user to a fresh session's `/status`,
`/hooks`, and a real tool event in Kontext. No Claude session or network policy
fetch is started by doctor. The doctor JSON contract is unchanged.

The optional native dispatch test verifies the actual installer output with
Claude 2.1.300, including system-only and user-only installs, a user copy next
to an earlier drop-in (same and different binary path), a differing-path
negative control, managed restrictions, and project `disableAllHooks`:

```sh
KONTEXT_TEST_CLAUDE_BINARY=/absolute/path/to/claude \
  go test ./internal/hookinstall -run '^TestClaudeHookLayersDispatch$' -count=1 -v
```

It uses an ad-hoc signed temporary executable copy with only the system managed
directory redirected, temporary settings, a hook recorder, and a loopback fake
model server. It does not access real account credentials or model APIs, edit
host settings, or verify a customer's remote policy delivery. The test refuses
unrecognized executable layouts rather than changing arbitrary binary bytes.

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
