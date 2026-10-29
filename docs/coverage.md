# Agent support matrix

This matrix is the source of truth for Kontext agent support. “Supported” is
not a logo on a list: it means we state exactly which lifecycle events reach
Kontext, which of those can stop an action, and how the integration is
installed.

The decision path and local authorization ledger are the same for every
supported hook. What varies is the event surface the agent exposes.

## Live agent support

| Agent | Events recorded | Can block | Installation | Status and limits |
| --- | --- | --- | --- | --- |
| Claude Code | Session start/end; pre-tool-use; successful and failed post-tool-use | Pre-tool-use only | `kontext setup` installs a managed Claude Code hook configuration | Supported. Session lifecycle hooks run asynchronously, so they record context but do not hold up the agent. Claude's configured hook surface does not include prompt-submission events. |
| Claude Cowork | The Claude Code hook event format: session start/end, pre-tool-use, and successful or failed post-tool-use | Pre-tool-use only | Configure the Cowork hook to invoke `kontext hook --agent cowork …` | Supported at the hook-protocol level. Cowork runs Claude Code inside a per-session VM; deployment and hook configuration are owned by that environment, not by `kontext setup`. |
| Codex | Session start; pre-tool-use; post-tool-use; user-prompt-submit; stop | Pre-tool-use. Codex can also receive a block result for post-tool-use or user-prompt-submit events. | `kontext setup` adds user hooks and enables the Codex hooks feature; trust the hooks once in the Codex CLI's `/hooks`. | Supported. User-scoped setup is currently macOS-only. Hook status verifies the configuration, not that a hook has executed. |
| Cursor (IDE agent and `cursor-agent` CLI) | Session start/end; prompt submit (IDE only); pre-tool-use for shell, read, write, delete, grep and subagent calls; MCP calls through `beforeMCPExecution`/`afterMCPExecution`, which name the server; successful and failed post-tool-use | Pre-tool-use only | Managed and self-serve installs write `/Library/Application Support/Cursor/hooks.json`, which Cursor reads before team, project and user hooks and a user cannot turn off. There is no per-user install. | Supported from Cursor 2.4. Cursor's WebSearch and WebFetch tools fire no hook, so they are neither recorded nor blockable. A hook that crashes or times out lets the call run. |
| Other agents | — | — | — | Not yet a shipped integration. A compatible hook adapter can use the local runtime, but it is not covered by this matrix until its event contract and enforcement behavior are documented and tested. |

Managed Claude hooks identify Cowork from the working directory, transcript
path, or session path under the current user's Claude session storage. Both
`local_<uuid>` session directories and Claude's eight-character lowercase
hexadecimal session directories are recognized.

For Cedar v2 policy scoping, Claude Cowork uses the Claude Code agent identity.
Its `mcp__workspace__bash` tool is evaluated as a shell, including shell block
rules. Hook and ledger records still identify the agent as Cowork.

## What every supported hook records

For each event that reaches the runtime, Kontext records the agent, session,
event type, tool name, available tool input and outcome, policy decision, and
redacted evidence in the local authorization ledger. Managed deployments can
also export those records to the Kontext dashboard.

The fields are limited by the event sent by the agent. In particular, Kontext
does not reconstruct full model reasoning or conversation history, and it does
not claim an action completed when it only received a pre-action event.

## Enforcement boundary

Enforcement is available only where the agent offers a synchronous callback
before the consequential action runs. That is why the matrix calls out the
exact blocking points instead of describing an entire agent as simply
“enforced.” Start in observe mode, inspect the resulting ledger, then enable
the boundaries you are prepared to own.

## Deployment support

`kontext setup` is the self-serve managed deployment path. It currently
supports macOS and installs the local daemon plus Claude Code, Codex and Cursor
hook configuration, the same agents a managed (MDM) install covers. A cloud or managed-agent environment can run the same local
runtime next to the agent, provided it configures one of the supported hook
contracts and supplies the required local storage and daemon lifecycle.

For the runtime model and data boundary, see the [Guard documentation](guard.md).
