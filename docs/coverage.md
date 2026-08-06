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
| Codex | Session start; pre-tool-use; post-tool-use; user-prompt-submit; stop | Pre-tool-use. Codex can also receive a block result for post-tool-use or user-prompt-submit events. | `kontext setup` adds user hooks and enables the Codex hooks feature; the hooks must then be trusted in Codex. | Supported. User-scoped setup is currently macOS-only. Hook status verifies the configuration, not that a hook has executed. |
| Prime Agent | Session start/end; pre-tool-use; successful and failed post-tool-use; user-prompt-submit; stop | Pre-tool-use only | `kontext setup` installs a managed extension into `~/.prime/agent/extensions` when Prime Agent is detected | Supported via Prime Agent's extension system, which exposes a synchronous `tool_call` callback. The managed extension forwards events in the Claude Code hook-input format to `kontext hook --agent prime-agent` and fails open (with a visible warning) when the local runtime is unavailable. Prompt-submit events are recorded but not blocked in this integration. |
| Other agents | — | — | — | Not yet a shipped integration. A compatible hook adapter can use the local runtime, but it is not covered by this matrix until its event contract and enforcement behavior are documented and tested. |

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
supports macOS and installs the local daemon plus Claude Code and Codex hook
configuration. A cloud or managed-agent environment can run the same local
runtime next to the agent, provided it configures one of the supported hook
contracts and supplies the required local storage and daemon lifecycle.

For the runtime model and data boundary, see the [Guard documentation](guard.md).
