<img src="assets/kontext-computer-wordmark.gif" alt="Kontext animated wordmark" width="100%" />

<div align="center">

<p>
  <a href="https://kontext.security">Website</a>
  |
  <a href="https://docs.kontext.security/getting-started/welcome">Documentation</a>
  |
  <a href="https://app.kontext.security">Dashboard</a>
  |
  <a href="https://discord.gg/gw9UpFUhyY">Discord</a>
</p>

<p>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-152822?labelColor=0d1714"></a>
  <a href="https://github.com/kontext-security/kontext/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/kontext-security/kontext?color=152822&labelColor=0d1714"></a>
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.26-152822?labelColor=0d1714">
</p>

</div>

# Stop risky AI-agent actions before they run

AI agents do more than suggest code. They run shell commands, read files, call
services, change infrastructure, and interact with production systems.

**Kontext puts local policy between AI agents and the tools they call.** It
observes supported actions, evaluates policy before consequential actions run,
and records the decision and outcome in an authorization ledger.

Start in observe mode. See what policy would stop. Move supported boundaries
into enforcement when you are ready.

Policy evaluation errors, a policy that is not ready (missing, corrupt, or
expired), and an unresolved identity allow the tool call, including in enforce
mode, and remain visible as failures in the activity record. Only completed
policy denies and unavailable required approvals block. When the hook cannot
get a decision at all, because the daemon is down, restarting, too slow, or
returns something unreadable, the tool call is not blocked and Kontext returns
no decision, so the agent's own permission settings apply.

- **Local decisions:** policy evaluation happens alongside the agent.
- **Pre-action enforcement:** matching actions can be denied at supported
  synchronous hooks.
- **No wrapper command:** install Kontext once and continue using your agents
  normally.
- **Attributable evidence:** preserve the agent, session, action, policy
  decision, and outcome.
- **Managed rollout:** distribute policy and review redacted records across an
  organization.

Kontext currently supports **Claude Code, Claude Cowork, Codex, Cursor, and
Antigravity**. Exact event and enforcement coverage varies by agent—see the
[agent support matrix](docs/coverage.md).

Managed Claude hooks recognize Cowork sessions with either full or shortened
session directory names, preserving their Cowork identity in activity records.

---

## Quickstart

### Install Kontext

**macOS**

```bash
brew install --cask kontext-security/tap/kontext
```

The cask updates itself: the background agent checks for a new release a few
minutes after it starts and every six hours, upgrades through Homebrew, and
restarts on the new version. It installs the notarized binary as is, so it does
not need an up-to-date Xcode.

Homebrew 7 updates only packages from taps you trust. Installing the cask by its
full name trusts it. A cask installed before Homebrew 7 is not trusted, and
Kontext does not trust it for you: `kontext doctor` shows the warning, and you
run `brew trust --cask kontext-security/tap/kontext` once.

To let Homebrew alone manage updates, install the homebrew-core formula instead.
It gets each release a few hours later, and you update it with
`brew upgrade kontext` (Homebrew does not allow formulae to update themselves):

```bash
brew install kontext
```

**Windows** (Windows 11, x64 and Arm)

Download the zip for your PC from the
[latest release](https://github.com/kontext-security/kontext/releases/latest),
unzip it into a folder you keep, and use `.\kontext.exe` there for the commands
below. [Kontext on Windows](docs/windows.md) has the steps, what setup changes
on the PC, and what Windows does not have yet.

### Connect this machine

Create an install token in the
[Kontext dashboard](https://app.kontext.security), then run:

```bash
kontext setup
```

Setup:

- stores the install token in the macOS login keychain, or in Windows Credential
  Manager;
- installs hooks for supported agents in your home folder, without `sudo` or
  administrator rights;
- starts the local Kontext daemon, and has it start when you sign in;
- connects the installation to your Kontext organization.

Verify the installation:

```bash
kontext doctor
```

Then keep using Claude Code or Codex normally. You do not need to launch the
agent through a separate wrapper. Codex runs hooks only after you trust them:
start `codex` once after setup, and trust the Kontext hooks when it asks, or in
`/hooks`.

The journey is the same on every system: install, connect with `kontext setup`,
check with `kontext doctor`, keep working, and move from observing to enforcing
in the dashboard. Only the install step differs.

> Self-serve setup supports macOS and Windows. On Windows it covers Claude Code
> and Codex. Managed and cloud environments can run the same local runtime when
> they provide a supported hook contract, storage, and daemon lifecycle.

---

## What changes after setup?

Without pre-action policy, an agent action executes before a security team can
review its logs:

```text
agent requests an action
        |
        v
action executes
        |
        v
activity appears in a log
```

With Kontext:

```text
agent requests an action
        |
        v
Kontext receives it through a supported hook
        |
        v
local policy evaluates the action
        |
        +---- allow ----------> action continues
        |
        +---- would deny -----> action continues and evidence is recorded
        |                       (observe mode)
        |
        +---- deny -----------> action is stopped before execution
                                (enforce mode)
        |
        v
decision and outcome enter the authorization ledger
```

This creates a decision point before the action, not only a record after it.

---

## Observe first. Enforce when ready.

Blocking every unfamiliar action on day one creates noise and interrupts
developers. Allowing every action indefinitely leaves policy as passive
monitoring.

Kontext separates rollout into two modes:

### Observe mode

Observe mode records the policy decision without interrupting the agent.

Use it to answer:

- Which tools are agents calling?
- Which actions would current policy deny?
- Which repositories, files, and systems are involved?
- Where would enforcement interrupt legitimate work?
- Which event surfaces can actually stop the action?

### Enforce mode

Enforce mode returns a real denial when a deterministic policy matches at a
supported synchronous pre-action hook.

Policies can define boundaries around actions such as:

- destructive commands;
- sensitive-file access;
- production-system operations;
- credential access;
- data exports.

Enforcement is intentionally limited to event surfaces where the agent waits
for Kontext before continuing. Kontext does not claim that receiving an event
means it can stop every action from that agent.

---

## Know what happened—and why

Every supported event that reaches Kontext can contribute evidence to the local
authorization ledger.

A record can include:

- the agent and session;
- the lifecycle or tool event;
- the tool name and available input;
- the local policy decision;
- the policy responsible for that decision;
- the available action outcome;
- redacted evidence for later review.

Kontext records tool activity and decision evidence. It does not capture model
reasoning or reconstruct full conversation history. Each prompt starts a turn
that groups the actions and tool-related model usage after it; the turn record
carries a redacted, bounded prompt excerpt only when the workspace captures
Summaries or Full payloads and has work-type classification on, and the
prompt's size alone otherwise.

Managed deployments can export redacted records to the Kontext dashboard for
organization-wide review, retention, and investigation.

Ledger exports and idle heartbeats report the running daemon's CLI release as
`device.cli_version`, separately from the package marker in
`device.deployment_version` (or its self-serve fallback). A package marker update
does not change the reported CLI release until a daemon running the new binary
sends telemetry.

---

## Policy where the agent runs

The decision path stays local:

```text
       supported agent
              |
              v
        supported hook
              |
              v
     local Kontext runtime
              |
        +-----+------+
        |            |
        v            v
  policy decision   local ledger
        |
        v
 allow / would deny / deny
```

A hosted service does not need to answer every tool call.

Managed deployments add organization configuration, policy rollout, record
export, identity, and retention. They do not move the synchronous decision path
out of the agent environment.

---

## Supported agents

“Supported” means more than accepting an event. Kontext documents which events
it receives, which events can block, and how each integration is installed.

| Agent | What Kontext records | Pre-action blocking | Installation |
| --- | --- | --- | --- |
| **Claude Code** | Session lifecycle, prompt submission, pre-tool-use, successful and failed post-tool-use, stop and subagent stop | Pre-tool-use | Installed by `kontext setup` |
| **Codex** | Session start, pre-tool-use, post-tool-use, prompt submission, stop | Pre-tool-use | Installed by `kontext setup`; trust the hooks once in the Codex CLI's `/hooks` |
| **Claude Cowork** | Claude Code-compatible session and tool events | Pre-tool-use | Configure the hook inside the Cowork environment |
| **Cursor** | Session lifecycle, prompt submission (IDE only), pre-tool-use, successful and failed post-tool-use, stop | Pre-tool-use | Installed by `kontext setup` |
| **Antigravity** | Session start, prompt submission, pre-tool-use, successful and failed post-tool-use, stop | Pre-tool-use | Installed by `kontext setup` |

See the [agent support matrix](docs/coverage.md) for exact behavior, deployment
scope, and known gaps. It is the authoritative source for enforcement coverage.

---

## Kontext and sandboxes solve different problems

A process sandbox asks:

> Which files, network destinations, credentials, and operating-system
> resources can this process access?

Kontext asks:

> Which agent is attempting which action, what policy applies, should the
> action proceed, and what evidence proves the decision?

Kernel sandboxes are strong containment boundaries. Kontext provides semantic
policy and attribution at supported agent and tool hooks.

They are complementary:

```text
Kontext
  decides whether the action is authorized
              |
              v
sandbox
  constrains what the process can physically access
```

Kontext does not claim kernel-level isolation. Use an appropriate sandbox when
the threat model requires process, filesystem, or network containment.

---

## Why not just collect agent logs?

Logs tell you what an agent reported after an event.

Kontext creates an authorization decision before supported consequential
actions execute, then links that decision to the available outcome.

That distinction matters during:

- policy rollout;
- incident investigation;
- production-access review;
- developer exception handling;
- compliance and audit review.

The result is not only “the agent called a tool.” It is evidence of what was
requested, which policy applied, whether it was allowed, and what happened
next.

---

## Run Kontext across your organization

Managed deployments add:

- centrally managed deterministic policy;
- enterprise identity and organization controls;
- observe-to-enforce rollout;
- managed agent and cloud deployment support;
- redacted evidence export;
- audit retention;
- deployment health and backlog monitoring;
- onboarding for security and platform teams.

For deployment planning and organization onboarding, contact
[michel@kontext.security](mailto:michel@kontext.security) or
[book a conversation](https://calendar.superhuman.com/book/11W5Y8b5JsB8dOzQbd/YECs9).

---

## Diagnose an installation

```bash
kontext doctor
```

`doctor` checks:

- installed agent hooks;
- daemon health and version;
- managed export health;
- pending export backlog.

It exits non-zero when a configured installation is unhealthy.

Claude hook validation accepts equivalent shell quoting while still requiring
the expected executable, arguments, and event settings. Codex runs the hooks in
both its system and user files, so doctor checks the two together: each event
needs one runnable Kontext hook. A file without Kontext hooks is fine; a
malformed file, a missing event, or an event both files run report an unhealthy
setup.

When an owned Claude drop-in is missing only events required by the current
version, doctor names the missing events and the scope-specific `hooks install`
command. Self-serve repairs never need `sudo`; organization repairs require
`sudo` with `--scope system`. `doctor --fix` does not reinstall hooks.

Cowork reads only machine-wide Claude settings, so a self-serve Mac governs
Cowork only when an earlier setup left Claude's machine-wide drop-in. Doctor
says which applies.

When a self-serve daemon is stale:

```bash
kontext doctor --fix
```

Rotate the installation token by running setup again:

```bash
kontext setup
```

The background agent restores Kontext hooks removed by hand within a minute and
adds hooks for newly supported agents after an update. To switch Kontext off,
remove the installation:

```bash
kontext setup --uninstall
```

The repairs above are described for macOS; for Windows see
[Kontext on Windows](docs/windows.md).

---

## Data handling

- Policy decisions happen locally.
- Tool activity and decision evidence are stored locally.
- Sensitive values are redacted before local storage and managed export.
- Kontext does not store model reasoning or full conversation history.
- Managed deployments can export redacted records to the organization
  dashboard.
- Tool output compaction, when an administrator turns it on, sends large tool
  outputs and recent conversation context to the Kontext API, with secrets
  replaced on the device first, and on macOS routes Codex's model requests
  through a local proxy (below).

See the [Guard documentation](docs/guard.md) for the runtime and data boundary.

### Tool output compaction

Tool output compaction is off unless an administrator turns it on for an
endpoint in the dashboard. When it is on, the managed daemon sends each Claude
Code Bash or Read output and each direct Codex shell output over 2 KB, and on
macOS each printed part of a Codex code mode result over 2 KB, to the Kontext
API, with the latest prompt, the assistant's text for that call and up to six
recent transcript items. Secrets in what it sends are replaced with
placeholders on the device first and put back in the reply before the agent
sees it. If the API returns a shorter version, the agent gets that version
instead:

- The full output is saved first, readable by the user only, under
  `managed-observe/tool-output/` in the daemon's data directory. A session's
  saved outputs are deleted together seven days after its newest one, and when
  all of them pass 512 MB, the longest-idle sessions go first. On
  macOS, Kontext's machine-wide Claude Code settings let the agent read that
  folder without a prompt. With the hooks in the user's own settings, the Read
  tool asks once; reading it from the shell does not.
- A shortened Read result keeps its line numbers; the agent reads the file
  itself for any lines it needs.
- When a later call reads a saved output or a left-out part of a file back, the
  daemon reports that to the API, without content.
- Outputs are compacted in every folder. The daemon still never opens files
  in the folders macOS guards with a permission prompt (Desktop, Documents,
  Downloads, iCloud Drive, cloud storage, external volumes): the output
  arrives with the hook, and a transcript kept in one is not read for
  context.
- Codex runs most tools from code mode, where no hook can change a result. On
  macOS, while the switch is on, the daemon routes Codex's model requests
  through a local proxy: it adds an `openai_base_url` line marked
  `# kontext-codex-proxy` to `~/.codex/config.toml` and serves the proxy from
  a launchd job on a loopback port. The proxy shortens large printed parts of
  code mode results in each request and repeats earlier decisions byte for
  byte, so the model's prompt cache keeps working. It also declines Codex's
  WebSocket connection, so Codex sends its requests over HTTP instead. If
  shortening fails, the request goes on unchanged. Routing changes reach new
  Codex sessions only: a session already running when routing starts stays
  direct until Codex restarts, and one still using the proxy after routing
  stops gets its requests passed through unchanged. `kontext codex-proxy
  status` shows the route.
- The daemon leaves Codex alone when something else already routes it: a base
  URL, model provider or ChatGPT URL in the user's Codex config or in one an
  administrator manages (MDM, `/etc/codex`, or workspace-managed). It also
  takes the route away when the proxy cannot reach OpenAI or the proxy stops
  answering. The proxy reaches OpenAI through the Mac's manual proxy settings,
  unless the daemon's environment sets any of `HTTPS_PROXY`, `HTTP_PROXY` or
  `NO_PROXY` (in either case): then it uses exactly those and ignores the Mac's
  settings. It doesn't
  read proxy auto-config (PAC) files or proxy auto-discovery, so on networks
  that need them the proxy can't reach OpenAI and Codex stays direct, without
  compaction. An administrator
  can turn Codex routing off for an endpoint ("Codex on Mac") and keep
  compaction for the other agents.
- When Codex calls the shell directly rather than from code mode, the hook
  blocks the finished call with the shorter version as the reason: the model
  gets `Process exited with code N` and the shorter output in place of the
  result, while the person still sees the full output. Codex logs each such
  call as a tool error. Shorter versions over about 9.5 KB, which Codex would
  cut, are left as they are.
- Codex outputs that cannot be shortened are not sent: shell calls whose
  command was still running when the call returned or whose session log
  can't be read, and code mode results that don't pass through the proxy
  (Windows, Linux, or a Mac where Codex isn't routed).
- A hook's round trip gets at most three seconds, and a Codex request waits
  under two seconds at the proxy. Any timeout, error or unexpected reply
  leaves the output unchanged. Turning the switch off stops compaction and
  takes the Codex route away from the daemon's next configuration refresh,
  normally within a minute.

---

## Development

```bash
go build -o bin/kontext ./cmd/kontext
go test ./...
go test -race ./...
go vet ./...
```

## Community

- Read [SUPPORT.md](SUPPORT.md) for support channels.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a contribution.
- Report vulnerabilities through our [Security Policy](SECURITY.md).
- Kontext is released under the [MIT License](LICENSE).

### Authority report

`kontext report` shows discovered agents and authority exactly as last accepted
by the cloud. Use `kontext report --json` for the raw payload. Before the first
successful send, it reports no data.

Set `KONTEXT_AUTHORITY_SCAN=off` in the daemon environment to disable authority
collection and transmission on this Mac.
