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
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.25-152822?labelColor=0d1714">
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

- **Local decisions:** policy evaluation happens alongside the agent.
- **Pre-action enforcement:** matching actions can be denied at supported
  synchronous hooks.
- **No wrapper command:** install Kontext once and continue using your agents
  normally.
- **Attributable evidence:** preserve the agent, session, action, policy
  decision, and outcome.
- **Managed rollout:** distribute policy and review redacted records across an
  organization.

Kontext currently supports **Claude Code, Claude Cowork, and Codex**. Exact
event and enforcement coverage varies by agent—see the
[agent support matrix](docs/coverage.md).

---

## Quickstart

### Install Kontext

```bash
brew install kontext-security/tap/kontext
```

### Connect this Mac

Create an install token in the
[Kontext dashboard](https://app.kontext.security), then run:

```bash
kontext setup
```

Setup:

- stores the install token in the macOS login keychain;
- installs hooks for supported agents;
- starts the local Kontext daemon;
- connects the installation to your Kontext organization.

Verify the installation:

```bash
kontext doctor
```

Then keep using Claude Code or Codex normally. You do not need to launch the
agent through a separate wrapper.

> Self-serve setup currently supports macOS. Managed and cloud environments can
> run the same local runtime when they provide a supported hook contract,
> storage, and daemon lifecycle.

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
reasoning or reconstruct full conversation history.

Managed deployments can export redacted records to the Kontext dashboard for
organization-wide review, retention, and investigation.

---

## Policy where the agent runs

The decision path stays local:

```text
Claude Code / Cowork / Codex
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
| **Claude Code** | Session lifecycle, pre-tool-use, successful and failed post-tool-use | Pre-tool-use | Installed by `kontext setup` |
| **Codex** | Session start, pre-tool-use, post-tool-use, prompt submission, stop | Pre-tool-use | Installed by `kontext setup`; hooks must be trusted in Codex |
| **Claude Cowork** | Claude Code-compatible session and tool events | Pre-tool-use | Configure the hook inside the Cowork environment |

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

When a self-serve daemon is stale:

```bash
kontext doctor --fix
```

Rotate the installation token by running setup again:

```bash
kontext setup
```

Remove the self-serve installation:

```bash
kontext setup --uninstall
```

---

## Data handling

- Policy decisions happen locally.
- Tool activity and decision evidence are stored locally.
- Sensitive values are redacted before local storage and managed export.
- Kontext does not store model reasoning or full conversation history.
- Managed deployments can export redacted records to the organization
  dashboard.

See the [Guard documentation](docs/guard.md) for the runtime and data boundary.

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
