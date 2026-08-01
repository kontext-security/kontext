<img src="assets/kontext-banner-cli.svg" alt="Kontext CLI banner" width="100%" />

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
  <a href="https://github.com/kontext-security/kontext-cli/releases"><img alt="Latest release" src="https://img.shields.io/github/v/release/kontext-security/kontext-cli?color=152822&labelColor=0d1714"></a>
  <img alt="Built with Go" src="https://img.shields.io/badge/Go-1.25-152822?labelColor=0d1714">
</p>

</div>

Kontext is an authorization platform for AI agents. It helps teams control what agents can access and do with scoped credentials, policy enforcement, approvals, and audit trails. Kontext can run local-first for developer agents and extend to managed or self-hosted deployments for security-sensitive environments.

## Quickstart

```bash
brew install kontext-security/tap/kontext
```

## Connect your machine to your workspace

Use self-serve setup to stream agent activity from your machine into your team's Kontext dashboard.

Generate an install token on your workspace's Deployments page, then run:

```bash
kontext setup
```

Re-run `kontext setup` to rotate the stored token. Run `kontext setup --uninstall` to remove the user-level config, hooks, LaunchAgent, and keychain token that setup installed; local logs and observe data are kept, and organization-managed hooks are left in place. Self-serve setup is currently macOS only.

Run `kontext doctor` to inspect the daemon version, heartbeat, and export backlog. When upgrading from a release that predates automatic stale-binary recovery, run `kontext doctor --fix` once if doctor reports an old or unknown daemon version; subsequent Homebrew upgrades restart the daemon automatically.

## Core features

Kontext balances security and utility for AI agents: low-risk actions keep moving, and unsafe actions can be blocked before they execute.

- **Audit trails:** Record who instructed which agent to do what, what the agent accessed, which tools it called, what policy decisions were made, and what happened next. Build a chain of custody for security review, incident investigation, and compliance evidence.
- **Deterministic policy:** Apply `allow` and `deny` rules to agent actions at runtime, before they execute. Use hard policies for known boundaries such as destructive commands, production resources, sensitive files, data exports, and credential access.
- **Probabilistic risk detection:** Route actions that deterministic policy allows through a local judge for an additional allow/deny decision without sending tool context to hosted services.
- **Credential injection:** Inject scoped OAuth credentials at runtime using RFC 8693-compliant OAuth 2.0 Token Exchange, so agents can access approved tools without users pasting secrets into chat, config files, or project environments. Credentials can be short-lived, least-privilege, and bound to the current user, session, or workflow.

The decision path is:

```text
Agent tool call
  -> agent hook
  -> daemon
  -> action classification
  -> deterministic policy
  -> probabilistic risk score
  -> allow / deny
  -> hosted dashboard stream
```

## Managed deployments

For enterprise identity, audit retention, organization controls, deployment planning, custom usage volume, and onboarding for security and platform teams, contact [michel@kontext.security](mailto:michel@kontext.security) or [book here](https://calendar.superhuman.com/book/11W5Y8b5JsB8dOzQbd/YECs9).

## Security defaults

| Default | Behavior |
| --- | --- |
| User-scope daemon | `kontext setup` installs a user LaunchAgent that runs `kontext managed-observe-daemon`. |
| Observe mode | Decisions are recorded as `would allow` or `would deny` without blocking the agent. |
| Keychain token storage | Self-serve install tokens are stored in the user's login keychain. |
| Redacted storage | Tool events and decisions are stored locally with redaction. |
| Managed local judge | Homebrew installs `llama-server` via `llama.cpp`; Kontext downloads and caches the default GGUF judge model when needed. |
| No reasoning capture | Kontext captures tool events and outcomes, not LLM reasoning, token usage, or full conversation history. |

## Agent support

| Agent | Status | Self-serve path | Support level |
| --- | --- | --- | --- |
| Claude Code | Active | `kontext setup` | Daemon, dashboard stream, observe by default (enforce only when managed config sets `enforce`). |
| Claude Cowork | Active | `kontext setup` | Cowork activity appears in the dashboard after setup. |
| Goose | Planned | Coming soon | Adapter not shipped yet. |
| Codex | Planned | Coming soon | Adapter not shipped yet. |
| Cursor | Planned | Coming soon | Adapter not shipped yet. |

Additional agents can be added through adapters that send compatible tool events into the local runtime.

## Architecture

```text
kontext setup
  |
  |-- User managed config: ~/Library/Application Support/Kontext/managed.json
  |-- Agent integration: hooks or observer
  |     |-- PreToolUse  -> kontext hook pre-tool-use
  |     |-- PostToolUse -> kontext hook post-tool-use
  |
  |-- LaunchAgent: security.kontext.managed-observe
  |-- Daemon: Unix socket service + RuntimeCore
  |-- Deterministic policy: curated rule categories + active profile
  |-- Probabilistic risk: local allow/deny decision after deterministic allow
  |-- Store: local SQLite with redacted events and decision metadata
  |-- Stream: governed activity to the hosted workspace dashboard
```

## Development

```bash
go build -o bin/kontext ./cmd/kontext
go test ./...
go test -race ./...
go vet ./...
```

Generate protobuf code with:

```bash
buf generate
```

Service definitions live in [kontext-security/proto `agent.proto`](https://github.com/kontext-security/proto/blob/main/proto/kontext/agent/v1/agent.proto).

## Community

- Read [SUPPORT.md](SUPPORT.md) for support channels.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a contribution.
- Kontext CLI is released under the [MIT License](LICENSE).
