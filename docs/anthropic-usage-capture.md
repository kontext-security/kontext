# Anthropic tool usage and API-equivalent cost

Implemented on 2026-09-16 across `kontext-cli` and the companion `kontext` cloud
repository. The Cost tab covers model requests that generate tool calls or
immediately consume tool results. Ordinary conversation-only requests are
excluded. This is API-equivalent model-token cost, not subscription spending
or an exact marginal price for an individual tool.

## What was tested

A fresh Claude Code desktop session, running bundled Code 2.1.271 in an empty
temporary directory, received this prompt:

> Use the Bash tool exactly once to execute this harmless command: printf kontext-usage-probe. Do not read files or run any other command. After seeing its output, reply with only OK.

Temporary project hooks captured SessionStart, PreToolUse, PostToolUse and Stop
stdin, and took a snapshot of assistant usage in the supplied `transcript_path`.
The tool printed the marker and Claude replied `OK`.

The CLI 2.1.150 attempt failed before making a tool call because its OAuth login
had expired. Its `<synthetic>` error message carried zero token counts. Those
counts are not evidence of a successful zero-cost request and the parser skips
synthetic messages. The desktop session supplied the successful live sample.

A separate fresh Cowork task also ran `printf kontext-cowork-usage-probe` and
replied `OK`. Its visible UI exposed the command and output, not usage counters.
Its transcript/hook capture has **not** been verified. Sharing the Claude hook
decoder does not prove that the host can access a Cowork transcript.

## Actual records

The reported model was `claude-fable-5-1`. Preserve this identifier verbatim;
never choose a similarly named price or treat an unknown price as zero.

| Model message | Uncached input | Cache writes | Cache reads | Output |
| --- | ---: | ---: | ---: | ---: |
| Generate Bash tool call | 2 | 17,270 | 34,745 | 83 |
| Consume tool result and reply OK | 32 | 121 | 52,015 | 4 |
| Total | 34 | 17,391 | 86,760 | 87 |

All observed cache writes used the one-hour lifetime. Thinking tokens were
reported as zero. Service tier and speed were `standard`; inference geography
was `not_available`. The transcript also supplied message IDs, request IDs,
timestamps, tool-use IDs and a Code version.

These are whole model-request counts, including the agent's existing context.
The 104,185 input tokens total counts inputs across both requests, including
reused context. It is neither the context-window size nor the size of the shell
command/output. The 83 output tokens generate the tool invocation. The tool's
returned text becomes input to the next model request; it is not model output.

The hook payload itself contains no model usage. Observed timing:

| Hook | Assistant usage records already in transcript |
| --- | --- |
| PreToolUse | None |
| PostToolUse | Tool-generating message |
| Stop | Tool-generating message and final response |

This is one observation, not a flush-order guarantee. Collection must tolerate
delayed writes and retry/reconcile after turn completion. A PostToolUse-only
collector misses the final response. `Stop` here is Claude's lifecycle event
for a completed turn; it does not implement stopping or limiting an agent.

## Implemented path

1. Claude/Cowork hook decoding and local IPC preserve `transcript_path` and
   `agent_transcript_path`. PostToolUse, PostToolUseFailure, Stop, SessionEnd,
   and SubagentStop register available transcript paths in SQLite. Reading
   happens in the managed stream worker, outside the policy decision path.
2. The reader merges cumulative usage snapshots by session and message ID.
   Tool-result blocks associate only the next model request with the tools
   it consumes. Requests shared by multiple tools are counted once. Usage
   records contain counters, identifiers, tool names, pricing metadata and
   the request's `turn_id`; no prompt, tool arguments, response text or local
   transcript path. The prompt itself travels only in the turn record (step 7),
   as the workspace's configuration allows:

   | Payload capture mode | Work-type classification switch | Turn record's `prompt.mode` | Cloud keeps the text |
   | --- | --- | --- | --- |
   | Omitted | any | `omitted`: size only | never |
   | Summaries | off | `skipped`: size only | never |
   | Summaries | on | `excerpt`: redacted, at most 64,000 characters | yes, redacted, with the turn |
   | Full payloads | off | `skipped`: size only | never |
   | Full payloads | on | `excerpt`: redacted, at most 64,000 characters | yes, redacted, with the turn |

   Summaries and Full payloads send the same excerpt, bounded to the
   captured-payload cap. The cloud deletes stored excerpts when the workspace
   turns the switch off or moves to Omitted. Until the daemon has confirmed
   its endpoint configuration it sends `skipped`. A prompt over 1 MiB is never
   redacted and also goes as `skipped`, with its true size.
3. SQLite stores changed records with increasing revisions. The stream worker
   captures before network I/O, retries partial/delayed writes, resumes after
   restart, and acknowledges only the revision successfully uploaded. It
   revisits active sources for seven days and uncollected sources regardless
   of age. Files must be regular and at most 256 MiB; JSONL lines at most
   16 MiB. Per-source read errors are retained locally for diagnosis.
4. The cloud ledger contract accepts optional `tool_usage`, validates its
   session/tool associations, and persists it under organization, installation,
   session and message identity. Newer revisions replace older snapshots;
   retries and late uploads do not add duplicate costs.
5. `anthropic-prices.json` in the cloud API stores versioned, exact-model
   standard global API rates. Uncached input, cache reads, cache writes by
   lifetime and output are priced separately. Missing required counts,
   unknown models, inconsistent usage and unknown cache duration produce an
   unavailable estimate. Thinking is already included in model output.
6. The authenticated Cost endpoint returns organization-scoped totals and
   cursor-paginated requests. The Cost tab shows API-equivalent cost, token
   buckets, pricing coverage and a request detail drawer with related tools.
   The baseline excludes subscription charges and separate tool-service fees;
   geography, batch and speed surcharges/discounts are not applied.
7. Turns give the Cost tab its "Type of work" cut. On every
   `UserPromptSubmit` with a prompt the daemon mints `turn_<uuid>` before
   answering the hook, stamps it on every action recorded after the prompt
   (the prompt's own `request.observed` row included; never on the signed
   receipt) and stores one turn row per prompt: session, 1-based sequence,
   agent, start time, source (`user_prompt`, `slash_command`, `interrupt`) and
   the prompt as the table in step 2 allows. The excerpt drops system
   reminders, command messages and pasted blocks, is redacted with the Merlin
   review redactor, whitespace-collapsed and bounded around a
   `[Context omitted]` marker; `chars` is the original's length and `sha256`
   is over the trimmed, collapsed original. Each turn keeps the configuration
   in force when it was minted. The stream uploads turns (batch `turns`,
   schema `turn/v1`) before usage and acknowledges them by id; the server
   ignores a resent id.

   A harness message delivered as a prompt is not a turn: when, with system
   reminders removed, it is empty or opens with `<task-notification>`,
   `<side-sessions-event>`, `<ci-monitor-event>`, `<cross-session-message`,
   `[Cross-session`, a subagent's `<agent-message` hand-back, a `!` shell
   command's `<bash-input>`, a local command's `<local-command-stdout>`, or
   Codex's injected context (`<environment_context>`,
   `<external_codex_apps_…`, `<codex_internal_context`), no turn is minted,
   the transcript starts none, and the work after it stays with the prompt
   before (`modelusage.IsHarnessEnvelope`). Nor is a prompt in a Codex
   thread the app runs for itself, recognised by its hooks carrying no
   transcript path (see `openai-usage-capture.md`).

   The reader matches usage to turns by time, not by text or ordinal. Every
   real prompt line starts a transcript turn: a `user` row that is not a tool
   result, meta, sidechain or compact summary, or a queued prompt absorbed
   mid-turn (`queue-operation` remove, `absorbed_mid_turn`); for Codex a
   `task_started` or a user message after model output. Prompt *k* owns
   minted turns started from 1 s before it to 1 s before the next prompt and
   takes the earliest; usage between two prompts carries that turn's id. A
   prompt whose hook was missed (hook not installed, daemon down, a session
   resumed from before the install) leaves its usage without a turn, and never
   takes the next prompt's. Subagent transcripts (Claude `subagents/*.jsonl`,
   Codex sub-agent rollouts) start no turns: their usage falls into the
   session's turn at that time, using boundaries kept per session in SQLite.
   A request whose turn changes on a later read is re-emitted with a new
   revision. A new turn, or a boundary found in one transcript, marks the
   session's other transcripts for another read, so usage read before them
   moves too. Once the cloud acknowledges a turn, the daemon drops its local
   copy of the excerpt; the turn's id and time stay in guard.db as long as the
   session has usage to stamp, since a session can resume after any idle time.

   `kontext doctor` reports `prompt hook missing: turns and type of work
   unavailable` when an installed Claude Code or Codex hook set lacks
   `UserPromptSubmit`.

The sanitized live fixture includes both assistant usage records and the
intervening tool result. The matching PostToolUse payload is under
`internal/hookruntime/testdata`. Shared Cowork protocol tests do not establish
live Cowork capture. SubagentStop supports explicitly supplied transcript
paths; complete subagent coverage has not been verified live.

## Rollout and limitations

- Deploy the cloud migration `0092_tool_usage.sql` and API before releasing the
  updated CLI; an older API rejects the new optional field. Pending usage
  remains queued and ordinary ledger uploads retain their separate path.
- Update the CLI/daemon and rerun the existing managed-hook installation flow
  to add async Stop and SubagentStop observers. These observe completion;
  they do not stop, limit, or change policy decisions.
- Capture starts from hook-registered files. It does not crawl past transcripts
  or claim complete session spend. An unavailable/inaccessible transcript
  cannot contribute usage; the UI reports captured requests only.
- Price changes require an explicit catalog version update. Historical rows
  retain the version used when ingested; no automatic repricing is performed.
- Cowork VM transcript accessibility still needs a live end-to-end validation.

## Repeat the local end-to-end test

The companion cloud repository has `docs/tool-cost-local.md` with API and web
startup commands. The default isolated ports are API `4107` and web `3107`.
Use an enrolled local Kontext profile for the same local database/workspace.

From this CLI repository, keep the collector running in one terminal:

```sh
bash scripts/tool-cost-local.sh start
```

The helper builds this checkout, creates an isolated collector database,
installation identity and socket, and writes project hooks under
`.tmp/tool-cost-local/project/.claude/settings.json`. It reuses the active local
profile's credential reference; it does not replace the installed daemon or
global hooks. Remote profiles and non-loopback API URLs are refused. Override
the API with `KONTEXT_COST_CLOUD_URL` if needed. Ctrl-C stops this collector.

With an authenticated terminal Claude client, run in another terminal:

```sh
KONTEXT_COST_DATABASE_URL='postgresql://…/kontext_spaces' bash scripts/tool-cost-local.sh probe
```

The probe sends two prompts in one session, each running one `printf`, waits
for the collector to upload, then reads the session's turns and usage back
from the local database and writes `.tmp/tool-cost-local/turns-<date>.json`.
It passes when both turns are stored with sequences 1 and 2 and every usage
row carries one of their ids. Labels appear only when the cloud runs the
classification worker (`WORK_TYPE_CLASSIFICATION_ENABLED=true` and an OpenAI
key); `KONTEXT_COST_COOKIE` (a signed-in browser Cookie header) adds the Cost
summary's `byWorkType`. Without `psql` on PATH the queries run in the compose
Postgres container (`KONTEXT_COST_POSTGRES_CONTAINER`, default
`kontext-postgres-1`). `KONTEXT_COST_PROFILE` selects an enrolled local
profile other than the active one. `report-turns SESSION_ID` repeats only the
read-back.

Without a signed-in terminal client, `probe-replay` runs the same check by
replaying a Claude Code session through the built hook binary
(`scripts/tool-cost-replay.py`): transcript rows in Claude Code's format with
real-time timestamps and the hook calls in Claude Code's order, including a turn
from before the install and a subagent with its own sidechain transcript.

To keep the test off the shared development database, give the API a fresh one
and seed a workspace the way the cloud e2e suite does; `KONTEXT_COST_TOKEN_ENV`
then names the variable holding the install token, so no profile is enrolled:

```sh
docker exec kontext-postgres-1 psql -U postgres -c 'create database kontext_cli_turns_e2e'
# In the cloud checkout's apps/api, with DATABASE_URL pointing at that database:
node dist/apps/api/src/db/migrate.js
NODE_ENV=development WORK_TYPE_CLASSIFICATION_ENABLED=true PORT=4117 RESEND_API_KEY='' \
  AUTHENTICATED_CALL_METERING_WORKER_ENABLED=false node dist/apps/api/src/main.js
# Seed: an organizations row (payload_capture_mode, work_type_classification)
# and an install_tokens row holding sha256(token) for it. Then, here:
KONTEXT_COST_CLOUD_URL=http://localhost:4117 KONTEXT_COST_TOKEN_ENV=TOKEN_VAR \
  bash scripts/tool-cost-local.sh start
KONTEXT_COST_CLOUD_URL=http://localhost:4117 KONTEXT_COST_DATABASE_URL=… \
  bash scripts/tool-cost-local.sh probe-replay
```

`NODE_ENV=development` runs the classification worker, which the shared-database
recipe keeps off with `NODE_ENV=test`; on a database of its own nothing else is
processed. Changing the seeded row's capture mode or switch reaches the
collector on its next configuration refresh (about a minute).

Alternatively, select `.tmp/tool-cost-local/project` as the folder in Claude
Code desktop, keep worktree creation off, and send:

> Use Bash exactly once to execute: printf kontext-cost-local-probe. Do not read files or run other commands. After seeing the output, reply only OK.

Open `http://localhost:3107/cost`, select the same workspace, and click Refresh
after the turn completes and the collector syncs. Expect a request labelled
"Calls tools" and a request labelled "Reads tool results". The exact counters
depend on Claude's current model and context. Click a row for cache lifetime,
model, session and pricing details. A subsequent "Do not use any tools. Reply
only HELLO." should not add a tool-related request.

On 2026-09-17 this path was verified with a fresh Claude Code desktop session,
the real local cloud API/database, and the Cost page: 2 requests, 34 uncached
input tokens, 20,199 one-hour cache-write tokens, 96,093 cache-read tokens and
88 output tokens, totaling $0.43274325 API equivalent. Both records synced and
were acknowledged. The tool-free follow-up left the count at 2. The terminal
client still had expired OAuth credentials, so desktop supplied the live test.

### Observe normal Claude Code sessions during local testing

With the isolated collector running, enable its observer in user settings:

```sh
bash scripts/tool-cost-local.sh observe-all
```

This adds async UserPromptSubmit, Stop, SubagentStop and SessionEnd observers to
`~/.claude/settings.json` (or `CLAUDE_CONFIG_DIR/settings.json`). Other settings
and hooks are preserved, with a backup saved under `.tmp/tool-cost-local`.
It does not replace the regular managed daemon or its policy hooks. Usage is
collected when a turn completes, including tool-related requests already in
that session's transcript. No unrelated transcript directories are scanned.

Start a new Claude Code session or resume an existing session to load the
hooks, complete a tool-using turn, then refresh `http://localhost:3107/cost`.
This was verified with a new desktop Code session using **No folder** and no
project hooks: both tool-related requests synced successfully. Existing active
sessions may still be using their previous hook configuration.

Remove just these temporary observers before retiring the test collector:

```sh
bash scripts/tool-cost-local.sh unobserve-all
```

The observer checks for its socket and does nothing when the collector is
stopped. This remains a temporary two-daemon setup; integrating the feature
into the regular daemon is a separate runtime upgrade.

If records remain pending, inspect `.tmp/tool-cost-local/collector.log` when
stdout/stderr were redirected there and the API logs. Build cloud shared
packages before starting the API: stale compiled shared exports can pass
source-level type checks but fail live batch validation. No manual record
insertion is required; pending records retry automatically after recovery.

Anthropic defines total input as `input_tokens + cache_creation_input_tokens +
cache_read_input_tokens`. Cache lifetime details, thinking details and the
`iterations` breakdown must not be added again to their parent totals.
See [Anthropic prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching)
and [Claude Code hook inputs](https://code.claude.com/docs/en/hooks).
