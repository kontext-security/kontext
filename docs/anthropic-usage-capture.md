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
   it consumes. Requests shared by multiple tools are counted once. The
   uploaded records contain counters, identifiers, tool names and pricing
   metadata; no prompt, tool arguments, response text or local transcript path.
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
bash scripts/tool-cost-local.sh probe
```

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

This adds async Stop, SubagentStop and SessionEnd observers to
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
