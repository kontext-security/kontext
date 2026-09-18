# OpenAI tool-related usage capture

Verified 2026-09-17 using the installed Codex CLI **0.154.0-alpha.6.2**.
This adapter reads local Codex transcripts; it does not intercept arbitrary OpenAI
SDK traffic or assume every agent exposes the same usage metadata.

## Sources and interpretation

- [OpenAI prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)
  defines inclusive input totals, cached reads, and separately priced writes on
  GPT-5.6 and later (30-minute retention, 1.25x base input).
- [OpenAI API pricing](https://developers.openai.com/api/docs/pricing) supplies the
  checked-in standard/global catalog in kontext-cloud's
  `apps/api/src/authorization-ledger/openai-prices.json`.
- [GPT-6 Astra](https://developers.openai.com/api/docs/models/gpt-6-astra),
  [GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol),
  [Terra](https://developers.openai.com/api/docs/models/gpt-5.6-terra),
  [Luna](https://developers.openai.com/api/docs/models/gpt-5.6-luna),
  [GPT-5.5](https://developers.openai.com/api/docs/models/gpt-5.5), and
  [GPT-5.4](https://developers.openai.com/api/docs/models/gpt-5.4)
  document the >272K input boundary and full-request rate multipliers.
- [Codex hooks](https://learn.chatgpt.com/docs/hooks) supplies `transcript_path`
  on hook stdin and requires review of non-managed hooks. The transcript format
  is explicitly unstable; the sanitized fixture pins the observed shape.

Codex's `token_usage_record` contains `thread_id`, `response_id`, and per-response
`usage`. We verified these fields with a real authenticated `printf` tool call.
`usage.input_tokens` includes `cached_input_tokens` and
`cache_write_input_tokens`. Ordinary input is their difference. Output includes
`reasoning_output_tokens`; reasoning must never be charged a second time. Missing
counts remain missing, including absent write counts, rather than becoming zero.
The adapter requires the per-response format and reports older cumulative-only
formats as a local capture error. It does not estimate token counts from strings.

## Scope, identity, and privacy

Only responses generating function/custom tool calls or immediately consuming
known tool results are persisted. Ordinary chat, later tool-free turns, and
compaction requests are excluded. Results belong to the following model request.
Multiple calls in one response share one response cost. Thread/turn totals and
`event_msg.token_count` are ignored; they must not be added to response usage.
The SQLite identity is `(codex-prefixed session ID, OpenAI response ID)`, with
revisioned upload acknowledgements. Re-reading/resuming does not add the same
response twice. Copied parent records in a fork are rejected by owning thread ID.
Only the `openai` model provider is accepted; custom OpenAI-compatible providers
must not inherit OpenAI rates based on a model name alone.

Transcript content stays local. Only IDs, tool names and optional type/namespace/
toolset/server metadata, model, timestamp, usage, and optional service tier enter
the usage payload. In code mode, `exec` is the model-facing wrapper. Its inner
tool calls cannot be inferred safely from the usage record; the cloud groups it
under Code execution. Hosted tool service fees and
whole-session usage are outside this feature. Subagent rollouts require their
own registered hook/session path; parent usage is not used to guess their cost.

## Local end-to-end verification

Use the existing enrolled local profile and run:

```sh
bash scripts/tool-cost-local.sh start
bash scripts/tool-cost-local.sh observe-codex
# Review the PostToolUse and Stop local cost observer definitions in Codex /hooks.
bash scripts/tool-cost-local.sh probe-codex
```

The observer is asynchronous, uses a dedicated socket, and only runs while that
socket exists. Settings are backed up, unrelated managed/user hooks are preserved,
and `unobserve-codex` removes only these two definitions. Normal installations
already include Codex PostToolUse/Stop hooks; they require the rebuilt CLI and
cloud code for this capture path. The installed regular daemon was not replaced.

Cloud preview is `http://localhost:3107/cost`, API `4107`. Follow the companion
cloud `docs/tool-cost-local.md`; use `NODE_ENV=test` and `RESEND_API_KEY=''` on
this isolated API so it does not process shared background alerts or send email.

Verified automatically, without a replayed hook:

- Session `codex-01a0afed-617c-70e2-9930-c584038d0451`, GPT-5.6 Luna.
- One harmless `printf` call; two model requests captured and uploaded.
- Ordinary input 4,104; cache reads 25,088; cache writes 0; output 127.
- API-equivalent cost: `(4104*0.2 + 25088*0.02 + 127*1.2)/1e6`
  = **$0.00147496**.
- A tool-free follow-up is excluded even though the transcript grows.
- Both OpenAI and Anthropic are visible in the local Cost page; totals are
  aggregated over complete selected windows without per-tool fan-out.

The earlier sanitized probe fixture totals $0.00192352. A separate replayed Stop
probe totals $0.00149976; those are distinct sessions, not differing calculations
of the same request. Local probe records are test activity, not subscription bills.

Validation includes parser scope/identity/unknowns/forks/partial writes,
SQLite reconciliation and acknowledgement, hook/IPC paths, pricing boundaries,
cross-agent ingest validation, and disposable PostgreSQL mixed-provider totals,
component reconciliation, historical prices, tenant isolation, and pagination.

## Existing desktop session recovery (2026-09-17)

The active Codex Desktop task had per-response `token_usage_record` counters,
but no entry in `tool_usage_sources`. Only the two earlier CLI probe transcripts
were registered. Its session metadata reports originator `Codex Desktop`, source
`vscode`, and model `gpt-6-astra`. Missing charts were a source-registration gap,
not missing OpenAI counters. The exact desktop hook-discovery cause is not yet
verified; trusting hooks in a CLI session alone did not register this existing task.

For an already-running task, explicitly attach that one session:

```sh
bash scripts/tool-cost-local.sh register-codex [SESSION_ID]
```

Inside Codex, the ID defaults to `CODEX_THREAD_ID`. The helper locates exactly one
matching rollout, validates its owning session and OpenAI provider, and uses the
store's registration API plus session metadata upsert. No synthetic Stop or tool
event is ingested, no hook trust changes are made, and unrelated transcripts are
not imported. The existing worker backfills only tool-related responses, then
continues following the registered file, including across collector restarts.
Sources are revisited for the existing seven-day registration window.

Verified the active task uploaded hundreds of Astra requests and new records
continued uploading during development; the local Cost page now shows Astra
usage alongside Claude and the Luna probes. This explicitly recovered desktop
task is distinct from automatic hook registration. New desktop-session discovery
still needs verification before calling the integration production-ready.
