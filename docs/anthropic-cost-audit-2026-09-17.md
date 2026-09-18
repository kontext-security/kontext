# Audit of the Claude Cost screenshots

Checked 2026-09-17. Scope: the two screenshots from session
`ad5fef85-d58e-4d74-8d60-39c8365c2d26`, plus one controlled repeat in that same
Claude Code desktop conversation. This validates these observations, not all
capture paths or production readiness. No pricing or product code changed.

## Result

Both screenshot amounts match the raw transcript, local SQLite records,
cloud PostgreSQL rows, and independently calculated standard global API prices.
The two rows describe one Bash invocation: one model request generated it and
the next consumed its result. They are not prices for two different tools.

The recorded model is `claude-fable-5-1`, with standard service tier and speed.
`inference_geo` is `not_available`; global pricing is an explicit comparison
baseline, not an inferred billing location or subscription charge.

## Exact calculation

Anthropic's published rates, verified on the audit date, match the checked-in
catalog: $10 uncached input, $0.25 cache reads, $12.50 five-minute writes,
$20 one-hour writes, and $50 output per million tokens.
Source: [API pricing](https://platform.claude.com/docs/en/about-claude/pricing).

| Bucket | First request tokens | First request USD | Result-reading tokens | Result-reading USD |
| --- | ---: | ---: | ---: | ---: |
| Uncached input | 2 | 0.00002000 | 32 | 0.00032000 |
| Cache reads | 38,009 | 0.00950225 | 57,224 | 0.01430600 |
| One-hour cache writes | 19,215 | 0.38430000 | 124 | 0.00248000 |
| Output | 84 | 0.00420000 | 4 | 0.00020000 |
| Total | | **0.39802225** | | **0.01730600** |

Five-minute writes and reported thinking tokens were zero. One-hour writes
account for 96.55% of the first request's estimate. Both requests together are
$0.41532825. The UI's $0.398 and $0.0173 are correctly rounded.

## Cache reuse evidence

The first request's cached prefix is 38,009 + 19,215 = **57,224** tokens.
The next request reports exactly **57,224 cache-read tokens**, with just
**124 new write tokens**. It did not rewrite 57,224 tokens.

At 12:53 UTC, approximately nine minutes after the original call, the same
harmless command was repeated with the identical prompt and model:

| Request | Uncached | Cache reads | One-hour writes | Output | USD |
| --- | ---: | ---: | ---: | ---: | ---: |
| Repeat: generate Bash call | 2 | 57,352 | 78 | 84 | 0.02011800 |
| Repeat: consume its result | 32 | 57,430 | 124 | 4 | 0.01735750 |

The second pair totals **$0.03747550**. The operation and output counts are the
same, but much less context is newly cached. This is direct evidence that
cache state strongly affects a request associated with a tool.

Claude's `/context` inspector after the repeat reported approximately 57.7k:
17.9k system tools, 14.9k MCP tools, 14.1k in its Messages category, 6k system
prompt, and 4.8k skills. These are current diagnostic categories, not an exact
decomposition of the first request's cache-write tokens. The 33k autocompact
buffer shown separately is reserved space and is not added to request usage.

Anthropic documents three separate input buckets: uncached input, cache reads,
and cache creation. Prompt caching covers a prefix of tools, system and
messages. Hits require matching content; expiry and prefix changes can produce
new writes. A hit refreshes lifetime without another write charge.
Source: [Prompt caching](https://platform.claude.com/docs/en/build-with-claude/prompt-caching).

Claude Code documents an hour-long cache lifetime on subscriptions and sending
conversation context again for subsequent requests.
Source: [Claude Code costs](https://code.claude.com/docs/en/costs#why-usage-climbs-in-a-long-session).

## Counting checks

### Follow-up: what makes this small task's prompt large?

Inspection of the original first-turn transcript found setup attachments before
the first assistant/tool-use message, independently of the visible Bash prompt:

- A deferred-tool catalog adding 166 tool names/descriptions.
- A listing of 31 skills and six agent types.
- Instruction blocks from three MCP servers.
- Environment, model, permission-mode, date and session-context attachments.
- Desktop scratch-workspace guidance prepended to the user's prompt. That first
  text block was 2,754 characters, versus 148 for the subsequent identical
  visible prompt.
- A system-prompt snapshot containing harness guidance, memory instructions,
  session guidance and desktop-specific instructions. It has a dynamic-boundary
  marker but no per-block token counts or wire-level cache-control fields.

The saved `/context` diagnostic reports these used categories after the repeat:

| Category | Reported tokens |
| --- | ---: |
| System tools | 17,851 |
| MCP tools | 14,874 |
| System prompt | 6,047 |
| Skills | 4,753 |
| Messages | 14,061 |
| Total | 57,586 |

The diagnostic separately lists deferred tool schemas and reserved buffer
space. Those are **not** added to this total. A deferred catalog listing is not
equivalent to loading all of those tools' full schemas. The Messages category
must not be interpreted as just text typed by the user.

This establishes substantial setup overhead before Bash runs. The original
19,215 write tokens are input to the request that generates Bash, so they
cannot be Bash output. Reused tool definitions plus shared instructions are a
plausible explanation for much of the 38,009-token hit; first-turn setup and
session-specific context plausibly account for much of the newly cached
remainder. **That partition is an inference, not a measured per-category cache
breakdown.** The usage response and context diagnostic cannot identify exact
category membership of either cache bucket. The expected per-session debug
file was absent. Exact attribution needs a diagnostic of the original wire
request's ordered blocks/cache breakpoints with compatible token accounting.

### Storage and pricing checks

- The original transcript has two distinct message/request IDs, linked by the
  same tool-use ID; each appears once in the cloud database across installations.
- Raw `cache_creation_input_tokens` equals the reported one-hour count. The
  parser does not add the aggregate and its duration breakdown together.
- Raw `iterations` repeats those counters. The parser reads top-level usage
  once, rather than also adding `iterations`.
- Thinking is not added on top of output. Repeated message snapshots update
  existing records instead of accumulating another request charge.
- All four audited requests were acknowledged locally and stored once each in
  PostgreSQL with the exact independently calculated amounts above.
- Focused Go parser/store/stream tests passed. API pricing and controller tests
  passed (2 suites, 7 tests).

## What remains uncertain and what to change before release

The usage record does not expose the precise prompt sections behind the first
19,215 write tokens, the earlier request that populated its 38,009-token hit,
or a cache-miss reason. The context inspector cannot reconstruct those facts.
Do not claim a specific invalidation cause from the counters alone.

The current product attribution needs clarification before using it to rank
tools. Full request context is associated with the call, including work Claude
would perform even without that particular tool. This is not an isolated or
incremental Bash cost. Show dollar contributions by token bucket and make the
relationship between the generating and consuming requests easier to inspect.
Tool comparisons must account for model, context and cache state.

Further release validation should cover expired/changed prefixes, multiple
tools in one request, interrupted/updated transcript records, and session
handoffs. Existing unit coverage is not a substitute for live coverage of each
agent runtime; Cowork remains unverified.

There is also a migration concern: cloud identity currently includes
installation ID. Two collectors with different installation identities
uploading the same transcript can produce duplicate organization totals.
The audited session has no duplicates, but production rollout must retire the
temporary collector and define deduplication for reimports/installation changes.
