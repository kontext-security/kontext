# Recovering missing turns

The stream worker can observe usage in a transcript even when its prompt hook
never reached the daemon. With validated settings that allow classification
and do not omit payloads, it recovers the missing turn from the real user prompt.

Recovery is automatic for new missed hooks. The first eligible reconcile after
an upgrade schedules registered transcripts once, bounded to 100 changed sources
per pass. Legacy unknown-policy prompts require an explicit historical request.
Missing or unreadable files retain
normal retry/retirement behavior. Unrecoverable usage remains accounted for.

Provider ownership and prompt-boundary rules exclude subagents, copied history,
harness envelopes and compaction summaries. A five-second grace period lets the
hook-recording queue finish before using a transcript fallback.

A delayed hook adopts the recovered turn ID through a durable alias. Recovery
also reads registered parent transcripts outside the current usage-reader batch.
Pending historical sources remain eligible after seven days and retry with
backoff; growing files are read through a stable prefix.

The cached incremental reader retains metadata only. Recovery uses a separate
short-lived reader after checking capture policy, and applies the same redaction,
hashing and 64,000-byte excerpt bound as a prompt hook. Raw text is not retained
in the metadata cursor or usage payload. Recorded explicit opt-outs remain
excluded after settings change and the transcript grows. Validated last-known
settings survive transient refresh failures and offline restarts; invalid caches
and rejected authority stay off. Verified stricter directives apply even if a
cache write fails.

Recovered IDs are deterministic per session and prompt timestamp. Existing
hook-created turns take precedence. Already-uploaded usage is revised under its
original session/message key, preserving requests and token counters. Retrying
does not add turns or revisions. Existing hosted IDs survive local history pruning.

Skipped text can be restored when its original hook recorded an unconfirmed
capture directive. Confirmed opt-outs, omitted prompts and existing text are not
overwritten. The original ID is re-exported; the API accepts the first permitted
excerpt and queues classification once.

## Rollout and verification

Deploy API support before releasing the endpoint. The API must accept restored
excerpts and use `(started_at, sequence)` for previous-prompt context and label
inheritance: recovered historical prompts have later allocation sequences.

Run provider JSONL → SQLite → revisioned HTTP upload E2E tests with a report:

```sh
KONTEXT_RECOVERY_E2E_ARTIFACT=/tmp/kontext-turn-recovery.json \
  go test ./internal/managedstream \
  -run 'TestTranscriptTurnRecoveryE2E|TestSkippedPromptRecoveryE2E' -count=1
```

The report contains counts and policy outcomes without prompt text. Tests cover
acknowledged requests, new missed hooks, redaction, repeat runs, database reopening,
local retention and explicit opt-outs across later file growth.

## Authorizing a bounded historical repair

Historical prompts with unknown capture policy are excluded by default. Current
workspace capture settings must also allow recovery. An authenticated batch
acknowledgement can authorize recovery through a specific timestamp, using the
workspace's operator-set `metadata.historicalTurnRecoveryBefore` ISO timestamp.
Only clients advertising `X-Kontext-Turn-Recovery: v1` receive the directive.
Removing the metadata key withdraws it. Recorded opt-outs remain excluded.
For an explicitly administered local installation, managed configuration can
alternatively opt in with `recover_historical_turn_prompts: true`.

Transient configuration refresh failures retain the last validated settings.
An explicit authorization rejection clears them; a newly validated stricter
setting takes effect even if persisting the cache fails.
