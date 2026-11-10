# Recovering missing turns

The stream worker can observe usage in a transcript even when its prompt hook
never reached the daemon. With validated settings that allow classification
and do not omit payloads, it recovers the missing turn from the real user prompt.

Recovery is automatic for new missed hooks. The first eligible reconcile after
an upgrade also schedules unchanged and historical registered transcripts once,
bounded to 100 changed sources per pass. Missing or unreadable files retain
normal retry/retirement behavior. Unrecoverable usage remains accounted for.

Provider ownership and prompt-boundary rules exclude subagents, copied history,
harness envelopes and compaction summaries. A five-second grace period lets the
hook-recording queue finish before using a transcript fallback.

The cached incremental reader retains metadata only. Recovery uses a separate
short-lived reader after checking capture policy, and applies the same redaction,
hashing and 64,000-byte excerpt bound as a prompt hook. Raw text is not retained
in the metadata cursor or usage payload. Recorded explicit opt-outs remain
excluded after settings change and the transcript grows. Validated last-known
settings survive refresh failures and offline restarts; invalid caches stay off.

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
