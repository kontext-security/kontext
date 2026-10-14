# Kontext Guard

The default-on Merlin advisory beta is documented in
[Local step-safety assessment](step-safety-shadow.md). It runs locally at
`PreToolUse` through an embedded native Go model in background recording,
excludes file tools and oversized actions, records redacted shadow evidence,
and cannot enforce. Set `KONTEXT_STEP_SAFETY_SHADOW=0` in the daemon environment
to opt out; see the [current candidate record](merlin-matched-replay-trial.md)
for evidence, limitations and rollout guidance.

Guard is the local safety runtime inside `kontext`. It watches tool calls locally, redacts captured data, and stores decisions in local SQLite.

There are two supported ways to use it:

- `kontext guard ...` is the standalone, local-only path. It has no login, does not call the hosted Kontext API, and does not upload traces or ledger records.
- `kontext setup` is the managed path. It configures the managed-observe daemon, which still makes decisions locally but authenticates with the installation token and streams authorization-ledger batches to the hosted Kontext backend. Those records can then be reviewed in the hosted dashboard.

## User path

```bash
brew install kontext-security/tap/kontext
kontext setup
```

Until the Guard PR is merged and released, test from source:

```bash
go run ./cmd/kontext setup
```

## Runtime boundary

Both paths are local-first for the decision path: the runtime, policy evaluation, risk annotation, and SQLite ledger are local. The network boundary differs:

- **Standalone Guard** (`kontext guard ...`): no login, hosted API, trace upload, or ledger export; its daemon and JSON API are local.
- **Managed setup** (`kontext setup`): no user login, but the managed-observe daemon uses its install token to fetch managed configuration and export authorization-ledger batches to the hosted backend. Its hook transport is a local Unix socket, and observe mode is the default unless the managed deployment selects another posture.

## Flow

```text
Claude Code
  -> kontext hook --agent claude --mode observe
  -> local runtime Unix socket
  -> RuntimeCore
  -> deterministic policy
  -> risk annotation (SVM; advisory, never consulted)
  -> local SQLite
  -> local daemon API
       \
  -> risk annotation (SVM; advisory, never consulted)
```

## Risk layers

Guard uses two layers:

1. Deterministic policy for obvious risk, such as credential access, direct provider API calls with credential material, production mutations, and destructive persistent-resource operations.
2. Probabilistic risk for cases deterministic policy allows.

Alongside those, the observe-mode risk classifier logs a verdict per bash command without participating in the decision. See [Risk classifier](#risk-classifier-observe-mode).

## Local authorization ledger

Guard persists new local decisions to an authorization ledger in SQLite:

- `agent_sessions`
- `authorization_actions`
- `authorization_receipts`

`authorization_actions` stores the latest lifecycle state for a tool action, while `authorization_receipts` appends decision and outcome evidence.

Receipt signing is intentionally small for the local implementation. Set `KONTEXT_GUARD_LEDGER_SIGNING=1` to enable local Ed25519 receipt signatures. The generated key is stored beside the SQLite database unless `KONTEXT_GUARD_LEDGER_SIGNING_KEY` points to a specific key path.

The SQLite store also exposes raw ledger export and verification helpers for follow-on managed streaming work. `LedgerBatch` returns sessions, selected actions plus any bridge actions needed by a contiguous receipt range, receipts, and a receipt-chain anchor for incremental batches. `VerifyReceipts` checks receipt hashes, previous-hash links, and local Ed25519 signatures when signing is enabled.

Provider-reported hook metadata is preserved under `authorization_actions.context_json.hook_metadata` and in new receipt payloads under `action.hook_metadata`. Optional fields are `duration_ms` (provider-reported execution time, not observer elapsed time), `is_interrupt` (whether the reported failure was due to user interruption), `permission_mode` (the agent's permission setting, separate from Kontext's observe/enforce mode), and `error_redacted`. Missing fields remain absent; explicit zero durations and `false` interruption flags are retained. Claude's adapter accepts all four; Codex currently supplies the permission-mode field through its adapter, without synthesizing the other fields from tool output.

Error text is redacted before truncation to 4 KiB, and permission-mode text is redacted and capped at 256 bytes. Text exceeding the 1 MiB redaction-input limit is omitted with a marker. The provider error also populates the existing `error_redacted` action column and outcome receipt field; a policy explanation is not substituted when no tool error was supplied. Metadata recording adds no model calls, changes neither allow/deny decisions nor the existing hook-name-based outcome labels, and does not rewrite historical receipts or change the Decision Fact v1 schema.

## Risk classifier (observe mode)

Guard attaches a **risk annotation** to every intercepted bash command, using the classifier from the sibling `authz-bench` serving contract (`authz-bench/serve/SERVING.md`).

The annotation is computed after the policy layer has produced its final answer, as part of decision recording, so it reaches the hosted ledger attached to the decision. The managed daemon defers recording until after the hook response. It is computed in exactly one place, `guardHookRuntime.annotate`, sitting between the finished decision and the write. That placement is deliberate on two counts: it is the only point that sees Cedar's actual answer, and it is the only point every path passes through, so observe, enforce, and managed runtimes all annotate rather than only the ones whose decision happens to come from the local chain.

It is nonetheless **strictly advisory**, by construction rather than convention: `annotate` receives an already-settled decision and may write nothing but its `Classifier` field, so there is no code path from a verdict to an allow/deny outcome. `TestAnnotationCannotChangeDecision` runs identical commands through a server with the classifier on and one with it off and requires byte-identical decision, reason, and reason code.

The binary SVM runs for **every** outcome, denies included. A deny is the case where knowing whether the models agreed with the policy is worth the most, and since the decision is already final there is nothing for the extra evidence to affect. The shadow risk-type SVM runs only for binary-risky shell calls.

Whether to gate on it later is a separate decision, and keeping the two apart means it can be made from real verdicts and labels instead of guessed at now. Deterministic rules own blocking today, as they did before.

The model is **char n-gram + LinearSVM** — the benchmark winner, ported natively to Go and embedded in the binary, so there is no Python and no model download at runtime. `scripts/riskclassifier/export_portable.py` flattens `authz-bench/serve/model/classifier.joblib` into `internal/guard/riskclassifier/model/svm.json.gz` and regenerates the golden fixtures that lock the port to the reference predictor. Run it after any upstream model change:

```bash
../authz-bench/.venv/bin/python scripts/riskclassifier/export_portable.py --authz ../authz-bench
```

Binary-risky shell commands also receive a native, multi-label char-SVM
risk-type annotation. It is separate append-only derived data rather than part
of the signed decision fact, so historical calls can be enriched without
rewriting evidence. The hosted Risk page keeps this as shadow data and uses its
automatic LLM assessment for the visible category and explanation. See
[Observe-only risk-type classification](risk-type-classifier.md) for the exact
model contract, retrospective command, transfer caveat, and hosted schema.

### What is deliberately lost

**A command larger than the store cap** keeps only its first 8 KiB, redacted, and `command_truncated` says so. The verdict is unaffected — the models score the whole command — and the stored hash covers exactly the retained prefix, so two scripts sharing that prefix share a hash. That is honest rather than lossy: the hash describes what the row holds.

`normalize_command` (IP → `1.1.1.1`, URL → `example.com`, long base64 → `BASE64`) is applied before scoring, identically to training. Three tests fail on any drift, and none of them should be "fixed" by loosening an assertion: `TestNormalizeCommandGoldenParity` and `TestSVMGoldenParity` pin this port to the Python reference, and `TestSVMUpstreamGoldenParity` cross-checks it against authz-bench's independent Go port via that repo's shipped vectors (`testdata/upstream-golden.json`, refreshed by copying `authz-bench/serve/model/golden.json`). Two independent ports agreeing is what catches a normalizer divergence — an upstream base64 skew once passed its own parity check because its vectors did not cover the boundary.

### Serving threshold

The SVM verdict uses a threshold on the signed margin carried by the artifact, so retuning it is a re-export rather than a code change. The model card ships `0.0` (LinearSVC's natural boundary, explicitly "tunable"); kontext serves `0.40`, chosen by `scripts/riskclassifier/pick_threshold.py`.

That script exists because the shipped model is fit on all clean labeled data, leaving no held-out split to tune on — it runs 5-fold `cross_val_predict(method="decision_function")` with the identical pipeline so every score comes from a model that did not see that command, then sweeps thresholds over those out-of-fold scores. Measured on 20,966 commands (966 risky):

| threshold | precision | recall | false alarms | misses |
|---|---|---|---|---|
| `0.00` (model card) | 0.934 | 0.906 | 62 | 91 |
| **`0.40` (served)** | **0.987** | **0.834** | **11** | **160** |

The operating point is precision-weighted (F0.5 argmax) because in observe mode the threshold does not gate data capture — every command is logged with its raw score either way. It only decides which rows the feedback UI presents as "would block", and a noisy would-block set burns the reviewer attention the ground-truth labels depend on. Misses stay recoverable: any past command can be flagged `should_block` from history, and deterministic rules already own known-bad. Each verdict records the threshold that decided it, so stored scores make any past verdict re-derivable under a new threshold.

Verdicts land in the `risk_classifier_verdicts` table, one row per decided action:

- `svm_verdict` / `svm_score` / `svm_threshold` / `svm_model_version`, and `enforced` (always `0`)
- `command_redacted` — credential-redacted, capped at 8 KB. Classification runs on the raw command in memory; only the redacted form is persisted, because this dataset is exported back to authz-bench.
- `user_feedback` — `should_allow` or `should_block`. This is the ground-truth label the whole pipeline exists to collect.

Two loopback endpoints expose it. The embedded dashboard that used to call them is gone, so these are now for whatever labels verdicts locally — a script, a local tool, or a future command. Writes are same-origin only, so nothing reachable from a browsed page can forge training labels:

```text
GET  /api/sessions/{session_id}/verdicts
POST /api/verdicts/{action_id}/feedback   {"user_feedback": "should_allow" | "should_block"}
```

The managed daemon defers classification and decision recording until after the hook response. The recorder drains pending writes before the store closes. Classification cannot change the settled decision.

One verdict row per decided action, enforced by a `unique(action_id)` constraint: the feedback endpoint updates by `action_id`, so a duplicate row would let one label land on two records and corrupt the ground truth silently.

## Public/private boundary

Public in `kontext-cli`:

- `kontext guard ...` commands
- Claude Code local hook adapter
- local daemon, SQLite store, JSON API
- Cedar policy and advisory SVM classification

Private in Lab:

- dataset ingestion
- OpenTelemetry/Claude trace import
- weak labeling
- unpublished datasets and experiments

## Work tracking

Linear is the front door for planning. GitHub issues and Linear issues should sync.

- Linear project: `Kontext CLI`
- GitHub label: `area:kontext`
- Private pipeline project: `Lab / Model Pipeline`

Done means:

- issue has acceptance criteria
- PR links the issue
- tests pass
- this file or the Linear Excalidraw link is updated if architecture changed

### What reaches the hosted ledger

The annotation rides **inside the Decision Fact**, as a `classifier` section on the same `request.decided` fact, so verdicts arrive with the decision instead of trailing it:

```json
"classifier": {
  "svm": {"verdict": "not_risky", "score": 0.0001, "threshold": 0.4, "model_version": "0.1.0"},
  "llm": null,
  "llm_error": null,
  "command": "npm install --save-dev typescript",
  "command_truncated": false
}
```

Those field names are a fixed contract with hosted ingest — do not rename them.

There is exactly one copy of the annotation on the row, and it is the one in the fact. That is deliberate: a parallel column plus a hash of it would let a reader see one verdict in the fact and a different one beside it, and the receipt already signs the complete fact, so a nested section is tamper-evident without a hash of its own. The fact's Go type carries only the contract fields, so the local-only halves of the annotation cannot reach the wire by construction rather than by remembering to strip them. A call that was not scored carries `"classifier": null`.

Because the fact is a mirror of the server-side shared contract with a byte-pinned golden corpus (`FixtureDigest`, asserted on both sides), this section cannot change from one repo alone. Adding it required the matching change in the hosted mirror; the two land together or CI fails on both.

The redacted command is uploaded. `agent_task`, `user_feedback`, and `feedback_at` stay local only. The non-optional `llm` and `llm_error` fields remain null to preserve the signed contract; local verdict records omit them.
