# Kontext Guard

Guard is the local safety mode inside `kontext`.

It lets a developer run Claude Code normally while Kontext watches tool calls locally, redacts captured data, and stores events in local SQLite with `would allow` and `would deny` decisions. Sessions are reviewed in the hosted Kontext dashboard; the daemon exposes a local JSON API only.

## User path

```bash
brew install kontext-security/tap/kontext
kontext start
```

Until the Guard PR is merged and released, test from source:

```bash
go run ./cmd/kontext start
```

## Runtime boundary

Guard mode is local-first by default:

- no login
- no hosted Kontext API
- no trace upload by default
- local daemon on `127.0.0.1:4765`
- local SQLite database
- local JSON API (`/api/...`) for status and tooling
- observe mode by default

Hosted managed mode remains separate:

```bash
kontext start --managed --agent claude
```

Hosted mode owns login, provider connection, short-lived scoped credentials, hosted traces, and team governance.

## Flow

```text
Claude Code
  -> kontext hook --agent claude --mode observe
  -> local runtime Unix socket
  -> RuntimeCore
  -> deterministic policy
  -> probabilistic risk when deterministic policy allows
  -> local SQLite
  -> local daemon API
       \
        -> risk annotation (SVM + guardrail LLM; recorded, never consulted)
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

## Local judge

The user-facing `kontext start` path manages a local judge by default. For daemon-only diagnostics, Guard can call a localhost OpenAI-compatible judge, such as `llama-server`, after deterministic rules allow a blocking tool call:

```bash
kontext guard start \
  --judge-url http://127.0.0.1:8080 \
  --judge-model qwen3-0.6b-q4
```

Guard can also manage `llama-server` itself. This downloads the selected GGUF into the Kontext model cache when it is missing, starts `llama-server` on loopback, waits for `/v1/models`, and shuts the child process down with Guard:

```bash
kontext guard start --judge-managed
```

Use `--judge-port` or a loopback `--judge-url` such as `http://127.0.0.1:18081` to choose a different managed `llama-server` port.

The managed default is `Qwen/Qwen3-0.6B-GGUF` with `Qwen3-0.6B-Q8_0.gguf`. Override it with either a local model path:

```bash
kontext guard start \
  --judge-managed \
  --judge-model-path ~/.config/kontext/judge-models/qwen.gguf
```

Or a specific Hugging Face GGUF:

```bash
kontext guard start \
  --judge-managed \
  --judge-hf-repo Qwen/Qwen3-0.6B-GGUF \
  --judge-hf-file Qwen3-0.6B-Q8_0.gguf
```

Use `--judge-hf-revision` when the GGUF is on a Hugging Face branch, tag, commit, or ref other than `main`.

The judge receives a small redacted JSON input with tool metadata, normalized risk fields, deterministic policy context, and no full conversation history. It must return structured JSON with `decision` set to `allow` or `deny`. `ask` is not part of the judge contract.

Judge failures are fail-open for launch. If the local runtime is unavailable, times out, or returns invalid JSON, Guard records `judge_unavailable_allow` plus high-level metadata and allows the tool call. Judge URLs must point at localhost.

Evaluate a local judge against the launch fixtures:

```bash
kontext guard judge eval \
  --judge-url http://127.0.0.1:8080 \
  --judge-model Qwen/Qwen3-0.6B-GGUF \
  --fixtures internal/guard/judge/testdata/launch-v0.jsonl
```

The eval command is for local model and prompt iteration. It skips fixtures
where deterministic policy is expected to deny before the judge is called.

## Risk classifier (observe mode)

Guard attaches a **risk annotation** to every intercepted bash command, using the classifier from the sibling `authz-bench` serving contract (`authz-bench/serve/SERVING.md`).

The annotation is deliberately independent of the block logic. It is computed after the decision is already made, stored alongside the action, and **nothing in Guard reads it back** — it does not participate in observe or enforce mode, and there is no configuration that lets it deny. Whether to gate tool calls on it is a separate, later decision, and keeping the two apart means that decision can be made from real data rather than guessed at now. Deterministic rules own blocking today, as they did before.

The model is **char n-gram + LinearSVM** — the benchmark winner, ported natively to Go and embedded in the binary, so there is no Python and no model download at runtime. `scripts/riskclassifier/export_portable.py` flattens `authz-bench/serve/model/classifier.joblib` into `internal/guard/riskclassifier/model/svm.json.gz` and regenerates the golden fixtures that lock the port to the reference predictor. Run it after any upstream model change:

```bash
../authz-bench/.venv/bin/python scripts/riskclassifier/export_portable.py --authz ../authz-bench
```

### Guardrail LLM

The second model is the stock, public **Qwen3-0.6B** served on `llama-server` with the prompt authz-bench's sweep selected (`eval/optimize_prompt.py`, variant "V2 precision + balanced few-shot"). Nothing is fine-tuned and nothing custom ships: the GGUF is pulled from Hugging Face like any other judge model, and the prompt is exported verbatim into `internal/guard/riskclassifier/prompts/guardrail-v2.json` by `scripts/riskclassifier/export_prompt.py` — a reworded bullet is a different classifier, so it is copied mechanically rather than by hand.

**This is the only LLM.** It supersedes the JSON judge: whenever the classifier is enabled, the judge is not constructed. Since the classifier only annotates, that leaves **no LLM on the decision path at all** — a gated tool call is decided by deterministic rules and waits for nothing.

The two models are complementary rather than redundant, which is why both are logged:

| | precision | recall | curated catastrophes caught |
|---|---|---|---|
| SVM (threshold 0.40) | 0.987 | 0.834 | 4/16 |
| Guardrail (Qwen3-0.6B, V2 prompt) | 0.585 | 0.967 | **16/16** |

The SVM is precise but blind to `rm -rf /`, `dd if=/dev/zero of=/dev/disk0`, and `mkfs` — its benign corpus is full of routine `rm -rf`. The guardrail catches every one of those and over-flags ordinary work instead. Recording both keeps that disagreement visible, which is the useful signal.

`KONTEXT_RISK_CLASSIFIER_MODE` is `on` (default, both models) or `off` (SVM only, no sidecar needed).

Measured end to end (Claude Code hook → socket → policy → SQLite) against a local Qwen3-0.6B-Q8:

| configuration | mean hook latency |
|---|---|
| no LLM at all | 24 ms |
| **classifier on** (what ships) | **28 ms** |
| the JSON judge this replaces | 298 ms |

Inference is 44 ms warm p50 (~90 ms on the first call while the fixed few-shot prefix is evaluated; `llama-server` keeps that prefix cached afterwards, so a long command costs the same as a short one) — but the agent never waits for it, which is why the hook stays within 4 ms of the no-LLM floor. Removing the judge from the decision path is where the 270 ms goes.

If the annotation is ever promoted to a gate, the number to weigh first is precision: 0.585 means roughly two in five RISKY calls are false alarms, and the measured cost of consulting it synchronously was 66 ms per gated command.

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

- `svm_verdict` / `svm_score` / `svm_threshold` / `svm_model_version`, and `enforced` (always `0` in v1)
- `command_redacted` — credential-redacted, capped at 8 KB. Classification runs on the raw command in memory; only the redacted form is persisted, because this dataset is exported back to authz-bench.
- `agent_task` — the session's latest user prompt, captured from `UserPromptSubmit`. Only the `kontext start` wrapper path registers that hook, so daemon-only `kontext guard start` sessions leave it empty.
- `user_feedback` — `should_allow` or `should_block`. This is the ground-truth label the whole pipeline exists to collect.

Two loopback endpoints expose it. The embedded dashboard that used to call them is gone, so these are now for whatever labels verdicts locally — a script, a local tool, or a future command. Writes are same-origin only, so nothing reachable from a browsed page can forge training labels:

```text
GET  /api/sessions/{session_id}/verdicts
POST /api/verdicts/{action_id}/feedback   {"user_feedback": "should_allow" | "should_block"}
```

Classification runs off the hook path: one worker behind a 256-record queue, draining on shutdown. Scoring itself takes microseconds — the store write is what would otherwise make a tool call wait. If the queue ever fills, the record is dropped rather than blocking; only the verdict is lost, since the tool call itself is already persisted on the decision path. Nothing here can delay or change a tool call.

One verdict row per decided action, enforced by a `unique(action_id)` constraint: the feedback endpoint updates by `action_id`, so a duplicate row would let one label land on two records and corrupt the ground truth silently.

## Public/private boundary

Public in `kontext-cli`:

- `kontext guard ...` commands
- Claude Code local hook adapter
- local daemon, SQLite store, JSON API
- deterministic policy and local LLM judge wiring

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
