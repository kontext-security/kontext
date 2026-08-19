# Kontext Guard

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
  -> risk annotation (SVM + guardrail LLM; advisory, never consulted)
  -> local SQLite
  -> local daemon API
       \
  -> risk annotation (SVM + guardrail LLM; advisory, never consulted)
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

The standalone `kontext guard start` daemon can use a local OpenAI-compatible judge, such as `llama-server`. The managed-observe daemon does not download or start a model by default; configure it explicitly as described in [Guardrail LLM](#guardrail-llm).

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

The annotation is computed **in the decision path** — after the policy layer has produced its final answer, before the tool executes — so it reaches the hosted ledger attached to the decision rather than trailing it. It is computed in exactly one place, `guardHookRuntime.annotate`, sitting between the finished decision and the write. That placement is deliberate on two counts: it is the only point that sees Cedar's actual answer, and it is the only point every path passes through, so observe, enforce, and managed runtimes all annotate rather than only the ones whose decision happens to come from the local chain.

It is nonetheless **strictly advisory**, by construction rather than convention: `annotate` receives an already-settled decision and may write nothing but its `Classifier` field, so there is no code path from a verdict to an allow/deny outcome. `TestAnnotationCannotChangeDecision` runs identical commands through a server with the classifier on and one with it off and requires byte-identical decision, reason, and reason code.

Both models run for **every** outcome, denies included. A deny is the case where knowing whether the models agreed with the policy is worth the most, and since the decision is already final there is nothing for the extra evidence to affect.

Whether to gate on it later is a separate decision, and keeping the two apart means it can be made from real verdicts and labels instead of guessed at now. Deterministic rules own blocking today, as they did before.

The model is **char n-gram + LinearSVM** — the benchmark winner, ported natively to Go and embedded in the binary, so there is no Python and no model download at runtime. `scripts/riskclassifier/export_portable.py` flattens `authz-bench/serve/model/classifier.joblib` into `internal/guard/riskclassifier/model/svm.json.gz` and regenerates the golden fixtures that lock the port to the reference predictor. Run it after any upstream model change:

```bash
../authz-bench/.venv/bin/python scripts/riskclassifier/export_portable.py --authz ../authz-bench
```

Binary-risky shell commands also receive a native, multi-label char-SVM
risk-type annotation. It is separate append-only derived data rather than part
of the signed decision fact, so historical calls can be enriched without
rewriting evidence. See [Observe-only risk-type classification](risk-type-classifier.md)
for the exact model contract, retrospective command, transfer caveat, and the
required companion hosted-schema deployment.

### Guardrail LLM

The second model is the stock, public **Qwen3-0.6B** served on `llama-server` with the prompt authz-bench's sweep selected (`eval/optimize_prompt.py`, variant "V2 precision + balanced few-shot"). Nothing is fine-tuned and nothing custom ships: the GGUF is pulled from Hugging Face like any other judge model, and the prompt is exported verbatim into `internal/guard/riskclassifier/prompts/guardrail-v2.json` by `scripts/riskclassifier/export_prompt.py` — a reworded bullet is a different classifier, so it is copied mechanically rather than by hand.

**This is the only LLM.** It supersedes the JSON judge: whenever the classifier is enabled, the judge is not constructed. Since the classifier only annotates, that leaves **no LLM on the decision path at all** — a gated tool call is decided by deterministic rules and Cedar, and waits for nothing.

That is a deliberate, accepted trade-off rather than an oversight, and it narrows enforce-mode coverage: a command that deterministic and provider policy allow, which the old JSON judge would have denied, now runs. It was accepted because the judge cost ~200 ms on every gated call against ~22 ms without it, and because promoting the classifier to a gate is not viable at its measured 0.585 precision — two in five of its RISKY calls are false alarms, so blocking on it would cause more harm than the gap it closes. Revisit when a model with enforce-grade precision exists; the verdicts and `user_feedback` being collected now are what will show whether it does.

The two models are complementary rather than redundant, which is why both are logged:

| | precision | recall | curated catastrophes caught |
|---|---|---|---|
| SVM (threshold 0.40) | 0.987 | 0.834 | 4/16 |
| Guardrail (Qwen3-0.6B, V2 prompt) | 0.585 | 0.967 | **16/16** |

The SVM is precise but blind to `rm -rf /`, `dd if=/dev/zero of=/dev/disk0`, and `mkfs` — its benign corpus is full of routine `rm -rf`. The guardrail catches every one of those and over-flags ordinary work instead. Recording both keeps that disagreement visible, which is the useful signal.

`KONTEXT_RISK_CLASSIFIER_MODE` is `on` (default, both models) or `off` (SVM only, no sidecar needed).

Whether the LLM runs depends on whether a local model is resolved, and that is opt-in everywhere. Nothing downloads a model or starts a `llama-server` child unless an operator asked for it:

| path | guardrail LLM |
|---|---|
| `managed-observe` daemon — what a plain `claude` session hits | `KONTEXT_JUDGE_URL` + `KONTEXT_JUDGE_MODEL` for an endpoint you already run, or `KONTEXT_JUDGE_MANAGED=1` to have the daemon manage one |
| `kontext guard start` — local-only, no org | the same env, or `--judge-managed` |

With neither set, both paths record the SVM verdict and `llm_error: "guardrail not configured"`.

On a self-serve Mac, `kontext setup --with-local-llm` is the supported way to opt in. It runs in three steps, and the order is load-bearing:

1. **Resolve `llama-server` before any privileged write.** Wanting the model without `llama.cpp` installed then costs nothing to recover from. The *absolute* path is what is kept: this lookup runs in a login shell where Homebrew is on PATH, while launchd hands the daemon a minimal PATH that excludes `/opt/homebrew/bin`, so a bare name would not resolve on the other side.
2. **Install the agent without the model, then pre-fetch the weights.** Enabling the model first would bootstrap a model-managing daemon that starts downloading at the same moment setup does — two ~680 MB transfers into one cache path. This way the agent comes up and starts observing immediately, and the weights land while nothing is waiting on them.
3. **Re-render the agent with `KONTEXT_JUDGE_MANAGED=1` and the resolved binary path**, which restarts it with the model attached. The opt-in lives in the agent's environment rather than a config file, because launchd already owns that environment and the daemon reads exactly those variables.

The cache is derived from the **daemon's** database path, not Guard's — they are different directories, and deriving it from the wrong one fills a cache nothing reads. A failed pre-fetch warns and continues; the weights are an optimization of something that already degrades cleanly. Without the flag, the install is byte-identical to one made before the option existed.

**Today that means Homebrew installs only.** The formula depends on `llama.cpp`, so `llama-server` is on PATH after `brew install`; nothing else provisions it, and the CLI deliberately does not ship or download it — `exec.LookPath` finds it or the guardrail degrades to SVM-only. An MDM-deployed endpoint therefore collects SVM verdicts and nothing more, which is the accepted starting point rather than an oversight: enabling the LLM fleet-wide would mean shipping a signed native binary, ~1.1 GB of resident memory per endpoint, and a `llama-server` child process that endpoint security tooling has every reason to flag.

Read collected data with that in mind. The managed daemon is the path that reaches the hosted ledger, so an endpoint without a model produces uploads whose `classifier.llm` is null — and the SVM is the weaker half of the pair.

**The model name must contain `qwen3`.** That is what makes the client send `/no_think`; without it Qwen3 reasons instead of answering and returns nothing inside the token budget.

The guardrail LLM can also be turned off **remotely**: `guardrailLlmEnabled` rides the endpoint-configuration sync, alongside `payloadCaptureMode`.

The flag is part of the **v2** endpoint-configuration contract, and being in the identity preimage is what makes it work: the identity is the ETag, so changing only this flag produces a different one and a conditional refresh actually observes it. The CLI requests `response_version=2`; the server serves v1 and v2 side by side, so released binaries keep getting the v1 shape and the v1 identity hashes untouched.

Both sides hash `["kontext:endpoint-config:v2", 2, payloadCaptureMode, guardrailLlmEnabled]`, and `Response.Validate` rejects any response whose identity does not match the locally recomputed one — so the preimage's field order and encoding are load-bearing. `testdata/portable/v2/identity-v2.json` is copied verbatim from the server's vectors and byte-pinned, which is what proves the two implementations agree rather than merely looking similar.

Under v2 the field is **required**, so the case of a response that simply omits it is rejected rather than resolved as enabled. The remembered directive still matters for one path: a cache written under an older response version cannot be revalidated, so it is discarded, and the remembered value is what carries a deliberate disable across that upgrade.

Its handling is deliberately the **inverse** of payload capture's, and there are two failure modes to avoid at once. Capture reverts to its privacy-safe mode whenever the configuration is unconfirmed, because recording content on an unverified directive is the harmful outcome. Here:

- Defaulting to off would let a transient fetch failure silently disable the classifier — a degradation nobody would notice, since the SVM keeps producing verdicts.
- Ignoring a persisted off would re-enable an LLM the org explicitly disabled, every time the daemon restarted before reconfirming — a kill switch failing in exactly the degraded state it exists for.

Both are satisfied by resolving the **last explicit** directive rather than whatever the current response carries. The cache remembers an explicit value across refreshes and restarts, stored beside the response rather than inside its config, since the response's identity is verified against its config on load. So:

- An explicit `false` survives restarts and unconfirmed fetches.
- A later response that simply **omits** the field does not clear it — that is the rollback case, where a server build without the field would otherwise switch a disabled guardrail back on with nobody told.
- Absence means "never set", not "not mentioned this time". **Clearing a disable therefore takes an explicit `true`,** not silence.

Resolve it through `riskclassifier.ResolveLLMEnabled(snapshot.GuardrailLLMDirective)` rather than reading `Config` or `Configured` directly.

Setting `KONTEXT_RISK_CLASSIFIER_MODE` explicitly pins the local value and makes it immune to the remote directive, so a developer debugging their own machine is not flipped by a config refresh. The embedded SVM is never gated.

Guardrail calls are bounded three ways, because the classifier now sits on the hook path: a hard 400 ms per-call budget, a circuit breaker (3 consecutive failures opens it; one probe admitted after a 30 s cooldown; a failure while half-open reopens immediately), and a readiness probe against `/v1/models` before the first call and after every reopen. The probe is the important one — a `llama-server` loading its model takes seconds, so without it every command during startup would pay the full budget and fail anyway.

Measured end to end (Claude Code hook → socket → policy → SQLite) against a local Qwen3-0.6B-Q8:

Measured end to end per gated bash command (hook process → socket → RuntimeCore → policy → classifier → SQLite), 40 samples after warm-up, local Qwen3-0.6B-Q8:

| configuration | p50 | p95 |
|---|---|---|
| no LLM at all | 21.8 ms | 23.2 ms |
| **classifier on, warm LLM** | **64.2 ms** | **75.6 ms** |
| classifier on, SVM only (LLM shed) | 21.7 ms | 23.7 ms |
| the JSON judge this replaces | ~200 ms | ~247 ms |

**The LLM adds p50 42 ms / p95 52 ms** per command. Even in-path this is well under half what the JSON judge cost, because a one-word answer generates far fewer tokens than a JSON object. The cost now applies to denied commands too, which previously skipped the LLM; that was measured as the row above, and it is the price of having the same evidence for every outcome.

### What is deliberately lost

Two cases drop verdicts on purpose, and both are worth stating plainly rather than discovering later.

**A command larger than the store cap** keeps only its first 8 KiB, redacted, and `command_truncated` says so. The verdict is unaffected — the models score the whole command — and the stored hash covers exactly the retained prefix, so two scripts sharing that prefix share a hash. That is honest rather than lossy: the hash describes what the row holds.

**Verdicts still queued when the daemon shuts down** are dropped once the drain budget expires. Nothing audit-relevant goes with them: the tool call and its decision are already persisted and receipted on the decision path, and the annotation is advisory training data. The alternative — writing them after cancellation — would mean either an unbounded shutdown or a second budget layered on the one that just expired, both of which add moving parts to the exact place a teardown race was fixed. Reaching this case at all means the store was already failing to keep up, which is the more useful signal.

Unhappy paths cost nothing rather than the full budget:

- **Sidecar down or loading** — the readiness probe fails fast and the breaker opens; six commands against a dead endpoint complete in well under a second, versus six 400 ms timeouts without it.
- **Remotely disabled** — the kill switch is consulted per call, so turning the LLM off costs nothing and needs no restart; the SVM keeps recording at microseconds.
- **Verbatim repeats** — served from an LRU, no inference.

If the annotation is ever promoted to a gate, the number to weigh is not latency but precision: 0.585 means roughly two in five RISKY calls are false alarms.

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

- `svm_verdict` / `svm_score` / `svm_threshold` / `svm_model_version`, `llm_verdict` / `llm_model` / `llm_prompt_id` / `llm_duration_ms` / `llm_cached` / `llm_error`, and `enforced` (always `0`)
- `command_redacted` — credential-redacted, capped at 8 KB. Classification runs on the raw command in memory; only the redacted form is persisted, because this dataset is exported back to authz-bench.
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

### What reaches the hosted ledger

The annotation rides **inside the Decision Fact**, as a `classifier` section on the same `request.decided` fact, so verdicts arrive with the decision instead of trailing it:

```json
"classifier": {
  "svm": {"verdict": "not_risky", "score": 0.0001, "threshold": 0.4, "model_version": "0.1.0"},
  "llm": {"verdict": "risky", "model": "Qwen/Qwen3-0.6B-GGUF", "duration_ms": 44, "cached": false},
  "llm_error": null,
  "command": "npm install --save-dev typescript",
  "command_truncated": false
}
```

Those field names are a fixed contract with hosted ingest — do not rename them.

There is exactly one copy of the annotation on the row, and it is the one in the fact. That is deliberate: a parallel column plus a hash of it would let a reader see one verdict in the fact and a different one beside it, and the receipt already signs the complete fact, so a nested section is tamper-evident without a hash of its own. The fact's Go type carries only the contract fields, so the local-only halves of the annotation cannot reach the wire by construction rather than by remembering to strip them. A call that was not scored carries `"classifier": null`.

Because the fact is a mirror of the server-side shared contract with a byte-pinned golden corpus (`FixtureDigest`, asserted on both sides), this section cannot change from one repo alone. Adding it required the matching change in the hosted mirror; the two land together or CI fails on both.

The redacted command, `agent_task`, `llm_prompt_id`, `user_feedback`, and `feedback_at` stay **local only**. `cached: true` means the verdict was reused from the local LRU for a byte-identical repeat — it says nothing about the model.
