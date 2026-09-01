# Local step-safety shadow pilot

The step-safety pilot scores every `PreToolUse` call with the fine-tuned
no-Thought DeBERTa-v3-xsmall encoder before Kontext releases the tool call. It
is shadow-only: the model has no enforcement API, `enforced` is always `false`,
and timeouts, overload, worker failures, missing dependencies, and malformed
outputs all fail open. Existing deterministic and Cedar policy decisions remain
the only authorization decisions.

This is intentionally a pilot, not an enforcement recommendation. The
structured-history DeBERTa checkpoint found 91.19% pooled accuracy, 92.66%
precision, 88.45% recall, 90.51% F1, and 0.824 MCC at the 0.5 threshold. Its
worst-source recall improved from the raw-history model's 14.77% to 50.85%, but
that remains far below released TS-Guard's 89.49%. The source shift is still
large enough to rule out enforcement without new deployment evidence.

## Model storage and local runtime

The trained artifacts are not embedded in the Go binary and Kontext never
reads them from ToolSafe-Lab. Import the four checksum-pinned inference files
into Kontext's existing database-adjacent model cache:

```sh
kontext step-safety install \
  --source /path/to/history_serialization/deberta_v3_xsmall
```

Only `config.json`, `model.safetensors`, `tokenizer.json`, and
`tokenizer_config.json` are copied. The 849 MB training checkpoint is not an
inference artifact and is deliberately excluded. Installation verifies the
exact sizes and SHA-256 digests, writes `PROVENANCE.json` and the upstream MIT
license, and atomically publishes the model at:

```text
<ledger directory>/judge-models/toolsafe/toolsafe-deberta-v3-xsmall-structured-history-v2
```

Inference uses one long-lived, local Python worker embedded in the Kontext
binary. The worker loads the tokenizer and model once with
`local_files_only=True`; no request, history, arguments, schema, score, or model
lookup is sent over the network. Provision a dedicated Python 3.10+ environment
with `torch>=2,<3`, `transformers>=5,<6`, and their DeBERTa dependencies. Kontext
does not import ToolSafe-Lab or any of its modules at runtime or build time.

## Enable shadow mode

Shadow mode is off by default. For a foreground Guard pilot:

```sh
export KONTEXT_STEP_SAFETY_SHADOW=1
export KONTEXT_STEP_SAFETY_PYTHON=/absolute/path/to/pilot-venv/bin/python
kontext guard start
```

Managed deployments set the same environment variables in the Kontext
LaunchAgent/daemon configuration and restart the daemon. Optional controls are:

- `KONTEXT_STEP_SAFETY_MODEL_DIR`: override the model-cache path.
- `KONTEXT_STEP_SAFETY_DEVICE`: `auto` (default), `cpu`, `mps`, or `cuda`.
- `KONTEXT_STEP_SAFETY_TIMEOUT`: complete admission plus inference budget;
  default `250ms`, maximum `500ms`.
- `KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT`: singleton load budget; default `30s`.
- `KONTEXT_STEP_SAFETY_MAX_CONCURRENCY`: fixed at `1` for this singleton pilot.

There is deliberately no enforcement flag. Promoting this signal requires a
separate reviewed code change.

Managed `PreToolUse` reserves the existing 250 ms policy window and a separate
bounded shadow-inference allowance (one second total at the hook edge). Thus a model
timeout returns an unavailable shadow result before tool execution without
turning an already-settled enforcing policy allow into a daemon-unavailable
deny. Installed Claude and Codex hooks retain their 20 second outer timeout.

## Exact input contract

The worker receives four fields available at the pre-execution boundary:

1. latest user request observed through `UserPromptSubmit` (or the typed hook
   field when supplied);
2. memory-only interaction history built exclusively from structured prior
   tool inputs/results and serialized in the model's training representation;
3. current tool name and arguments;
4. available tool schemas when the agent adapter supplies the typed hook field.

Kontext never reads agent transcripts or assistant messages for this model, so
agent Thought/reasoning is excluded. Missing hook fields remain empty and their
presence flags are recorded so reviews can separate full-context from
partial-context results.

History is a compact, key-sorted JSON array that is semantically equivalent to
ToolSafe-Lab's frozen structured-history proxy. Each event contains `tool`,
optional `arguments`, and optional string `observation`; missing fields are
omitted and empty history is exactly `[]`. Successful structured responses are
rendered as compact JSON strings. Failed calls use the error text as the
observation string. If an adapter supplies both a response and an error, the
observation string is the compact JSON encoding of both. For example:

```json
[{"arguments":{"file_path":"README.md"},"observation":"{\"content\":\"Kontext\"}","tool":"Read"}]
```

The cross-language goldens were produced with ToolSafe-Lab revision
`9c63e6191598b0ba72947a4394ac8297c41053d1`. Go tests reproduce the canonical
history for empty, multiple, nested, response, error, Unicode, truncation, and
missing-field cases. Python tests reproduce the pinned tokenizer IDs and model
logits with the imported checkpoint. Raw inputs and reasoning are not added to
telemetry by these tests or by serving.

The current action is rendered exactly as the training parser's execution-only
view:

```text
[TOOL_NAME]
<tool name>
[ARGUMENTS]
<sorted compact JSON>
```

Packing is copied from `standalone_encoder.py`: markers are
`[USER_REQUEST]`, `[INTERACTION_HISTORY]`, `[CURRENT_ACTION]`, and
`[TOOL_DESCRIPTIONS]`; the total sequence is padded to 512 tokens; content
budgets are 96/144/128/128. Request keeps its head. History, action, and schemas
keep equal head/tail slices.

Packing remains exact for admitted inputs. Before tokenization, Kontext caps
each rendered field at 64 KiB and all four fields together at 128 KiB. An
oversized call records `input_too_large` and fails open instead of asking the
tokenizer to process an unbounded hook-controlled string. Structured
`PostToolUse` context is captured in memory before its asynchronous durable
ingestion is acknowledged, so the next action deterministically sees the
preceding interaction.

For logits `[safe_logit, unsafe_logit]`, Kontext computes:

```text
margin = unsafe_logit - safe_logit
unsafe_probability = sigmoid(1.427213430140093 * margin + 2.953687013257505)
```

The initial unsafe threshold remains `0.5`. The validation-selected high-recall
threshold is deliberately not served: validation recall did not transfer
reliably to the combined evaluation sources.

## Health, telemetry, and feedback

`GET /healthz` includes `step_safety` with `disabled`, `ready`, or `unavailable`,
the model version, local device, and a redacted error code. An unavailable model
does not make the main daemon unhealthy because this pilot must fail open.
If a worker response times out or loses protocol synchronization, Kontext
retires that process and performs one bounded background reload; calls fail
open while the singleton is restarting.

For each enabled `PreToolUse`, the local `step_safety_verdicts` table stores only:

- unsafe probability, shadow decision, threshold, model version, and latency;
- redacted/capped tool name and tool/session/action correlation IDs;
- stable error category and context-presence booleans;
- `enforced=false`, plus eventual `should_allow` / `should_block` feedback.

It never stores the user request, history, arguments, schemas, logits, or raw
error messages, and the entire step-safety annotation is excluded from signed
decision facts and hosted streams. Read local results at
`GET /api/sessions/{session_id}/step-safety` and submit same-origin feedback to
`POST /api/step-safety/{action_id}/feedback` with:

```json
{"user_feedback":"should_allow"}
```

(`should_block` is the other accepted label.)

## Review before enforcement

Review shadow results by model version and context coverage, overall and per
tool. At minimum, report score distributions, score/label calibration, false
positive and false negative rates from human-reviewed calls, unfamiliar-tool
behavior, p50/p95/p99 latency, timeout/error/overload rates, and drift over
time. Sample both sides of the threshold and low-confidence cases; do not review
only `unsafe` predictions.

Enforcement must remain disabled until an independent review establishes
acceptable worst-tool recall and false-positive cost on real deployment data,
recalibrates or confirms the threshold without using the final test slice,
validates missing-schema behavior, and sets operational budgets for latency and
failures. The known cross-source recall failure is a blocking caveat, not a
metric to average away. The structured-history result is exploratory because
prior evaluation results were already inspected; confirmation requires the
exact deployed representation and a new independent holdout.

For context, at threshold 0.5 the structured DeBERTa result trails released
TS-Guard by 2.17 points accuracy, 5.37 points recall, 2.56 points F1, 0.043 MCC,
and 38.64 points worst-source recall. Its precision is 0.33 points higher. These
are offline released-data comparisons, not a production equivalence claim.

Run the local benchmark after installation:

```sh
kontext step-safety benchmark \
  --python /absolute/path/to/pilot-venv/bin/python \
  --iterations 50 --json
```

On the implementation host (Apple MPS, 50 measured calls after one warm-up),
the structured-history v2 integration measured p50 40.19 ms, p95 41.06 ms, and
p99 41.41 ms, with zero failures. Treat this as a local smoke benchmark, not a
fleet SLO.

## License and provenance

The fine-tuned checkpoint and history serializer come from ToolSafe-Lab commit
`9c63e6191598b0ba72947a4394ac8297c41053d1`, artifact path
`artifacts/models/history_serialization/deberta_v3_xsmall`, with results in
`results/history_serialization_ablation.json` and findings in
`docs/HISTORY_SERIALIZATION_ABLATION_FINDINGS.md`. The base checkpoint is
[`microsoft/deberta-v3-xsmall`](https://huggingface.co/microsoft/deberta-v3-xsmall/tree/4b419818330868dff6a60ad3e6b1c730f8b8c0c6)
at revision `4b419818330868dff6a60ad3e6b1c730f8b8c0c6`. Its pinned model card declares
MIT, and Microsoft's
[`DeBERTa` license](https://github.com/microsoft/DeBERTa/blob/master/LICENSE)
is MIT. The imported cache includes that license text. Fine-tuning provenance,
calibration, source revision, and artifact hashes are recorded in
`internal/guard/stepsafety/model/PROVENANCE.json` and copied beside the model.
