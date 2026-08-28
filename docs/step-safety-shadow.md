# Local step-safety shadow pilot

The step-safety pilot scores every `PreToolUse` call with the fine-tuned
no-Thought DeBERTa-v3-xsmall encoder before Kontext releases the tool call. It
is shadow-only: the model has no enforcement API, `enforced` is always `false`,
and timeouts, overload, worker failures, missing dependencies, and malformed
outputs all fail open. Existing deterministic and Cedar policy decisions remain
the only authorization decisions.

This is intentionally a pilot, not an enforcement recommendation. ToolSafe-Lab's
frozen evaluation found 90.24% pooled accuracy and 83.62% pooled recall at the
0.5 threshold, but only 14.77% recall on the worst evaluation source. That
source shift is enough to rule out enforcement without new deployment evidence.

## Model storage and local runtime

The trained artifacts are not embedded in the Go binary and Kontext never
reads them from ToolSafe-Lab. Import the four checksum-pinned inference files
into Kontext's existing database-adjacent model cache:

```sh
kontext step-safety install \
  --source /path/to/deberta_v3_xsmall
```

Only `config.json`, `model.safetensors`, `tokenizer.json`, and
`tokenizer_config.json` are copied. The 849 MB training checkpoint is not an
inference artifact and is deliberately excluded. Installation verifies the
exact sizes and SHA-256 digests, writes `PROVENANCE.json` and the upstream MIT
license, and atomically publishes the model at:

```text
<ledger directory>/judge-models/toolsafe/toolsafe-deberta-v3-xsmall-no-thought-v1
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
   tool inputs/results;
3. current tool name and arguments;
4. available tool schemas when the agent adapter supplies the typed hook field.

Kontext never reads agent transcripts or assistant messages for this model, so
agent Thought/reasoning is excluded. Missing hook fields remain empty and their
presence flags are recorded so reviews can separate full-context from
partial-context results.

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
unsafe_probability = sigmoid(1.157280529495871 * margin + 1.1360845295110542)
```

The initial unsafe threshold is `0.5`.

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
metric to average away.

Run the local benchmark after installation:

```sh
kontext step-safety benchmark \
  --python /absolute/path/to/pilot-venv/bin/python \
  --iterations 50 --json
```

On the implementation host (Apple MPS, 20 measured calls after one warm-up),
the initial integration measured p50 48.17 ms, p95 48.64 ms, p99 48.97 ms, with
zero failures. Treat this as a local smoke benchmark, not a fleet SLO.

## License and provenance

The base checkpoint is
[`microsoft/deberta-v3-xsmall`](https://huggingface.co/microsoft/deberta-v3-xsmall/tree/4b419818330868dff6a60ad3e6b1c730f8b8c0c6)
at revision `4b419818330868dff6a60ad3e6b1c730f8b8c0c6`. Its pinned model card declares
MIT, and Microsoft's
[`DeBERTa` license](https://github.com/microsoft/DeBERTa/blob/master/LICENSE)
is MIT. The imported cache includes that license text. Fine-tuning provenance,
calibration, source revision, and artifact hashes are recorded in
`internal/guard/stepsafety/model/PROVENANCE.json` and copied beside the model.
