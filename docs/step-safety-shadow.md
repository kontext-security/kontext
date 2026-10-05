# Local step-safety assessment: Merlin advisory beta

The default-on step-safety model supplies an additional advisory signal alongside
Kestrel. Kestrel keeps its existing Bash/shell classifier. Step-safety can score
short non-file tool actions using the user request and recent tool history.
Neither model replaces deterministic/Cedar authorization. `enforced` is always
`false`, and a timeout, exclusion, oversized input, or inference failure leaves
the settled authorization decision unchanged.

## Coverage

The retained checkpoint is DeBERTa-v3-xsmall, continued from the benchmark model
with mixed benchmark, authored and reviewed benign examples. See the
[matched-replay trial](merlin-matched-replay-trial.md) for its training composition and remaining false positives. It is not trained to understand every tool a
coding agent can call. The training inventory has no current-action tools named
`Read`, `Write`, `Edit`, `MultiEdit`, or `apply_patch`; nine generic
`file_operation` examples do not establish coverage for code edits or diffs.

The pilot excludes `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookEdit`, `apply_patch`,
and known file-content aliases such as `read_file`, `write_file`, and `edit_file`.
Namespace leaves are recognized (`functions.apply_patch`,
`mcp__filesystem__read_file`). These calls are skipped before arguments are
serialized, and their results are excluded from model history. Tool names such
as `read_email` and `write_message` remain eligible. Unknown aliases cannot be
identified semantically; extend the explicit list when adding an adapter.

The useful hypothesis is that request/action mismatch or suspicious tool use
may be detectable when the evidence fits in the model's input. This does not
establish sensitive-path policy, arbitrary patch analysis, detection of every
prompt injection, or protection against threats that require omitted context.
A compact representation that includes path, scope, or a diff summary would
need matching training/evaluation examples before becoming a model input.
The hook contract currently supplies raw arguments/results, not a general
trusted summary. The pilot does not invent one.

## Embedded runtime

The current [matched-replay candidate](merlin-matched-replay-trial.md) runs in
native Go with embedded float32 weights and tokenizer. Endpoints need no Python,
ONNX Runtime, downloads or installed model directory. The hidden historical
ONNX installer does not replace this candidate. See the trial document for exact
checkpoint/calibration pins, limitations and reproduction commands.

## Input limits

The four training fields, markers, separators, and 512-token padding stay the
same. Supported history uses the training head/tail rule after file-tool
exclusions; oversized requests, actions, and schemas remain unscored:

| Field | Content budget | When it does not fit |
| --- | ---: | --- |
| User request | 96 tokens | Skip: `request_too_large` |
| Recent interaction history | 144 tokens | Retain the first 72 and last 72 tokens after excluding file tools |
| Current tool name + complete arguments | 128 tokens | Skip: `action_too_large` |
| Available tool schemas, when supplied | 128 tokens | Skip: `schema_too_large` |

A long Bash command is therefore never scored from just its beginning and end.
The 128-token action allowance includes the tool name, JSON structure, and
`[TOOL_NAME]` / `[ARGUMENTS]` labels. Missing requests or schemas remain absent;
Kontext does not infer them from transcripts or assistant reasoning. Rare Unicode
combining sequences that Go NFC would modify differently from Hugging Face are
skipped as `unsupported_text`.

History remains compact sorted JSON with `tool`, optional `arguments`, and an
optional string `observation`. For example:

```json
[{"arguments":{"command":"pwd"},"observation":"{\"stdout\":\"/workspace\"}","tool":"Bash"}]
```

History is serialized in chronological order after file-tool exclusions. If
it exceeds 144 tokens, retain its first 72 and last 72 tokens, matching the
training packer. These token fragments need not form complete JSON; the model
was trained with that truncation. A result longer than the token window is no
longer discarded in full. A `history_omitted` flag records any excluded,
truncated, oversized, or evicted history, including token truncation for the
current inference.
It does not imply that omitted context was harmless.

Pre-tokenization limits remain 64 KiB per field and 128 KiB total. JSON input
is size-checked before serialization. The memory-only history cache holds at
most 256 sessions, 24 events per session, and 64 KiB of history per session.
Individual events may use that same 64 KiB bound, so supported results above
the former 4 KiB limit reach token truncation. Events beyond the byte bound
are rejected before evicting useful history. Overlong user requests are marked
unscorable, not silently cut.
`PostToolUse` history is captured before asynchronous ingestion acknowledges the
hook, so the next action sees the preceding retained interaction.

## Enable and operate

Advisory assessment is on by default. An unset or empty flag enables it; an
explicit `0` or `false` disables it without loading the model:

```sh
KONTEXT_STEP_SAFETY_SHADOW=0 kontext guard start
```

Managed deployments set the variables in their daemon configuration and restart;
an export in an unrelated terminal does not change an already-running service.
Existing explicit opt-outs remain disabled after upgrading. To re-enable, remove
the opt-out or set it to `1` and restart. Initialization loads the embedded model
once per process, using additional memory and up to the startup timeout; failure
leaves assessment unavailable and does not fail daemon startup.
Optional controls are `KONTEXT_STEP_SAFETY_TIMEOUT` (default 250 ms, maximum 500 ms),
`KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT` (default 30 seconds), and
`KONTEXT_STEP_SAFETY_MAX_CONCURRENCY` (fixed at 1).

Merlin admission and inference run in deferred recording after policy settles.
The hook response does not wait for model inference. Request/history are captured
at the call, and results cannot revise authorization. A per-evaluation deadline
bounds model-slot admission and work; Go checks cancellation between layers.
The recorder has four workers and 256 waiting slots. Submission happens after
the transport sends the settled response. A full queue retains the submitting
handler until space is available, preserving its audit record. Each transport
admits at most 64 active hook requests, so pending handlers cannot grow without
bound: new socket requests wait for admission, and excess HTTP requests receive
503 before policy evaluation. Shutdown drains transport submissions and accepted
records before closing the store/model; timed-out host closes preserve resources
for retry. No library is loaded or unloaded.

`GET /healthz` includes step-safety status, version, device (`go-cpu`), and a
redacted error code. An unavailable model does not make the main daemon unhealthy.
Each recorded enabled pre-tool call has a local `step_safety_verdicts` row containing
correlation IDs, capped/redacted tool name, probability when present, model
version, latency, error category, context-presence flags, `history_omitted`, and
`enforced=false`. Exclusions and failures have `shadow_decision=unavailable` and
no probability. They must not be counted as safe predictions.

Unsafe predictions also retain a separately bounded, redacted review context:
up to 2,000 bytes of the user request and 6,000 bytes of supported tool history.
This snapshot supplies the cloud AI assessment with evidence from the time of
the action. It does not alter Merlin's inference input or restore excluded file
tools. Context omission is explicit; no schemas or logits are stored.

Managed streams upload `merlin_annotation/v1` records in a separate optional
`merlin_annotations` array after the referenced action has been acknowledged.
The annotation remains excluded from signed decision facts. Retries use an
independent persisted cursor; mutable local feedback is not exported. Deploy
the cloud receiver and its migration before releasing this stream extension.
Results are available at `GET /api/sessions/{session_id}/step-safety`; same-origin
feedback can be posted to `POST /api/step-safety/{action_id}/feedback`:

```json
{"user_feedback":"should_allow"}
```

`should_block` is the other accepted label. The candidate calibration is
`sigmoid(1.3003148180546902 * (unsafe_logit - safe_logit) - 5.527577655786232)`;
the advisory threshold is `0.5`.

## Validation

Current candidate parity checks, research results and their limits are recorded
in [the matched-replay trial](merlin-matched-replay-trial.md). Historical ONNX numbers do
not describe the embedded candidate.
