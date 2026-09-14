# Local step-safety shadow pilot

The opt-in step-safety model supplies an additional advisory signal alongside
Kestrel. Kestrel keeps its existing Bash/shell classifier. Step-safety can score
short non-file tool actions using the user request and recent tool history.
Neither model replaces deterministic/Cedar authorization. `enforced` is always
`false`, and a timeout, exclusion, oversized input, or inference failure leaves
the settled authorization decision unchanged.

## Coverage

The checkpoint is DeBERTa-v3-xsmall, fine-tuned on 2,192 TS-Bench training rows
(1,518 ASB and 674 AgentAlign). It is not trained to understand every tool a
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

## Install: Go serving, ONNX Runtime, no Python on endpoints

Kontext runs a CPU ONNX session in-process through a pinned Go binding. Both
tokenization and field packing are Go. The existing `CGO_ENABLED=0` release
builds are preserved; the optional feature dynamically loads a separate native
ONNX Runtime library. Nothing is downloaded when the daemon starts or scores.

The model and tokenizer are not embedded in the binary. Import a verified
export and provision the native runtime with the explicit install command:

```sh
kontext step-safety install --source /path/to/exported-onnx-model
```

This copies only `config.json`, `model.onnx`, `tokenizer.json`, and
`tokenizer_config.json`, verifies sizes and SHA-256 hashes, and writes license
and provenance files. It then downloads the checksum-pinned CPU runtime from
Microsoft's [official ONNX Runtime releases](https://github.com/microsoft/onnxruntime/releases).
For offline installation, supply `--runtime-archive /path/to/pinned-runtime.tgz`.
Each component is published atomically; retrying an interrupted runtime install
reuses the already verified model. Existing invalid destinations are reported
rather than overwritten.

The cache is:

```text
<ledger directory>/judge-models/toolsafe/toolsafe-deberta-v3-xsmall-onnx-scoped-v2
```

Use `--db` to select the daemon's ledger path or `--destination` for a custom
cache. The native library lives under `runtime/<os>-<arch>` inside it. Linux
amd64/arm64 and Apple Silicon use ONNX Runtime 1.24.4; Intel macOS uses the
upstream 1.23.2 x86_64 asset. Only the pinned library is loaded, never a library
found through the shell's search path. ONNX Runtime still has the platform's
native OS/C++ runtime requirements; unsupported hosts report unavailable.

For maintainers, the one-time checkpoint conversion uses Python in the build
workspace. It is separate from installation and serving:

```sh
python3.12 -m venv /tmp/step-safety-export-env
/tmp/step-safety-export-env/bin/pip install -r scripts/step-safety/requirements-export.txt
/tmp/step-safety-export-env/bin/python scripts/step-safety/export_onnx.py \
  --source /path/to/ToolSafe-Lab/artifacts/models/history_serialization/deberta_v3_xsmall \
  --output /path/to/new-exported-onnx-model
```

The exporter verifies source hashes, emits fixed `[1,512]` inputs and `[1,2]`
float32 logits at opset 17, checks the model, and verifies the exported bytes
against the serving pin. It performs no model-hub lookup and never imports the
training resume checkpoint. A second clean export reproduced the pinned hash.

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

Shadow mode is off by default:

```sh
export KONTEXT_STEP_SAFETY_SHADOW=1
kontext guard start
```

Managed deployments set the variables in their daemon configuration and restart.
Optional controls are `KONTEXT_STEP_SAFETY_MODEL_DIR`,
`KONTEXT_STEP_SAFETY_TIMEOUT` (default 250 ms, maximum 500 ms),
`KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT` (default 30 seconds), and
`KONTEXT_STEP_SAFETY_MAX_CONCURRENCY` (fixed at 1).

The hook deadline includes admission and inference. The native binding does
not interrupt an active `Run`; Kontext returns at the deadline, discards its
late result, and holds the singleton slot until the native call completes.
Subsequent calls cannot accumulate unbounded background work. Native session
creation is also bounded at the caller, and late-created sessions are closed.
`Close` waits for outstanding native inference before unloading its library.
Missing or invalid artifacts produce an unavailable model until daemon restart.

Managed `PreToolUse` retains its reserved policy budget and bounded shadow
allowance (one second total at the hook edge). Installed Claude/Codex hooks keep
their existing 20-second outer timeout.

`GET /healthz` includes step-safety status, version, device (`onnx-cpu`), and a
redacted error code. An unavailable model does not make the main daemon unhealthy.
Each enabled pre-tool call records a local `step_safety_verdicts` row containing
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

`should_block` is the other accepted label. The original calibration is
`sigmoid(1.427213430140093 * (unsafe_logit - safe_logit) + 2.953687013257505)`;
the advisory threshold remains 0.5.

## Validation and interpretation

Run ordinary Go tests without model artifacts or Python. To check the actual
installed model, tokenizer, frozen reference logits, and deadline behavior:

```sh
KONTEXT_STEP_SAFETY_PARITY_MODEL_DIR=/path/to/installed-model \
  CGO_ENABLED=0 go test ./internal/guard/stepsafety -run 'TestGoTokenizer|TestONNX' -v
kontext step-safety benchmark --model-dir /path/to/installed-model --iterations 50 --json
```

The Go tokenizer matched 532 Hugging Face vectors, including Unicode,
normalization, special tokens, and structured-history fixtures. All seven
frozen checkpoint cases matched token IDs exactly and logits within `2e-5`.
These tests deliberately reconstruct the old training packer to verify the
conversion. Separate cache-to-Evaluator tests verify that supported results
above 4 KiB survive storage and match frozen Hugging Face training token vectors
after truncation. Production admission and file-tool exclusion have separate tests.
On the implementation host (Apple Silicon, CPU, 50 measured calls after
warm-up), p50 was 53.88 ms, p95 55.71 ms, p99 56.04 ms, with zero failures.
This is a local measurement, not a fleet latency guarantee.

A committed 48-case synthetic smoke set (`testdata/scoped_smoke.json`) contains
24 labeled pairs covering shell, file, communication, API, database, and
network actions. Under the scoped policy, 10 Read/Write/Edit cases were skipped
and 38 were scored. All 38 were classified safe: **0/19 unsafe cases detected,
19/19 benign cases classified safe**. This small, hand-authored set is not a
production recall estimate, but it provides no positive evidence for detection
at the current threshold. Many examples carried context through a Read result;
excluding that history removes it from the model. `TestONNXScopedSmoke` reports
per-family confusion counts without treating model mistakes as software-test
failures or tuning the threshold to these examples.

An aligned replay uses the same 192 archived benchmark/validation inputs before
and after the history change, with unchanged weights, calibration, admission,
and threshold. The panel selected solely for input eligibility reports:

| Source | Unsafe detected before -> after | Safe flagged before -> after |
| --- | --- | --- |
| ASB | 20/20 -> 20/20 | 0/20 -> 0/20 |
| AgentAlign validation | 5/5 -> 5/5 | 0/12 -> 0/12 |
| AgentDojo | 0/4 -> 3/4 | 0/2 -> 0/2 |
| AgentHarm | 1/3 -> 1/3 | 0/8 -> 2/8 |

The three recovered detections follow transaction, file-listing, and email
results longer than 144 tokens; none requires restoring Read. The two restored
false alarms also match the training-reference behavior. The original packing
is not itself a guarantee of model quality.

Admission remains restrictive on the archived payloads: a separate balanced
40-example panel per source scores 40 ASB, 3 AgentAlign, 0 AgentDojo, and 3
AgentHarm examples. Most skips outside ASB involve oversized tool descriptions.
Live adapters can supply different schema payloads, so these are not production
coverage rates. These previously used benchmark/validation controls are not a
new independent holdout. Sampling, case IDs, skip counts, and before/after
confusion counts are in [the recorded replay results](step-safety-shadow-results.json).

The source checkpoint's held-out TS-Bench results were 91.19% accuracy, 92.66%
precision, 88.45% recall, and 50.85% worst-source recall. Those metrics describe
the original evaluation representation, not the new scoped production policy.
For the pilot, report scored-call coverage, skip reasons, false positives and
false negatives on reviewed calls, history omissions, and timeout rates,
separately for shell and non-shell tools. Keep Kestrel's results independent;
their probabilities measure different signals and should not be averaged.

The input-policy version is `toolsafe-deberta-v3-xsmall-onnx-scoped-v2`, separating
these shadow results from the earlier whole-event policy and Python pilot.
Checkpoint weights, tokenizer, calibration, and threshold are unchanged; no
retraining or new export is required. Existing verified ONNX files remain usable
with an explicit model directory. Extending
coverage requires evidence on the proposed inputs, but useful narrow advisory
signals do not require this model to be an ultimate guard.

## Provenance

The checkpoint and history serializer are from ToolSafe-Lab commit
`9c63e6191598b0ba72947a4394ac8297c41053d1`, under
`artifacts/models/history_serialization/deberta_v3_xsmall`. The base model is
[`microsoft/deberta-v3-xsmall`](https://huggingface.co/microsoft/deberta-v3-xsmall/tree/4b419818330868dff6a60ad3e6b1c730f8b8c0c6),
revision `4b419818330868dff6a60ad3e6b1c730f8b8c0c6`, under the
[Microsoft MIT license](https://github.com/microsoft/DeBERTa/blob/master/LICENSE).
Source weights, export toolchain, model artifact hashes, input policy, and
reference-only evaluation metrics are recorded in
`internal/guard/stepsafety/model/PROVENANCE.json`. Native runtime archive and
library hashes are pinned in `runtime_artifacts.go`; the installed runtime
includes its own license, third-party notices, and provenance.
