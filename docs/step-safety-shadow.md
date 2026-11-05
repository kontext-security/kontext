# Local step-safety assessment: Merlin advisory beta

The default-on Merlin V3 ungated runtime supplies an advisory contextual signal
alongside Kestrel. Neither model replaces deterministic/Cedar authorization.
Inference remains asynchronous and `enforced` is always `false`.

## Coverage

[V3 ungated](merlin-v3.md) uses the same contextual DeBERTa weights and learned
action-agreement filter as V3, with the operation allowlist, lexical request gate
and learned informational-intent gate removed. Bash, browser wrappers, lookups
and unknown tool names can now be assessed if they fit the existing input limits.
Known file-content tools such as Read, Write, Edit and apply_patch remain excluded.
The threshold remains 0.5. Scores express threshold-relative agreement, not a
calibrated probability of actual risk. Missing request context no longer causes
an eligibility rejection; context-presence flags remain available for review.

## Embedded runtime

Native Go runs the embedded float32 contextual checkpoint, tokenizer and two
small sparse classifiers. Endpoints need no Python, ONNX Runtime, downloads or
installed model directory. The hidden historical ONNX installer does not replace
this candidate. Serving provenance is in `model/native/PROVENANCE.json`; the
older `model/PROVENANCE.json` describes only that historical installer.

The checkpoint is about 213 MB of the binary. Hosts that cannot carry that, such
as plugin packages for hosted agent sessions, can build without it:

```bash
CGO_ENABLED=0 go build -tags nostepsafetymodel -ldflags='-s -w' ./cmd/kontext
```

That binary is about 18 MB. Assessment then reports `unavailable`, which means
not assessed; authorization and decisions are unchanged. Release artifacts are
built with the model.

## Input limits

The four training fields, markers, separators, and 512-token padding stay the
same. Request intent and operation names no longer determine eligibility.
The contextual model receives the same bounded view. Actions are never truncated:

| Field | Content budget | When it does not fit |
| --- | ---: | --- |
| User request | 96 tokens | Retain the first 96 tokens |
| Recent interaction history | 144 tokens | Retain the first 72 and last 72 tokens after excluding file tools |
| Current tool name + complete arguments | 128 tokens | Skip: `action_too_large` |
| Available tool schemas, when supplied | 128 tokens | Retain the first 64 and last 64 |

Oversized actions are skipped in full.
The 128-token action allowance includes the tool name, JSON structure, and
`[TOOL_NAME]` / `[ARGUMENTS]` labels. Missing requests or schemas remain absent;
Kontext does not infer them from transcripts or assistant reasoning. Missing
requests are recorded with `user_request_present=false` and do not by themselves
prevent assessment. Rare Unicode
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
are rejected before evicting useful history. Requests exceeding the byte bound
remain unscorable; token-level request cropping is the explicit V3 policy above.
`PostToolUse` history is captured before asynchronous ingestion acknowledges the
hook, so the next action sees the preceding retained interaction.

## Prompt capture

Both Claude Code and Codex must register UserPromptSubmit. The hook captures the
latest prompt before tools run; Merlin inference still runs after the tool-hook
response. Empty new prompts clear stale intent, session closure clears context,
and Codex and Claude session IDs remain isolated. Upgrades recognize older
Kontext-owned five- and seven-event Claude configurations as incomplete so setup
can add the missing hook. Foreign settings and prompt handlers are preserved.
A binary upgrade alone does not rewrite already installed hook settings: refresh
them through the normal setup/management flow before evaluating coverage. The
context cache is memory-only, so a daemon restart needs a new prompt event.

## Enable and operate

Advisory assessment is on by default. An unset or empty flag enables it; an
explicit `0` or `false` disables it without loading the model:

```sh
KONTEXT_STEP_SAFETY_SHADOW=0 kontext guard start
```

Managed deployments set the variables in their daemon configuration and restart;
an export in an unrelated terminal does not change an already-running service.
Existing explicit opt-outs remain disabled after upgrading. To re-enable, remove
the opt-out or set it to `1` and restart. The embedded model loads once per process,
using additional memory and up to the startup timeout; failure leaves assessment
unavailable and does not fail startup. The managed daemon loads it in the background
and serves hooks meanwhile, while the local guard server loads it before serving.
Optional controls are `KONTEXT_STEP_SAFETY_TIMEOUT` (default 250 ms, maximum 500 ms),
`KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT` (default 30 seconds), and
`KONTEXT_STEP_SAFETY_MAX_CONCURRENCY` (fixed at 1).

Merlin admission and inference run in deferred recording after policy settles.
The hook response does not wait for model inference. Request/history are captured
at the call, and results cannot revise authorization. A per-evaluation deadline
bounds model-slot admission and work; Go checks cancellation between layers.
Records of calls made during a background load wait for the model instead of going
unscored. That deadline and the reported latency start once it has loaded. They are
then released together and share the one model slot, so with a large backlog or slow
inference some record `timeout` or `concurrency_timeout`. A stop releases them with
`daemon_stopping`. A crash during the load loses them.
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
correlation IDs, capped/redacted tool name, agreement score in the legacy
`unsafe_probability` field when present, model
version, latency, error category, context-presence flags, `history_omitted`, and
`enforced=false`. Exclusions and failures have `shadow_decision=unavailable` and
no score. They must not be counted as safe predictions. Historical gated V3 rows may contain `unsupported_effect`, `missing_request`,
`compound_or_mutation_request` or `request_not_informational`. The ungated runtime
no longer produces those gate-rejection codes.

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
