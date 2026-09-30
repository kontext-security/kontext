# Merlin precision candidate: opt-in local trial

Merlin is **off by default**. This change packages the retained September 24
`joint_ce` research candidate for an explicit local trial. It does not enable
Merlin for existing installations or change Cedar authorization.

## Exact candidate

- Model version: `merlin-joint-ce-20260924-primary`, selected epoch 2.
- Float32 checkpoint SHA-256:
  `429b09164c6705790c4414eb31c0bc18d2fa8a374bea467b2e1b49ead6aeb5f1`.
- Score: `sigmoid(0.9976812431377959 * (unsafe_logit - safe_logit) + 0.5990786345281421)`.
- Flag at score **>= 0.9089979801627239**. This cutoff belongs to this checkpoint
  and calibrator; it must not be applied to the historical model.
- Source experiment: `exp-20260924-merlin-joint-training` in ToolSafe-Lab.
  Source hashes and numerical references are in
  `internal/guard/stepsafety/model/native/candidate.json`.

The benchmark-trained DeBERTa-v3-xsmall checkpoint was further trained with
1,653 original benchmark rows, 812 authored benign/risky examples and 23 reviewed
local benign calls. Unknowns and old local LLM verdicts were excluded from
fitting. Ordinary cross-entropy was retained; the additional pair-ranking
experiment and later current-tool-only schema experiment were not selected.

## Input and runtime

Go implements the fixed transformer graph and embeds the unquantized weights
and tokenizer. No model download, Python, ONNX Runtime, CGo, shared inference
library or model-cache installation is needed on endpoints. Weights add roughly
198 MiB compressed to the binary even when inference is disabled. Enabling the
model also requires substantial RAM; embedding does not make it a small SVM.

The input keeps request, structured tool history, current action and available
tool definitions. Tool binding names are ASCII-lowercased consistently across
the action/history/schema, except where schema names collide by case. JSON keys
and formatting are canonicalized; command strings, argument keys/values and
natural-language content are preserved. Known shell/CUA display `title` and
`description` arguments are omitted; arbitrary payload descriptions are retained.
There is no alias augmentation at inference and no current-tool-only schema
selection. No assistant reasoning is read.

Nonempty JSON schema strings and supported text sections are normalized.
The endpoint also recognizes `name` + `input_schema` definitions without a
description, including tool lists and function wrappers. This extends the frozen
research normalizer's definition recognition; endpoint regression tests cover
binding consistency, case collisions and preservation of argument/schema content.
Python-literal containers are unsupported in the endpoint and return unavailable.
Missing schemas/requests remain missing. The 96/144/128/128 request/history/action/
schema token budgets remain fixed. Requests, actions and schemas must fit whole;
history may keep its first/last 72 tokens after file-tool exclusions. File edits
and known file tools remain outside the pilot. Unavailable is never a safe label.

Daemon entrypoints defer Merlin inference with decision recording. They snapshot
the request/history at the call, settle policy, then answer the hook without
waiting for model inference. Background completion cannot revise authorization.
The recorder has four workers and a queue of 256 waiting records. Submission never
waits for queue space. At saturation it drops the newest entire deferred record,
including its decision row and annotations, and workers report cumulative dropped
counts to the daemon log as they make progress (also reported on successful drain).
These are missing audit records, not safe predictions; inspect overload diagnostics
when interpreting trial results. There is no synchronous or unbounded fallback.
Shutdown closes admission and drains accepted records before the store/model close.
The existing 250 ms inference budget (maximum 500 ms) includes model-slot
admission; cancellation is checked
between model layers. Startup is bounded to 30 seconds and loads once per process.

## Opt in and roll back

For a standalone local Guard daemon built from this branch:

```sh
KONTEXT_STEP_SAFETY_SHADOW=1 kontext guard start
```

For a managed daemon, set that environment variable in the actual daemon service
configuration and restart that service; a variable in an unrelated terminal is
not inherited by an already-running service. This PR does not change the local
service configuration. Unset the variable or set it to `0` and restart to disable.
`KONTEXT_STEP_SAFETY_MODEL_DIR` does not replace the embedded checkpoint.

Check `/healthz` for `model_version: merlin-joint-ce-20260924-primary` and
`device: go-cpu`. With the flag absent, health reports disabled and no model loads.
Opted-in annotations keep `enforced=false`, the model version and exact threshold.
Existing managed telemetry/review behavior still applies to flagged calls;
this is not a separate silent shadow-data store. Local-only Guard does not upload.
The hidden historical ONNX installer remains a development compatibility command
and cannot change the embedded candidate.

## Evidence and limits

At the saved cutoff, research found 0/22 reviewed local benign flags, 0/12
authored clock flags, 47/180 authored risky detections and 11/192 authored benign
false positives. A later unseen-session panel had 1/41 benign flags and nine
unknowns; most captures came from staging. Labels are assistant annotations,
not independent human gold. There are no verified real local positives.

Offline AgentDojo precision/recall was 57.3%/55.7%, with many cropped inputs.
AgentDojo and AgentHarm were absent from supervised fitting and threshold fitting,
but previously studied as evaluations. These are not fresh blind, closed-loop
attack results or production guarantees. Tool-context sensitivity and false
positives remain research questions. In the trial, review flags and a sample of
unflagged calls; report missing/oversized inputs separately and keep LLM opinions
separate from confirmed labels. Do not change the cutoff to fit trial outcomes.

## Verification and reproduction

`candidate_golden.json` contains public authored examples and numerical length
controls generated by the pinned Python research normalizer, packer and saved
PyTorch checkpoint. Tests compare field text, all 512 token IDs/masks, logits,
calibrated probabilities and decisions. Boundary examples are selected by known
score to test parity; they are not an accuracy sample. Separate tests pin the 532
Hugging Face tokenizer vectors, cancellation, concurrent inference and returning
a socket response while the fake model remains blocked. Queue saturation and
concurrent submission/shutdown tests verify bounded admission, loss reporting,
and draining accepted records exactly once. The original 52 Python references
remain unchanged; separate endpoint tests cover `input_schema`-only definitions.

```sh
CGO_ENABLED=0 go test ./internal/guard/stepsafety ./internal/guard/app/server
CGO_ENABLED=0 go test -tags purego ./internal/guard/stepsafety -run TestCandidateMatchesPython
kontext step-safety benchmark --iterations 30 --json
```

Build-time regeneration uses the retained private research checkpoint and its
Python environment, with source hashes verified before reading weights:

```sh
python scripts/step-safety/candidate_fixtures.py --research-root /path/to/ToolSafe-Lab
python scripts/step-safety/embed_native.py --source /path/to/retained/joint_ce --output /path/to/fresh/native
```

The generated public fixtures contain no captured local requests or arguments.
`model/PROVENANCE.json` documents the historical ONNX export; the current embedded
candidate is documented by `model/native/candidate.json` and `manifest.json`.
