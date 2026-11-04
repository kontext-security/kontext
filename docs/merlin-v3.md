# Merlin V3 ungated — local evaluation release

Runtime `merlin-v3-ungated-20261104` uses the unchanged V3 contextual encoder and
sparse action-agreement model from `merlin-v3-precision-20261007`. This is a
runtime eligibility change, not newly trained weights. It removes the operation
allowlist, lexical request gate and learned informational-request gate.

The threshold remains **0.5**. The complete current action must fit **128 tokens**;
long actions and excluded tools remain unassessed. The output score is a
threshold-relative agreement score, **not a calibrated probability of risk**.
This is an advisory detector; it does not execute or block tool calls.

## Run locally

Download this folder (`v3-ungated`) from `kontext-security/Merlin`, preserving its
layout. Go 1.26.10 or later is required to build the standalone native runtime.
It embeds the supplied assets and needs no Python, ONNX runtime or hosted inference.
Go downloads normal build dependencies on the first build.

```bash
hf download kontext-security/Merlin --include 'v3-ungated/*' --local-dir dist/Merlin
cd dist/Merlin/v3-ungated/native
go build -o merlin ./cmd/merlin
printf '%s\n' '{"id":"example","input":{"user_request":"Find public documentation","tool_name":"WebSearch","tool_arguments":{"query":"Go JSON decoder documentation"},"interaction_history":"[]"}}' | ./merlin
```

Each input line contains `id` and `input`. Input fields are `user_request`,
`interaction_history` (a JSON array encoded as a string), `tool_name`,
`tool_arguments`, and optionally `available_tool_schemas`. Include only completed
**prior** tool observations in history, never the current result or later turns.
Each output line preserves `id` and includes `evaluation`; unavailable assessments
have an `error_code` and no score. Do not treat those as safe classifications.

## Evaluation

| Cohort | Assessed / available | Detections or alerts |
|---|---:|---|
| AgentDojo-Traj | 1,159 / 1,220 | 85/352 positives detected (24.1% recall); 20/868 benign cases flagged (2.3% FPR) |
| Private historical replay cohort | 415 / 415 | 1 false alert |
| Private later workload sample | 600 / 1,207 | 3 clear false alerts, 1 uncertain low-impact alert |

The historical source pool contains 610 unique saved calls. Context was reliably
reconstructed for 415, forming the replay cohort above; the other 195 were
excluded before scoring because their context remains unresolved. They are not
runtime skips or successful safe predictions.

The original collected false-positive subset has 539 saved cases, of which 409
were reconstructed and assessed: Claude Code 0/128 alerts; Codex 1/281. The expanded
historical panel above includes these cases. These cohorts are not additive.
The later sample's clear false-alert frequency is 3/600 assessed calls (0.50%);
607 cases remain unassessed. This is not a population false-positive guarantee.

Historical data overlap training/selection/calibration and AgentDojo was repeatedly
consulted during development. The later sample is stratified, not traffic weighted.
Historical context was reconstructed from transcripts rather than exact daemon
snapshots. The remaining historical examples are unresolved, not successful tests.
No fresh ungated ASB or AgentHarm result is claimed. The earlier v0.1 benchmark
numbers do not describe this runtime.

This release is suitable for controlled evaluation. It is not evidence of uniform
precision on unfamiliar tools or workloads. See `merlin-v3-ungated-evaluation.json` for aggregates
and the Hugging Face release manifest for file checksums. **No private prompts, calls,
transcripts, reviewer text, identifiers or per-example scores are distributed.**
Private evaluation requires the internal access-controlled archive; the public
release cannot independently reproduce its private-data metrics.

## Provenance and terms

Base encoder: `microsoft/deberta-v3-xsmall` (MIT), revision
`4b419818330868dff6a60ad3e6b1c730f8b8c0c6`. The V3 encoder weights SHA-256 is
`429b09164c6705790c4414eb31c0bc18d2fa8a374bea467b2e1b49ead6aeb5f1`.
V3 was developed using benchmark data and private training/selection examples;
only model parameters and aggregate evaluation results are released here.
Upstream dataset/model terms continue to apply; consult the bundled attribution
and provenance files. The checkpoint is a research release (`other` license),
not a blanket commercial-use license. Runtime source follows the repository
Apache-2.0 license. The older request-intent asset remains for provenance but is
not used by the ungated inference path.

The [original gated V3 report](merlin-v3-gated.md) is retained for historical comparison. Kontext retains asynchronous advisory inference (`enforced=false`), the existing default-on setting and explicit opt-out.
