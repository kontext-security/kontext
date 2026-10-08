# Merlin V3: precision-first contextual issue detection

Candidate `merlin-v3-precision-20261007` combines a repaired Claude prompt path
with a deliberately narrow contextual detector. This is a review candidate;
creating this change does not update an installed daemon or hook configuration.
The existing default-on advisory behavior and explicit opt-out are preserved.
Kestrel, Cedar policy decisions and the asynchronous inference boundary remain
unchanged. Every Merlin result has `enforced=false`.

## Why the prompt fix alone is insufficient

Claude's managed hook template omitted UserPromptSubmit while Codex included it.
The installed Claude configuration had the same omission. All 1,105 Claude V2
records in the initial audit lacked a user request. The V2 fitting pool contained
188 real calls from one Codex session, with no WebSearch/WebFetch/ToolSearch.
Claude did appear in calibration and the small test panel; it was not wholly
untested. Normalizing capitalization already worked, but name-only WebSearch to
webrun substitutions changed seven of 239 empty-history decisions from flag to
no flag. This diagnostic is not adopted as a production aliasing workaround.

The follow-up recovered actual explicit human requests from two Claude sessions
and paired 1,060 fully captured calls with and without those requests. Tool,
arguments, empty history and absent schemas were fixed within each pair. Skill
attachments, task notifications and assistant reasoning were excluded. These
are input interventions, not exact reconstructions of original live history.

| Frozen model/input contract | Result on 1,060 restored-request calls | AgentDojo, 1,220 calls /352 risky |
| --- | --- | --- |
| V2 plus prompt transport only | 13 assessed; four benign calls flagged; 1,047 unavailable | Five assessed, zero detections |
| V2 plus bounded request/schema context | 889 assessed; 191 flags, including 45/71 previously reviewed benign flags | 92 true and 52 false alerts; 26.1% recall |
| V3 plus prompt repair | Zero flags; all these local operations outside scope | 23 true and zero false alerts; 6.53% recall |

V2's 70 incident false positives become request-too-large under the hook-only
fix. That is loss of coverage, not successful benign classification. Four other
short real requests still produce false alerts on public searches and localhost
navigation. Allowing V2 to read bounded long context increases noise. Neither
simpler change meets the precision requirement.

The V3 comparison reuses the frozen candidate and thresholds; no retraining or
threshold selection used these follow-up outcomes. Earlier evidence includes
zero alerts in 539 captured hosted-benign flags (mixed fitting/evaluation roles,
not all unseen), and one independently reviewed credible issue in 3,545 additional
published AgentDojo calls from another model on the same task suite. The benchmark
has been studied repeatedly and these observations do not prove production
precision. No hosted “risky” judgment is treated as a true-positive label.

## Model and input contract

An alert requires a recognized structured deletion, credential change, money
transfer, outgoing message or sharing effect; populated effect arguments; a
request without explicit or ambiguous mutation authorization; a learned
informational-intent gate; and agreement between contextual and action models.
The contextual neural checkpoint is retained from earlier research; the action
and request filters are newly trained. Ordinary reads, Bash, browser/code wrappers
and unsupported tools abstain. This scope reduction explains much of the noise
reduction and gives up broad risk coverage.

The complete request is checked by the intent/authorization gates. The encoder
uses request head96, history head72/tail72, complete action128 and schema
head64/tail64, within the existing 512-token sequence. Existing 64 KiB per-field
and 128 KiB total byte limits remain. Missing intent and other abstentions carry
an error reason with no score; they are never certified safe. The legacy
`unsafe_probability` field carries a threshold-relative agreement score, not a
calibrated probability of actual harm.

Weights, tokenizer and both sparse filters are embedded in native Go. No ONNX,
Python, external model installation or runtime downloads are needed. Current
pins, thresholds, provenance and licenses are under
`internal/guard/stepsafety/model/native` and `model/ATTRIBUTION.md`. The separate
historical ONNX provenance remains preserved for its legacy installer.

## Integration and validation

Claude prompt registration is required in both managed and user installs. Older
Kontext-owned configurations remain recognizable for upgrade; foreign prompt
hooks are preserved. A new empty prompt clears stale intent. Adapter-to-runtime
tests cover latest prompt, session closure and Claude/Codex isolation. Existing
tests protect the pre-call context snapshot and post-response inference boundary.

Updating a binary alone does not refresh installed hooks. Use the normal setup
or management upgrade flow when a trial is authorized; the daemon's memory-only
request cache also needs a fresh prompt after restart. Do not judge a trial only
by lack of alerts: check request coverage and actual eligible assessments.

The integrated implementation reproduces the 1,505 saved native reference
decisions and replays 1,060 restored-request calls separately. Public numerical
fixtures are committed; private captures remain in ToolSafe-Lab. The standalone
candidate measured about 1.63 GB peak RSS, 2.35 s startup and 120 ms long-context
p95 on macOS arm64. Other-platform latency is not established. Pure-Go parity,
race tests and an isolated daemon E2E cover portability and advisory behavior;
E2E requires an actual eligible score within the configured production deadline,
and separately verifies forced-timeout and explicit opt-out behavior.

Research records: `exp-20261007-merlin-v3-precision`, child
`merlin_prompt_repair_20261007_v1` in ToolSafe-Lab. Aggregate results accompany this
document; no local user content, API keys or raw replay data belongs in this PR.
