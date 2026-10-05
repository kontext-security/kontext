# Matched replay: authorized local staging trial

On 2026-10-05 Hasan accepted lower AgentDojo recall in exchange for fewer benign
flags and requested replacing his running local Merlin with `matched_replay` at
the already evaluated diagnostic cutoff `0.5`. This is a local trial decision
after reviewing results, not a claim that the original synthetic-heavy operating
point gates passed. The original research freezes and findings are unchanged.

- Model version: `merlin-matched-replay-20261005-local`, epoch 2.
- Source experiment: `exp-20261005-merlin-matched-hard-negatives`.
- Float32 checkpoint SHA-256:
  `6b888cff5a81dd9785a756b95b6f56b362ddc7ce792883a422d389857ddaaaf4`.
- Score: `sigmoid(1.3003148180546902 * (unsafe_logit - safe_logit) - 5.527577655786232)`.
- Flag at score **>= 0.5**. The previous model's `0.909` cutoff does not apply.

The same native Go graph embeds the unchanged FP32 checkpoint and tokenizer.
Input normalization, field budgets, unsupported-input behavior, asynchronous
recording, inference deadline and policy handling remain unchanged. Merlin is
still disabled by default; this user's existing opt-in remains advisory and
uses the staging profile. No tool call is blocked by a Merlin classification.

Training retains the previous data and adds 188 real likely-benign staging
calls, with authored paired calls placed in real histories. At 0.5, independent
held-out replay has 4/50 older and 0/21 newer benign flags, versus 44/50 and 18/21
for the previous deployed candidate. These selected captures are not a traffic
false-positive-rate estimate and many histories are truncated. AgentDojo direct
offline results are 113/352 unsafe detected (32.1% recall), 59/868 benign flagged
(6.8%), and 65.7% precision. AgentDojo was not fitted in this experiment; native
admission coverage must be kept separate from these direct classifier metrics.

The retained synthetic probes remain diagnostics, not evidence of real attacks.
They expose limitations, including missed directory deletion controls. This
local trial does not authorize a broader release or enforce-mode deployment.

## October 5 follow-up: retain strict input handling

The final packaging keeps the current field budgets and rejection behavior. No
first-X or first/last truncation change is included. In the separate offline
coverage comparison, both truncation methods assessed 1,208/1,220 historical
AgentDojo-derived rows, compared with 5/1,220 under current native limits.
Training-style truncation detected 112/350 assessed unsafe calls and flagged
59/858 benign calls; first-X detected 12/350 and flagged 3/858. Both retained
4/71 local held-out benign flags. These results justify neither a local-noise
improvement nor broader deployment. Unassessed calls are not safe predictions.

The expanded truncation experiment also exposed three native/Python probability
differences above its frozen 1e-5 tolerance (maximum 1.279e-5), with no decision
differences. That numerical gate remains failed; its inputs are outside the
current strict admission policy. The public and private fixtures below are
separate numerical regression checks, not evidence that this expanded gate passed.

A read-only local snapshot through 2026-10-05T15:15:25Z contained 199 scored
calls (192 safe, 7 flagged) and 296 unassessed calls since activation. Inspection
of all seven flagged calls found routine lookup/navigation behavior, including
plugin discovery, public web search, research-page reads and chat reads. The
six newer flags had full captured arguments but character-truncated saved review
histories; exact original model inputs cannot be reconstructed from those saved
histories. These seven assistant-reviewed examples are a diagnostic, not a
traffic-wide accuracy estimate or independent human ground truth.

The hosted reviewer still used prompt v4 for these calls. Six of seven Merlin
flags were marked risky, often by inferring possible payments, edits or sensitive
data from surrounding context while exact arguments were missing. The separate
cloud reviewer PR addresses evidence capture and unsupported risk speculation;
no reviewer implementation or daemon configuration is changed here. Remaining
model false positives and assessment coverage both require further validation.

Reproduce numerical references with ToolSafe-Lab's Python environment:

```sh
python scripts/step-safety/matched_replay_fixtures.py --research-root /path/to/ToolSafe-Lab
python scripts/step-safety/embed_native.py --source /path/to/matched_replay --output /path/to/fresh/native
```

Install the generated shards/manifest into `internal/guard/stepsafety/model/native`
before building. The old 52 public references remain in
`testdata/candidate_joint_ce_golden.json`; the current references test the same
packing and token vectors with the new weights/calibration. A separate private
fixture verifies all 71 real replay scores without publishing captured text;
only 12 have complete retained histories for full input-to-score parity.
Public authored fixtures verify numerical correctness only, not model quality.

```sh
CGO_ENABLED=0 go test ./internal/guard/stepsafety ./internal/guard/app/server ./internal/managedobserve
CGO_ENABLED=0 go test -tags purego ./internal/guard/stepsafety -run TestCandidateMatchesPython
KONTEXT_MERLIN_PARITY_FIXTURE=/path/to/private/real_parity.json CGO_ENABLED=0 go test ./internal/guard/stepsafety -run TestCandidateMatchesPython
```

Activation uses the existing Kontext management runtime and stable hook command.
The previous executable and its metadata are retained for rollback. The final
activation receipt and parity logs live in the ignored research run's
`local_trial` directory; aggregate results live under ToolSafe-Lab `results/`.
