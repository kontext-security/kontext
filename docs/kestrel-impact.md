# Kestrel Impact advisory pilot

Kestrel Impact detects consequential destructive or disruptive capability from
the command alone. It does not assess authorization, intent, or whether an
operation was a mistake. It runs alongside the existing Kestrel SVM, including
when that model returns a low-risk verdict. Neither score changes the local
Cedar policy decision.

The pilot uses the frozen `command-risk-process/9-P_process` linear model and
`kontext-command-risk-features/2` extractor. Both use Kontext's existing
`mvdan.cc/sh/v3` Bash parser dependency. Parsing is inert: no command execution,
variable expansion, environment lookup, filesystem access, or network access.
The extractor and scorer are imported from the evaluated research implementation;
feature semantics and weights must not change without a new version and evaluation.

The `one_percent` calibration setting flags a margin **>= 1.1957946473415046**.
This is a calibration false-positive budget, not an alert probability, severity,
or a guarantee about production false positives. Lower scores are reported as
`below_threshold`, never as proof of safety. Limits, unavailable models and
inference failures are explicit `not_assessed` annotations with no score.

## Integration verification plan (before implementation)

Failure modes to exercise:

- Impact-only flags disappear behind the existing SVM, tool allowlist, or risk UI.
- Advisory success/failure changes a settled Cedar allow/deny decision.
- Non-shell input or a missing command receives a shell assessment.
- A clipped/redacted input changes the score; raw commands or features leak into
  model annotations, logs, error messages or diagnostic hashes.
- Different normalization, vocabulary, parser version, weights or threshold
  changes the evaluated margins. Check parity against the frozen research binary.
- Limit-exceeded/parser-fallback input is silently labelled safe or loses status.
- Concurrent scoring mutates shared weights or has non-deterministic output.
- A bad embedded model prevents startup or disables existing Kestrel.
- Old SQLite databases cannot add/read the optional Impact column, or old records
  acquire invented scores. A reopened store must retain annotations exactly.
- New signed facts cannot round-trip through the mirrored Go/TypeScript contract,
  optional fields alter historical fact bytes, or invalid/nonfinite results pass.
- Hosted filters, explanations and UI omit Impact-only flags or interpret the
  margin as a probability. Existing allow/block feedback must not be treated as
  Impact capability labels.

Tests pass command strings only as inert data. The original incident is a
regression check only; no fitting or threshold selection is part of this change.

## Serving and rollout

The model is embedded compressed, checked against its frozen SHA-256, decoded
once per process and scored in Go. There is no additional inference service.
Existing Kestrel remains enabled if Impact is unavailable. Set
`KONTEXT_KESTREL_IMPACT_ENABLED=false` before starting Guard to disable Impact.

Annotations persist separately from the legacy SVM score, with model/extractor
versions, source artifact hash, status, margin, threshold, verdict and
`enforced: false`. The existing credential redaction and command length cap
still govern stored evidence; inference uses the full command within extractor
limits. No features or raw input are added to the annotation.

Deploy the compatible hosted schema/read paths before enabling the updated CLI:
older strict ingest validators reject unknown classifier fields. Existing signed
facts are not rewritten. This change prepares an advisory pilot; deployment and
replacement of an installed CLI are separate operations.

Evaluate alert volume per session as well as per call. Review capability labels
(`consequential`, `clear false alert`, `uncertain`) separately from existing
Kestrel allow/block feedback. Retain the 0.5% setting for offline comparison;
the serving threshold is fixed to the approved 1% setting.
