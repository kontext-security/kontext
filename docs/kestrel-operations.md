# AWS operation classifier: shadow integration

The existing n-gram SVM score, threshold, model version, verdict, risk-type gate,
authorization decisions and hosted upload contract stay unchanged. A second,
local annotation scores AWS CLI operations extracted from the full raw shell
input. Its `combined_verdict` is the hypothetical OR of the old verdict and the
operation verdict, not an average of incomparable margins. `shadow: true` is
mandatory in this version. Unsupported or malformed input is an abstention.
A resource-limited or failed scan keeps a positive already found, but emits no
score or negative verdict for an incomplete negative scan.

Initial scope: statically identifiable AWS CLI calls for the eight services in
the frozen training schemas (plus s3api), command substitutions, invoked shell
functions and literal shell wrappers. Python, HTTP, dynamic command construction
and arbitrary program semantics remain outside this implementation.

Shell exits propagate through taken blocks and functions; function returns and
child-shell exits stay local to their scopes. Fresh literal `bash/sh/dash -c`
shells do not inherit unexported parent functions. Static case patterns respect
matching and fallthrough; unknown branches represent possible execution. Global
AWS flags produce the same features regardless of their valid placement.
Budgets cover cumulative parsed bytes, traversed nodes, pattern bytes, scope
copies and extracted calls, including repeated function invocations.

The exporter verifies every consumed frozen input before importing research
modules or writing artifacts. Reproduce its integrity checks with the research
Python environment and the same two source-directory arguments as the exporter:

```sh
python scripts/check-aws-operation-export.py \
  --experiment-dir /path/to/known-operation-patch-2026-11-02 \
  --schema-dir /path/to/cloud-training-evaluation-2026-11-02 \
  --receipt /tmp/aws-export-checks.json
```

The receipt records rejection of changed weights, extractor code, syntax
schemas and authored fixtures. The private replay output must be a new file;
existing files, symlinks and hardlinks are refused without truncation.

## Failure modes to verify before implementation

- Changed legacy score, threshold, model version, alert or authorization outcome.
- Serving features differ from the frozen Python reference or use the wrong head.
- Quoted examples, help, skeleton generation, dry runs, dormant functions or
  statically false branches incorrectly produce operation alerts.
- Commands hidden in assignments, substitutions, functions or literal wrappers
  are lost; flag values are mistaken for flags; global options shift service/op.
- Redaction or the 8192-byte evidence cap modifies the model input.
- A parser error, unsupported operation, resource limit or model failure becomes
  a clean assessment, hides a positive already found, or crashes the daemon.
- Credentials or argument values leak through new annotations or parser errors.
- Old SQLite databases cannot upgrade; new records fail to round-trip or upload
  the shadow fields into a contract that does not support them.
- Repeated/concurrent calls mutate model state or reuse stale extraction results.
- Warm latency, tail latency or binary size exceeds the prototype estimates.

## Validation

Write integration fixtures and hook-to-SQLite tests before serving code. Use
real embedded models and the existing mvdan Bash parser. Compare scores with
frozen, inert Python-generated fixtures; never execute any fixture command.
Run the existing classifier, store and server checks and a bounded benchmark.
Keep a repeatable JSON test/benchmark/build receipt outside the repository.
All new records are local shadow data; enabling fleet alerts is a separate step.

The integration reuses `mvdan.cc/sh/v3/syntax` in Bash mode. There are no new Go
dependencies. The compressed artifact contains both frozen heads and syntax
tables, with source hashes in `aws_operations.provenance.json`. Regenerate it
with `scripts/export-aws-operation-model.py` and the frozen experiment inputs;
the script verifies the original model and extractor hashes before exporting.
The golden corpus contains synthetic authored inputs only, never production
traces. Python's duplicate function-body visits are not a serving requirement:
parity checks compare maximum margins and verdicts rather than visit counts.

The parser does not interpret arbitrary programs or resolve dynamic service/
operation names, aliases, sourced files, shell environment changes or flags
constructed at runtime. It considers potentially executable unknown branches;
it cannot prove which branch a tool call will take. Historical redacted commands
with broken shell syntax abstain rather than using regex recovery. Resource
bounds (1 MiB input, 100,000 syntax nodes, depth 128 and 1,024 operations) are
reported as `limit_exceeded`, with no silent input truncation. Existing SVM
assessment still runs on its original full input.

For private corpus replay, provide JSONL `{id,command}` rows via
`KONTEXT_OPERATIONS_REPLAY_INPUT`, set a distinct output file with
`KONTEXT_OPERATIONS_REPLAY_OUTPUT`, and run:

```sh
go test ./internal/guard/riskclassifier -run '^TestAWSOperationLocalCorpusReplay$' -count=1 -v
```

Replay output contains scores and status only. It never contains command text,
argument values or hashes of unredacted commands. This fixture tool does not
execute shell commands.
