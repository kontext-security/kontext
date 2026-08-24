# Observe-only risk-type classification

The risk-type classifier is a shadow advisory stage after the existing binary
bash-risk SVM. It annotates a binary `risky` result with zero or more canonical
effects; it never participates in authorization. The hosted Risk page does not
present it as a visible second-stage classifier: the current product category,
severity, and explanation come from the hosted automatic LLM assessment, while
this native result remains model-versioned shadow data.

## Runtime boundary

The stage runs only when all of these conditions hold:

1. the hook is `PreToolUse`;
2. the tool name is one of the explicit shell identities (`Bash`, `shell`,
   `shell_command`, `exec_command`, or `functions.exec_command`);
3. the input has a non-empty command; and
4. the existing binary SVM verdict is `risky` at its shipped threshold.

The tool allowlist is intentional. A payload from `apply_patch`, an MCP tool,
or another arbitrary tool can contain a `command` field or shell-looking text
without being shell execution. Those payloads are not eligible even if the
binary classifier produced a historical false positive for them.

Authorization is already settled before `Classifier.Classify` runs. The native
stage has no network or subprocess path; a missing/corrupt embedded artifact or
an inference panic degrades to a missing advisory result. Persistence errors
are ignored on the tool path. Managed hooks additionally do classification and
all ledger writes in their existing deferred recorder after returning the
decision to the agent.

## Exact deployed model

Source of truth: [authz-bench PR #1](https://github.com/kontext-security/authz-bench/pull/1),
revision `1c27d7770b46ce5cfbe99a2821d09f035cfe7bd8`.

The embedded model is the pooled `char_svm.joblib` artifact with SHA-256
`6a35aeba10cd9c72277c5a614613c285cf2bf318f1161b3dbe16815284495ca4`:

- `TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2,
  max_features=50000)` with scikit-learn defaults preserved (`lowercase=True`,
  raw term frequency, smooth IDF, L2 normalization);
- 15 balanced one-vs-rest `LinearSVC` heads in canonical taxonomy order;
- signed-margin threshold `0.0` independently on every head;
- every head at or above threshold is returned; the highest positive margin is
  `primary_risk_type`;
- no positive head returns `risk_types: []`, `primary_risk_type: "none"`, and
  `abstained: true`.

Unlike the binary SVM, this model was trained on the raw command. Do not call
`NormalizeCommand` before the risk-type model: URL, IP, and base64 replacement
would introduce train/serve skew. The Go port implements only the vectorizer's
own Unicode lowercase, Python-whitespace word splitting, padded character
n-grams, IDF multiplication, and L2 normalization.

`scripts/riskclassifier/export_risk_types.py` refuses any source artifact whose
preprocessing or estimator shape differs from that contract. It emits a
deterministic portable model plus 175 Python-reference golden commands with all
15 margins:

```bash
../authz-bench/.venv/bin/python scripts/riskclassifier/export_risk_types.py \
  --authz ../authz-bench
go test ./internal/guard/riskclassifier -run RiskType
```

Each result carries `authz-bench-risk-types-char-svm/1`, the joblib hash, source
revision and PR, annotation-corpus hash, annotation schema `1.0`, and prompt
version `1.1`.

No XGBoost, CodeBERT, or online Sol call runs in the CLI. Sol generated the
offline training annotations only. The hosted product's separate automatic LLM
assessment is outside this local model contract.

## Persistence and retrospective enrichment

Risk types do **not** extend `DecisionFactV1`. A decision fact and its receipt
are immutable signed historical evidence; adding a field later would change the
signed bytes. Instead, `risk_type_annotations` is an append-only derived table
with a deterministic ID and a unique `(action_id, model_version)` key. Live and
retrospective results use the same `risk_type_annotation/v1` envelope.

Live inference records `input_kind: "raw_command"`. Historical enrichment uses
the credential-redacted command already retained in `risk_classifier_verdicts`
and records `input_kind: "stored_redacted_command"`; raw historical commands
are intentionally unavailable. The source action's stored command hash binds
the derived result to that retained input.

Run the idempotent local enrichment with:

```bash
kontext risk-types enrich
kontext risk-types enrich --json
kontext risk-types enrich --db /path/to/guard.db --json
```

Re-running the command returns the existing byte-equivalent row. It neither
updates the authorization action nor rewrites `decision_fact_json` or receipt
payloads. A different model version appends a new row.

## Hosted schema compatibility

The CLI extends `authorization-ledger-v1` batches with an optional top-level
`risk_type_annotations` array. It is omitted when empty. Hosted support landed
in [kontext-cloud #884](https://github.com/kontext-security/kontext-cloud/pull/884)
and must remain deployed before a CLI that can emit non-empty annotations.

The hosted contract:

1. Defines a strict shared `RiskTypeAnnotationV1` schema matching
   `sqlite.RiskTypeAnnotationRecord`: deterministic `id`, `action_id`,
   `session_id`, optional `tool_use_id`, `command_hash`, `input_kind`, the
   complete nested `annotation`, and RFC3339 `created_at`.
2. Validates the 15 canonical labels and their order in `scores`; requires finite
   signed margins; derives the returned labels by applying the recorded
   threshold; requires primary to be the first highest positive margin; and
   requires `none` plus `abstained=true` for empty results. It validates all
   provenance fields as non-empty and treats the scores as margins, never
   probabilities.
3. Adds `risk_type_annotations` as an optional/default-empty array on
   `hostedLedgerBatchSchema` with a maximum of 1,000 records. The field counts
   toward the existing payload byte limit.
4. Persists annotations in a separate table keyed by organization,
   installation, annotation ID, and action/model uniqueness. Insert/upsert must
   be idempotent for an identical deterministic ID and reject different content
   for the same `(action, model_version)` key. It must not update the stored
   decision fact or signed receipt.
5. Permits an annotation to reference an action ingested by an earlier batch,
   while verifying that the action belongs to the same installation and
   organization. The CLI has an independent at-least-once annotation cursor,
   so duplicates are expected.
6. Exposes the derived annotation separately in shared API types. The current
   Risk UI intentionally uses the automatic LLM assessment for its visible
   classification and retains this result as shadow evidence.

No `DecisionFactV1` schema change is required or desired.

## Deployment caveat

Authz-bench reports pooled micro-F1 `0.764`, but source transfer is uneven:
Atomic Red Team held out is only `0.107` micro-F1, versus `0.667` for GTFOBins
and `0.658` for Payloads. The training set contains 514 retained commands and 15
supported types after excluding review/low-confidence/invalid rows; five source
annotations were still pending and 217 generated annotations required human
review in PR #1.

AI canonicalization made labels compatible; it did not solve coverage or
distribution shift. Risk types must therefore remain observe-only until typed
Kontext production feedback and a renewed transfer evaluation justify any
stronger use.
