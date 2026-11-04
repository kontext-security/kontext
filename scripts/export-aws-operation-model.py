#!/usr/bin/env python3
"""Package frozen research weights and syntax tables; never execute input commands.

Usage: <research-venv>/bin/python scripts/export-aws-operation-model.py \
  --experiment-dir /path/to/known-operation-patch-2026-11-02 \
  --schema-dir /path/to/cloud-training-evaluation-2026-11-02

The experiment modules require bashlex. No training, imports of captured source,
network access, or production trace export occurs here. Golden inputs come only
from the authored synthetic dataset, including its routine controls.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_frozen_inputs(patch, schema):
    expected = json.loads(Path(__file__).with_name('aws-operation-frozen-inputs.json').read_text())
    schemas = {p.name for p in (schema / 'source-schemas').glob('*.json')}
    pinned = {Path(p).name for p in expected['schema'] if p.startswith('source-schemas/')}
    if schemas != pinned:
        raise ValueError('frozen schema set mismatch')
    for key, root in (('experiment', patch), ('schema', schema)):
        for name, sha in expected[key].items():
            source = root / name
            if not source.is_file() or digest(source) != sha:
                raise ValueError('frozen input hash mismatch: ' + key + '/' + name)
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-dir", required=True, type=Path)
    parser.add_argument("--schema-dir", required=True, type=Path)
    parser.add_argument("--verify-only", action="store_true", help="verify every frozen input before imports; write nothing")
    args = parser.parse_args()
    patch, schema = args.experiment_dir.resolve(), args.schema_dir.resolve()
    expected = verify_frozen_inputs(patch, schema)
    if args.verify_only:
        print(json.dumps({'verified_inputs': sum(map(len, expected.values())), 'written_files': 0}))
        return
    sys.path[:0] = [str(patch), str(schema)]
    from operation_features import event_features, extract
    from semantic_features import SCHEMAS, kebab, parameters

    heads = {}
    sources = {}
    for unit in ('command', 'session'):
        sha = expected['experiment']['models/' + unit + '.joblib']
        source = patch / "models" / (unit + ".joblib")
        if digest(source) != sha:
            raise ValueError("frozen model hash mismatch: " + unit)
        portable = patch / "models" / (unit + ".json.gz")
        head = json.loads(gzip.decompress(portable.read_bytes()))
        if digest(patch / "operation_features.py") != head["feature_extractor_sha256"]:
            raise ValueError("feature extractor changed after model export")
        heads[unit] = head
        sources[unit] = {"joblib_sha256": sha, "portable_sha256": digest(portable)}

    tables = {}
    for service, model in sorted(SCHEMAS.items()):
        cli_service = "s3api" if service == "s3" else service
        tables[cli_service] = {
            kebab(op): parameters(cli_service, kebab(op))
            for op in sorted(model["operations"])
        }
    tables["s3"] = {op: parameters("s3", op) for op in
                    ("ls", "cp", "mv", "sync", "rm", "mb", "rb", "presign", "website")}
    bundle = {
        "schema": "kontext-aws-operations/1",
        "model_version": "aws-operations/0.1.0-shadow",
        "extractor_version": "aws-cli/1",
        "heads": heads,
        "argument_types": tables,
    }
    root = Path(__file__).resolve().parents[1] / "internal/guard/riskclassifier"
    artifact = root / "model/aws_operations.json.gz"
    artifact.write_bytes(gzip.compress(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode(), mtime=0))

    # AWS-only golden scores. HTTP/Python effects are explicitly out of scope.
    rows = json.loads((patch / "authored-data.json").read_text())
    unique = {}
    for row in rows:
        command = row["command"]
        # AWS CLI templates only; Python SDK calls are for a later integration.
        if "aws " not in command or "python" in command:
            continue
        events = [e for e in extract(command)["events"] if e["kind"] == "aws"
                  and e["operation"] in tables.get(e["service"], {})]
        if not events:
            continue
        unit = "session" if "\n" in command else "command"
        m = heads[unit]
        weights = dict(zip(m["feature_names"], m["weights"]))
        scores = []
        for e in events:
            keys = [k for k in event_features(e) if k in weights]
            norm = len(keys) ** 0.5
            scores.append(m["intercept"] + (sum(weights[k] for k in keys) / norm if norm else 0))
        score = max(scores)
        unique[command] = {"command": command, "score": score,
                           "verdict": "risky" if score >= m["threshold"] else "not_risky",
                           "count": len(events)}
    chosen = sorted(unique.values(), key=lambda r: hashlib.sha256(r["command"].encode()).hexdigest())[:512]
    if len(chosen) < 100:
        raise ValueError("insufficient AWS CLI reference inputs")
    golden = root / "testdata/aws-operations-golden.jsonl"
    golden.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in chosen))
    provenance = {
        "schema": bundle["schema"], "model_version": bundle["model_version"],
        "extractor_version": bundle["extractor_version"], "sources": sources,
        "feature_extractor_sha256": digest(patch / "operation_features.py"),
        "shared_extractor_sha256": digest(schema / "semantic_features.py"),
        "schema_sha256": {p.name: digest(p) for p in sorted((schema / "source-schemas").glob("*.json"))},
        "authored_data_sha256": digest(patch / "authored-data.json"),
        "artifact_sha256": digest(artifact), "artifact_bytes": artifact.stat().st_size,
        "golden_sha256": digest(golden), "golden_inputs": len(chosen),
        "notes": ["Frozen experiment V4, no retraining", "Threshold 0 for each head",
                  "Training/validation were iterated using known regressions; not blind accuracy evidence",
                  "Head chosen by presence of a newline, matching the reference replay",
                  "SDK schemas describe syntax only; model weights decide risk"],
    }
    (root / "model/aws_operations.provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"artifact_bytes": artifact.stat().st_size, "golden_inputs": len(chosen)}))


if __name__ == "__main__":
    main()
