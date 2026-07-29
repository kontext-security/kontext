"""Choose the SVM decision threshold from out-of-fold cross-validated scores.

The shipped classifier is fit on ALL clean labeled data (authz-bench
serve/export_model.py), so there is no held-out split left to tune a threshold
on — picking one from in-sample scores would be optimistic. This runs 5-fold
`cross_val_predict(method="decision_function")` with the identical pipeline, so
every score is produced by a model that did not see that command, then sweeps
thresholds over those out-of-fold scores.

Operating point: v1 is observe mode. Every command is logged with its raw score
regardless of verdict, so the threshold does not gate data capture — it decides
which rows the feedback UI presents as "would block". A noisy would-block set
burns the reviewer attention the ground-truth labels depend on, so the choice is
precision-weighted (F0.5) rather than F1, with recall reported so the trade is
visible.

Run from the kontext-cli repo root with authz-bench's venv:

    ../authz-bench/.venv/bin/python scripts/riskclassifier/pick_threshold.py \
        --authz ../authz-bench
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]


def load_corpus(authz_root: Path):
    sys.path.insert(0, str(authz_root / "eval"))
    from benchmark_pooled import load_clean  # noqa: E402

    return load_clean(20000)


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    from sklearn.svm import LinearSVC

    # Identical to authz-bench serve/export_model.py.
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, max_features=50000)),
        ("clf", LinearSVC(class_weight="balanced")),
    ])


def sweep(scores: np.ndarray, labels: np.ndarray) -> list[dict]:
    rows = []
    candidates = np.unique(np.round(np.concatenate([np.arange(-0.5, 1.5001, 0.05), [0.0]]), 4))
    for threshold in candidates:
        predicted = scores >= threshold
        tp = int(np.sum(predicted & (labels == 1)))
        fp = int(np.sum(predicted & (labels == 0)))
        fn = int(np.sum(~predicted & (labels == 1)))
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        beta2 = 0.25  # F0.5 — precision weighted
        fbeta = ((1 + beta2) * precision * recall / (beta2 * precision + recall)) if (beta2 * precision + recall) else 0.0
        rows.append({
            "threshold": round(float(threshold), 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "f0.5": round(fbeta, 4),
            "false_alarms": fp,
            "misses": fn,
        })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authz", type=Path, default=REPO_ROOT.parent / "authz-bench")
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--out", type=Path, help="optional path to dump the full sweep as JSON")
    args = parser.parse_args()

    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    commands, labels = load_corpus(args.authz.resolve())
    labels = np.asarray(labels)
    print(f"corpus: {len(commands)} commands ({int(labels.sum())} risky / {len(labels) - int(labels.sum())} benign)")

    cv = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=0)
    scores = cross_val_predict(build_pipeline(), commands, labels, cv=cv, method="decision_function", n_jobs=-1)
    print(f"out-of-fold scores: min={scores.min():.3f} max={scores.max():.3f}")

    rows = sweep(scores, labels)
    best_f1 = max(rows, key=lambda r: r["f1"])
    best_f05 = max(rows, key=lambda r: r["f0.5"])
    at_zero = next(r for r in rows if r["threshold"] == 0.0)

    print("\n threshold  precision  recall     f1     f0.5   false_alarms  misses")
    for row in rows:
        if row["threshold"] % 0.25 < 1e-9 or row in (best_f1, best_f05, at_zero):
            mark = " <- " + ",".join(
                name for name, ref in (("F1", best_f1), ("F0.5", best_f05), ("current", at_zero)) if row is ref
            )
            print(f"  {row['threshold']:+.2f}      {row['precision']:.4f}   {row['recall']:.4f}  "
                  f"{row['f1']:.4f}  {row['f0.5']:.4f}      {row['false_alarms']:5d}    {row['misses']:5d}{mark.rstrip(' <-')}")

    print(f"\ncurrent (0.00): precision {at_zero['precision']:.4f} recall {at_zero['recall']:.4f} "
          f"({at_zero['false_alarms']} false alarms, {at_zero['misses']} misses)")
    print(f"best F1   at {best_f1['threshold']:+.2f}: precision {best_f1['precision']:.4f} recall {best_f1['recall']:.4f}")
    print(f"best F0.5 at {best_f05['threshold']:+.2f}: precision {best_f05['precision']:.4f} recall {best_f05['recall']:.4f} "
          f"({best_f05['false_alarms']} false alarms, {best_f05['misses']} misses)")

    if args.out:
        args.out.write_text(json.dumps({
            "folds": args.folds,
            "corpus": {"total": len(commands), "risky": int(labels.sum())},
            "recommended_threshold": best_f05["threshold"],
            "sweep": rows,
        }, indent=2))
        print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
