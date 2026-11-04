"""Freeze ungated PyTorch/sklearn references for the committed public fixtures.

Run with ToolSafe-Lab's Python environment and --research-root pointing to its
matching V3 artifact checkout. Only inputs already in scoped_golden.json are
read; no private examples are selected or copied. This script never runs tools
contained in the fixtures. The ordinary Go tests use the frozen output only.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import math
from pathlib import Path
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--research-root", type=Path, required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(args.research_root / "src"))
    import numpy as np
    import torch
    from toolsafe_lab.data import Sample
    from toolsafe_lab.merlin_balanced_training import normalize
    from toolsafe_lab.merlin_v3_scoped_context import Candidate
    from toolsafe_lab.merlin_v3_sparse import texts
    from toolsafe_lab.merlin_v3_veto import packed
    from toolsafe_lab.standalone_encoder import context_fields

    root = Path(__file__).resolve().parents[2]
    target = root / "internal/guard/stepsafety/testdata/scoped_golden.json"
    inputs = [
        {"name": r["name"], "input": r["input"]} for r in json.loads(target.read_text())
    ]
    torch.set_num_threads(3)
    candidate = Candidate()
    expected = json.loads(
        (root / "internal/guard/stepsafety/model/native/candidate.json").read_text()
    )
    assert candidate.info["weights_sha256"] == expected["weights_sha256"]
    cal = candidate.info["calibrator"]
    sc = candidate.info["sparse_calibrator"]
    point = candidate.info["operating_point"]
    output = []
    with torch.inference_mode():
        for row in inputs:
            inp = row["input"]
            sample = Sample(
                row["name"],
                "public_numerical",
                "test",
                inp["user_request"],
                inp.get("interaction_history") or "[]",
                "Action: "
                + inp["tool_name"]
                + "\nAction Input: "
                + json.dumps(inp["tool_arguments"], ensure_ascii=False),
                inp.get("available_tool_schemas") or "",
                0,
            )
            # Deliberately bypass operation and both request gates. Preserve the
            # same complete-action bound and sparse action-agreement scoring.
            features, error = packed(
                candidate.tokenizer, sample, candidate.info["view"]
            )
            assert error is None, (row["name"], error)
            fields = list(
                context_fields(normalize(sample), "execution_context").values()
            )
            counts = [
                len(candidate.tokenizer.encode(f, add_special_tokens=False))
                for f in fields
            ]
            batch = {
                k: torch.tensor([features[k]], dtype=torch.long)
                for k in ("input_ids", "attention_mask")
            }
            logits = candidate.model(**batch).logits[0].tolist()
            sparse = float(
                candidate.sparse["model"].decision_function(
                    candidate.sparse["vectorizer"].transform(texts([sample]))
                )[0]
            )
            encoder_margin = (
                cal["coefficient"] * (logits[1] - logits[0])
                + cal["intercept"]
                - math.log(
                    point["encoder_threshold"] / (1 - point["encoder_threshold"])
                )
            )
            sparse_margin = (
                sc["coefficient"] * sparse
                + sc["intercept"]
                - math.log(point["sparse_threshold"] / (1 - point["sparse_threshold"]))
            )
            margin = min(encoder_margin, sparse_margin)
            probability = float(1 / (1 + np.exp(-margin)))
            output.append(
                {
                    **row,
                    "error": "",
                    "fields": fields,
                    **features,
                    "uncropped_token_counts": counts,
                    "history_omitted": counts[1] > 144
                    or bool(inp.get("history_omitted")),
                    "logits": [0.0, margin],
                    "probability": probability,
                    "unsafe": probability >= 0.5,
                }
            )
    target.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
    modules = [
        "merlin_v3_scoped_context",
        "merlin_v3_sparse",
        "merlin_v3_veto",
        "merlin_balanced_training",
        "standalone_encoder",
    ]
    provenance = {
        "runtime": "merlin-v3-ungated-20261104",
        "reference": "independent PyTorch FP32 encoder and sklearn sparse action-agreement model; no Go inference",
        "weights_sha256": candidate.info["weights_sha256"],
        "torch_version": torch.__version__,
        "fixture_input_sha256": hashlib.sha256(
            json.dumps(inputs, ensure_ascii=False, sort_keys=True).encode()
        ).hexdigest(),
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "research_source_sha256": {
            name: hashlib.sha256(
                (args.research_root / "src/toolsafe_lab" / f"{name}.py").read_bytes()
            ).hexdigest()
            for name in modules
        },
        "cases": len(output),
        "private_examples": 0,
    }
    target.with_name("scoped_golden.provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n"
    )
    print(
        json.dumps(
            {
                "cases": len(output),
                "unsafe": sum(r["unsafe"] for r in output),
                "private_examples": 0,
            }
        )
    )


if __name__ == "__main__":
    main()
