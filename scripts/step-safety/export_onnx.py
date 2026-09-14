"""Offline, reproducible export of the pinned checkpoint; never used for serving.

Use Python 3.12 and requirements-export.txt. Install the resulting directory
with `kontext step-safety install --source <output>`.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import shutil
import tempfile

import onnx
import torch
from transformers import AutoModelForSequenceClassification

ROOT = Path(__file__).resolve().parents[2]
PROVENANCE = ROOT / "internal/guard/stepsafety/model/PROVENANCE.json"


class Export(torch.nn.Module):
    def __init__(self, source: Path):
        super().__init__()
        self.model = AutoModelForSequenceClassification.from_pretrained(
            source, local_files_only=True
        ).eval()

    def forward(self, input_ids, attention_mask):
        return self.model(input_ids=input_ids, attention_mask=attention_mask).logits


def sha256(path: Path) -> str:
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    for package, expected in {"torch": "2.13.0", "transformers": "5.14.1", "onnx": "1.22.0"}.items():
        if importlib.metadata.version(package) != expected:
            raise ValueError(f"Expected {package}=={expected}; use requirements-export.txt")
    provenance = json.loads(PROVENANCE.read_text())
    weights = args.source / "model.safetensors"
    if sha256(weights) != provenance["source_weights_sha256"]:
        raise ValueError("Source checkpoint does not match pinned training weights")
    for artifact in provenance["artifacts"]:
        if artifact["name"] != "model.onnx" and sha256(args.source / artifact["name"]) != artifact["sha256"]:
            raise ValueError(f"Source artifact mismatch: {artifact['name']}")
    if args.output.exists():
        raise ValueError("Choose a new output directory; existing artifacts are never overwritten")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".step-safety-export-", dir=args.output.parent) as temp:
        output = Path(temp) / "model"
        output.mkdir()
        torch.set_num_threads(4)
        model = Export(args.source).eval()
        ids = torch.ones((1, 512), dtype=torch.int64)
        mask = torch.ones_like(ids)
        with torch.inference_mode():
            torch.onnx.export(
                model, (ids, mask), str(output / "model.onnx"),
                input_names=["input_ids", "attention_mask"], output_names=["logits"],
                opset_version=17, dynamo=False, external_data=False,
            )
        onnx.checker.check_model(str(output / "model.onnx"))
        for artifact in provenance["artifacts"]:
            path = output / artifact["name"]
            if artifact["name"] != "model.onnx":
                shutil.copyfile(args.source / artifact["name"], path)
            if path.stat().st_size != artifact["size_bytes"] or sha256(path) != artifact["sha256"]:
                raise ValueError(f"Export mismatch: {artifact['name']}; investigate before changing any pin")
        output.rename(args.output)
    print(f"Verified ONNX export: {args.output}")


if __name__ == "__main__":
    main()
