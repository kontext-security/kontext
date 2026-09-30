"""Package the pinned, unmodified checkpoint for Go embedding (build time only).

Uses only Python's standard library. Endpoints need neither this script nor
Python. Each compressed shard stays below GitHub's 100 MiB per-file limit.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]
WEIGHTS_SHA256 = "429b09164c6705790c4414eb31c0bc18d2fa8a374bea467b2e1b49ead6aeb5f1"
TOKENIZER_SHA256 = "d6c20af053b5d86d986a9f70898c1fceccb9d93e7ce6f63dabc899a12a53b031"
SHARD_BYTES = 64 * 1024 * 1024


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "internal/guard/stepsafety/model/native")
    args = parser.parse_args()
    for name, sha in (("model.safetensors", WEIGHTS_SHA256), ("tokenizer.json", TOKENIZER_SHA256)):
        if digest(args.source / name) != sha:
            raise ValueError(f"Pinned source mismatch: {name}")
    if args.output.exists():
        raise ValueError("Output already exists; choose a fresh directory to compare a reproducible export")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".native-embed-", dir=args.output.parent) as temp:
        output = Path(temp) / "native"
        output.mkdir()
        with (args.source / "model.safetensors").open("rb") as f:
            index = 0
            while chunk := f.read(SHARD_BYTES):
                (output / f"weights.{index:02d}.gz").write_bytes(gzip.compress(chunk, compresslevel=9, mtime=0))
                index += 1
        (output / "tokenizer.json.gz").write_bytes(gzip.compress((args.source / "tokenizer.json").read_bytes(), compresslevel=9, mtime=0))
        manifest = {
            "format": "kontext-merlin-native-safetensors-f32/v1",
            "source_weights_sha256": WEIGHTS_SHA256,
            "tokenizer_sha256": TOKENIZER_SHA256,
            "quantized": False,
            "shard_uncompressed_bytes": SHARD_BYTES,
            "files": [{"name": p.name, "size_bytes": p.stat().st_size, "sha256": digest(p)} for p in sorted(output.iterdir())],
        }
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        output.rename(args.output)
    print(f"Embedded assets: {args.output}")


if __name__ == "__main__":
    main()
