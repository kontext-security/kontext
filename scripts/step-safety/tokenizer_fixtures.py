"""Refresh HF tokenizer vectors using the pinned maintainer export environment."""
import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import random

from transformers import AutoTokenizer


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    tokenizer_hash = "d6c20af053b5d86d986a9f70898c1fceccb9d93e7ce6f63dabc899a12a53b031"
    if hashlib.sha256((args.model_dir / "tokenizer.json").read_bytes()).hexdigest() != tokenizer_hash:
        raise ValueError("Tokenizer does not match the checkpoint pin")
    if importlib.metadata.version("tokenizers") != "0.22.2":
        raise ValueError("Expected tokenizers==0.22.2")
    tokenizer = AutoTokenizer.from_pretrained(args.model_dir, local_files_only=True)
    texts = [
        "", "hello world", "[USER_REQUEST] hi [CURRENT_ACTION]", "[UNK][UNK]",
        "a   b", "a\u00a0b", "\u0000\ufffd\u0378", "x\u2028x", "cafe\u0301",
        "中文 😊🚀 test", " leading   spaces  ",
        '[TOOL_NAME]\nBash\n[ARGUMENTS]\n{"command":"ls -la"}',
        # x/text before v0.42.0 truncated NFC composition keys to 16 bits,
        # so these composed as if the starter were U+00C6 or U+0041.
        "\U000100c6\u0304", "\U000900c6\u0304", "x\U00010041\u0301y",
        # HF NFC has Unicode 9.0 tables, so it neither reorders nor composes
        # around marks from Unicode 10, 11, 14, 15 and 16; x/text does.
        "\u07fd\u031b", "e\u1dfa\u0301", "\u0301\u1dfa", "cafe\u0301 \u0d3b\u0334",
        "x\u0c3c\u0334 y", "a\u0345\u08d3", "\u1e00\u1df6\u0334", "\U0001e4ec\u0316",
        "\U000105d2\u0307",
    ]
    rng = random.Random(42)
    parts = [
        "hello", " world", "你好", "cafe\u0301", "\t", "\n", "\r", "\v", "\f",
        "\u00a0", "\u2003", "\u2028", "\u2029", "\x00", "\u0378", "😀",
        "[USER_REQUEST]", "[UNK]", "[MASK]", "▁", "\\u2028", '"', "${HOME}", "&&",
    ]
    texts += ["".join(rng.choices(parts, k=rng.randint(1, 80))) for _ in range(500)]
    fixtures = root / "internal/guard/stepsafety/testdata"
    history_fixture = json.loads((fixtures / "history_serialization_golden.json").read_text())
    for case in history_fixture["cases"]:
        for key in ["user_request", "normalized_history", "tool_name"]:
            if key in case:
                texts.append(case[key])
    data = {
        "tokenizer_sha256": tokenizer_hash,
        "reference": "transformers 5.14.1 / tokenizers 0.22.2; scripts/step-safety/tokenizer_fixtures.py",
        "cases": [{"text": text, "ids": tokenizer.encode(text, add_special_tokens=False)} for text in texts],
    }
    (fixtures / "tokenizer_golden.json").write_text(
        json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n"
    )


if __name__ == "__main__":
    main()
