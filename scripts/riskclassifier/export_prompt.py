"""Export the winning guardrail prompt from authz-bench into the file kontext embeds.

The prompt is not prose we get to paraphrase — it is the exact input the V2 row was
measured with (`eval/optimize_prompt.py`: PRECISION system prompt + BALANCED
few-shot, P 0.585 / R 0.967 / F1 0.729, curated 16/16 block and 6/6 allow). A
reworded bullet or a stray trailing newline is a different prompt, so it is copied
mechanically out of the Python source rather than by hand.

Run from the kontext-cli repo root:

    python3 scripts/riskclassifier/export_prompt.py --authz ../authz-bench

Out: internal/guard/riskclassifier/prompts/guardrail-v2.json
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT = REPO_ROOT / "internal" / "guard" / "riskclassifier" / "prompts" / "guardrail-v2.json"

# The variant whose numbers we are adopting, as named in optimize_prompt.py.
VARIANT = "V2 precision + balanced few-shot"
SCHEMA = "kontext-guardrail-prompt/1"


def literals_from(source: Path) -> dict:
    """Read module-level assignments without importing (no torch dependency).

    Handles values that reference earlier assignments by name — VARIANTS points at
    PRECISION/BALANCED rather than inlining them — which plain literal_eval cannot.
    """
    tree = ast.parse(source.read_text())
    out: dict = {}

    def resolve(node):
        if isinstance(node, ast.Name):
            if node.id not in out:
                raise ValueError(f"unresolved name {node.id}")
            return out[node.id]
        if isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            values = [resolve(item) for item in node.elts]
            return values if isinstance(node, ast.List) else tuple(values)
        if isinstance(node, ast.Dict):
            return {resolve(k): resolve(v) for k, v in zip(node.keys, node.values)}
        return ast.literal_eval(node)

    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = resolve(node.value)
            except (ValueError, TypeError):
                continue
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--authz", type=Path, default=REPO_ROOT.parent / "authz-bench")
    args = parser.parse_args()

    source = args.authz.resolve() / "eval" / "optimize_prompt.py"
    values = literals_from(source)

    system = values["PRECISION"]
    fewshot = values["BALANCED"]
    variants = values["VARIANTS"]

    # Fail loudly if upstream renames the variant or repoints it at another prompt,
    # rather than silently exporting a prompt nobody measured.
    chosen = next((v for v in variants if v["name"] == VARIANT), None)
    if chosen is None:
        raise SystemExit(f"variant {VARIANT!r} not found in {source}; upstream renamed it")
    if chosen["sys"] != system or chosen["shots"] != fewshot:
        raise SystemExit(f"variant {VARIANT!r} no longer maps to PRECISION + BALANCED")

    assert system.endswith("No explanation."), "system prompt tail changed"
    assert len(fewshot) == 9, f"expected 9 few-shot pairs, got {len(fewshot)}"

    payload = {
        "schema": SCHEMA,
        "variant": VARIANT,
        "source": "authz-bench/eval/optimize_prompt.py",
        # The eval renders each turn as "Command:\n<cmd>"; kontext must match.
        "user_template": "Command:\n{command}",
        "system": system,
        "fewshot": [{"command": c, "answer": a} for c, a in fewshot],
        "measured": {
            "precision": 0.585,
            "recall": 0.967,
            "f1": 0.729,
            "curated_block": "16/16",
            "curated_allow": "6/6",
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT} (system {len(system)} chars, {len(fewshot)} few-shot pairs)")


if __name__ == "__main__":
    main()
