from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any, Sequence


MAX_LENGTH = 512
FIELD_BUDGETS = {
    "request": 96,
    "history": 144,
    "action": 128,
    "schema": 128,
}
FIELD_MARKERS = {
    "request": "[USER_REQUEST]",
    "history": "[INTERACTION_HISTORY]",
    "action": "[CURRENT_ACTION]",
    "schema": "[TOOL_DESCRIPTIONS]",
}


def _head_tail(values: Sequence[int], budget: int) -> list[int]:
    if budget < 0:
        raise ValueError("Token budget cannot be negative")
    if len(values) <= budget:
        return list(values)
    if budget == 0:
        return []
    head = (budget + 1) // 2
    tail = budget - head
    return [*values[:head], *values[-tail:]] if tail else list(values[:head])


def _head(values: Sequence[int], budget: int) -> list[int]:
    if budget < 0:
        raise ValueError("Token budget cannot be negative")
    return list(values[:budget])


def _ensure_field_markers(tokenizer: Any) -> None:
    tokenizer.add_special_tokens(
        {"additional_special_tokens": list(FIELD_MARKERS.values())}
    )


def _string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def execution_only_text(tool_name: object, arguments: object) -> str:
    normalized_arguments = json.dumps(
        arguments,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return "\n".join(
        ("[TOOL_NAME]", _string(tool_name), "[ARGUMENTS]", normalized_arguments)
    ).strip()


def pack_fields(
    tokenizer: Any,
    fields: dict[str, str],
    *,
    max_length: int = MAX_LENGTH,
    field_budgets: dict[str, int] | None = None,
) -> dict[str, list[int]]:
    # This is copied from toolsafe_lab.standalone_encoder.pack_sample. Keep the
    # order, marker handling, start/separator fallback, truncation direction,
    # and padding behavior byte-for-byte equivalent.
    budgets = field_budgets or FIELD_BUDGETS
    if set(budgets) != set(FIELD_MARKERS):
        raise ValueError("Field budgets must cover every standalone input field")

    start_id = tokenizer.cls_token_id
    if start_id is None:
        start_id = tokenizer.bos_token_id
    separator_id = tokenizer.sep_token_id
    if separator_id is None:
        separator_id = tokenizer.eos_token_id
    if start_id is None or separator_id is None:
        raise ValueError("Tokenizer requires start and separator tokens")

    input_ids = [int(start_id)]
    for name in ("request", "history", "action", "schema"):
        marker_id = tokenizer.convert_tokens_to_ids(FIELD_MARKERS[name])
        if marker_id is None or marker_id == tokenizer.unk_token_id:
            raise ValueError(f"Tokenizer is missing field marker {FIELD_MARKERS[name]}")
        tokens = tokenizer.encode(fields[name], add_special_tokens=False)
        selected = (
            _head(tokens, budgets[name])
            if name == "request"
            else _head_tail(tokens, budgets[name])
        )
        input_ids.extend((int(marker_id), *selected, int(separator_id)))

    if len(input_ids) > max_length:
        raise ValueError(
            f"Packed sequence has {len(input_ids)} tokens, over limit {max_length}"
        )
    pad_id = tokenizer.pad_token_id
    if pad_id is None:
        pad_id = separator_id
    attention_mask = [1] * len(input_ids)
    padding = max_length - len(input_ids)
    input_ids.extend([int(pad_id)] * padding)
    attention_mask.extend([0] * padding)
    return {"input_ids": input_ids, "attention_mask": attention_mask}


def _device(torch: Any, requested: str) -> str:
    if requested != "auto":
        return requested
    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


class ModelRuntime:
    def __init__(self, model_dir: str, model_version: str, requested_device: str):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self.torch = torch
        self.model_version = model_version
        self.device = _device(torch, requested_device)
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_dir,
            local_files_only=True,
            use_fast=True,
        )
        _ensure_field_markers(self.tokenizer)
        self.model = AutoModelForSequenceClassification.from_pretrained(
            model_dir,
            local_files_only=True,
        ).to(self.device)
        self.model.eval()

    def infer(self, request: dict[str, object]) -> list[float]:
        fields = {
            "request": _string(request.get("user_request")),
            "history": _string(request.get("interaction_history")),
            "action": execution_only_text(
                request.get("tool_name"), request.get("tool_arguments")
            ),
            "schema": _string(request.get("available_tool_schemas")),
        }
        packed = pack_fields(self.tokenizer, fields)
        inputs = {
            name: self.torch.tensor([values], dtype=self.torch.long, device=self.device)
            for name, values in packed.items()
        }
        with self.torch.inference_mode():
            logits = self.model(**inputs).logits.detach().cpu().float()[0].tolist()
        if len(logits) != 2 or not all(math.isfinite(float(value)) for value in logits):
            raise ValueError("Expected two finite logits")
        return [float(logits[0]), float(logits[1])]


def _write(payload: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


def serve(model_dir: str, model_version: str, device: str) -> int:
    runtime = ModelRuntime(model_dir, model_version, device)
    _write(
        {
            "id": 0,
            "type": "ready",
            "status": "ready",
            "model_version": model_version,
            "device": runtime.device,
        }
    )
    for line in sys.stdin:
        request: dict[str, object] = {}
        try:
            request = json.loads(line)
            request_id = int(request.get("id", 0))
            request_type = request.get("type")
            if request_type == "health":
                _write(
                    {
                        "id": request_id,
                        "type": "health",
                        "status": "ready",
                        "model_version": model_version,
                        "device": runtime.device,
                    }
                )
                continue
            if request_type != "infer":
                raise ValueError("Unsupported request type")
            _write(
                {
                    "id": request_id,
                    "type": "result",
                    "logits": runtime.infer(request),
                }
            )
        except Exception:
            # Error details can include library internals and input fragments.
            # The parent only needs a stable, redacted category to fail open.
            _write(
                {
                    "id": request.get("id", 0) if isinstance(request, dict) else 0,
                    "type": "result",
                    "error_code": "inference_error",
                }
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", required=True)
    parser.add_argument("--model-version", required=True)
    parser.add_argument("--device", default="auto")
    args = parser.parse_args()
    return serve(args.model_dir, args.model_version, args.device)


if __name__ == "__main__":
    raise SystemExit(main())
